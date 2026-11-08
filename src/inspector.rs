//! Инспектор ELF — ядро анализа исполняемых файлов.
//!
//! Программа читает ELF (32/64 бита, little/big endian), разбирает его
//! крейтом `goblin` и печатает человекочитаемую структуру:
//! ELF-заголовок → сегменты → интерпретатор → секции → строковые
//! таблицы → таблицы символов (.symtab/.dynsym) → секция .dynamic.
//!
//! Кроме отчёта, инспектор умеет выгружать «кандидатов на обфускацию» —
//! функции (STT_FUNC) с известным размером, целиком лежащие в
//! исполняемой секции. Именно этот список получает обфускатор: из него
//! он узнаёт, какая функция есть в программе, по какому адресу она
//! лежит и сколько байт занимает, чтобы найти её в исходнике на C и
//! переписать.
//!
//! Точка входа консольного бинарника — функция run() внизу файла;
//! библиотечный API (pipeline) пользуется ElfInspector напрямую.

use std::collections::HashSet;
use std::io::{self, Write};
use std::process::ExitCode;

use goblin::elf::{Elf, Symtab};
use goblin::strtab::Strtab;

use crate::dicts::*;

// ═══════════════════════════════════════════════════════════════════
// РАЗДЕЛ 1. ЯДРО: разбор файла и печать отчёта.
//
// Синтаксический разбор выполняет крейт `goblin` — он сам определяет
// класс ELF (32/64 бита) и порядок байт по e_ident. Наша задача —
// обойти разобранные структуры в удобном порядке и напечатать их
// человекочитаемо:
//
//   ELF-заголовок → программные заголовки (сегменты) → интерпретатор →
//   секции → строковые таблицы → таблицы символов → .dynamic.
// ═══════════════════════════════════════════════════════════════════

/// Ширина поля адреса в таблицах: «0x» + 16 цифр для ELF64,
/// «0x» + 8 цифр для ELF32.
fn hex(v: u64, addr_w: usize) -> String {
    let digits = addr_w.saturating_sub(2);
    let s = format!("{:x}", v);
    // Дописываем нули слева до фиксированной ширины — таблица остаётся ровной.
    let pad = digits.saturating_sub(s.len());
    format!("0x{}{}", "0".repeat(pad), s)
}

/// Русская форма счётного существительного: plural(1, "запись", "записи", "записей").
fn plural(n: u64, one: &str, few: &str, many: &str) -> String {
    let m100 = n % 100;
    let m10 = n % 10;
    if m10 == 1 && m100 != 11 {
        one.into()
    } else if (2..=4).contains(&m10) && !(12..=14).contains(&m100) {
        few.into()
    } else {
        many.into()
    }
}

/// Описание одной функции — задел на будущие режимы
/// (декодирование, деобфускация, патчинг кода).
#[allow(dead_code)] // публичный API-задел, отчёт им пока не пользуется
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    /// Имя символа (может быть пустым у локальных функций без имени).
    pub name: String,
    /// Виртуальный адрес начала функции.
    pub addr: u64,
    /// Размер в байтах (0, если компилятор не сообщил).
    pub size: u64,
    /// true — символ найден в .symtab, false — в .dynsym.
    pub from_symtab: bool,
}

/// Один кандидат на обфускацию — запись для JSON, которую читает
/// обфускатор.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// Имя символа функции.
    pub name: String,
    /// Виртуальный адрес начала функции.
    pub addr: u64,
    /// Размер кода функции в байтах.
    pub size: u64,
    /// Смещение кода функции внутри файла.
    pub file_offset: u64,
    /// Имя секции, в которой лежит код.
    pub section: String,
    /// Индекс этой секции.
    pub section_index: usize,
    /// true — символ из .symtab, false — из .dynsym.
    pub from_symtab: bool,
}

/// Инспектор: хранит разобранный ELF и печатает по нему отчёт.
pub struct ElfInspector<'a> {
    /// Путь к файлу — нужен только для заголовка отчёта.
    path: String,
    /// Сырые байты файла: из них читаем, например, строку интерпретатора.
    bytes: &'a [u8],
    /// Разобранный goblin'ом ELF (ELF32/ELF64, little/big endian).
    elf: Elf<'a>,
    /// Ширина поля адреса (18 символов для ELF64, 10 для ELF32).
    addr_w: usize,
}

impl<'a> ElfInspector<'a> {
    /// Шаг разбора 1: отдаём байты файла крейту goblin.
    ///
    /// goblin проверит магию \x7fELF, определит класс и порядок байт
    /// и разберёт все таблицы. Ошибка возвращается, если это не ELF
    /// или файл обрезан.
    pub fn parse(path: &str, bytes: &'a [u8]) -> Result<Self, goblin::error::Error> {
        let elf = Elf::parse(bytes)?;
        Ok(Self {
            path: path.to_string(),
            bytes,
            addr_w: if elf.is_64 { 18 } else { 10 },
            elf,
        })
    }

    /// Полный отчёт: вызывает разделы по очереди, каждый — отдельным
    /// методом, чтобы их можно было вызывать и по отдельности.
    pub fn report(&self, out: &mut dyn Write, limit: usize) -> io::Result<()> {
        writeln!(out, "════════════════════════════════════════════════")?;
        writeln!(out, " Инспектор ELF: {}", self.path)?;
        writeln!(out, "════════════════════════════════════════════════")?;

        self.print_header(out)?;
        self.print_program_headers(out)?;
        self.print_interpreter(out)?;
        self.print_sections(out)?;
        self.print_string_tables(out)?;
        self.print_symbols(out, ".symtab", &self.elf.syms, &self.elf.strtab, limit)?;
        self.print_symbols(out, ".dynsym", &self.elf.dynsyms, &self.elf.dynstrtab, limit)?;
        self.print_dynamic(out)?;
        Ok(())
    }

    /// Раздел 1. ELF-заголовок (struct Elf32/64_Ehdr).
    fn print_header(&self, out: &mut dyn Write) -> io::Result<()> {
        // goblin сводит 32- и 64-битные заголовки к одной структуре Header
        // с полями фиксированной ширины (u64 для адресов), поэтому код
        // один и тот же для обоих классов.
        let h = &self.elf.header;
        // e_ident — первые 16 байтов файла: магия, класс, порядок байт и т.д.
        let id = &h.e_ident;

        writeln!(out, "\n─── ELF-ЗАГОЛОВОК ───")?;
        // Шаг 1: магия — 16 байтов e_ident в шестнадцатеричном виде.
        write!(out, "  {:<22}", "Магия:")?;
        for b in id.iter() {
            write!(out, "{:02x} ", b)?;
        }
        writeln!(out)?;

        // Шаг 2: служебные поля e_ident.
        writeln!(out, "  {:<22}{}", "Класс:", class_to_str(id[4]))?;
        writeln!(out, "  {:<22}{}", "Порядок байт:", data_to_str(id[5]))?;
        writeln!(out, "  {:<22}{}", "Версия ELF:", h.e_version)?;
        writeln!(out, "  {:<22}{}", "OS/ABI:", osabi_to_str(id[7]))?;
        writeln!(out, "  {:<22}{}", "Версия ABI:", id[8])?;

        // Шаг 3: содержательные поля заголовка.
        writeln!(out, "  {:<22}{}", "Тип файла:", etype_to_str(h.e_type))?;
        writeln!(out, "  {:<22}{}", "Архитектура:", machine_to_str(h.e_machine))?;
        writeln!(out, "  {:<22}{}", "Точка входа:", hex(h.e_entry, self.addr_w))?;
        writeln!(out, "  {:<22}{} ({} {} по {} {})",
                 "Смещение PH:", hex(h.e_phoff, self.addr_w),
                 h.e_phnum, plural(h.e_phnum as u64, "запись", "записи", "записей"),
                 h.e_phentsize, plural(h.e_phentsize as u64, "байт", "байта", "байт"))?;
        writeln!(out, "  {:<22}{} ({} {} по {} {})",
                 "Смещение SH:", hex(h.e_shoff, self.addr_w),
                 h.e_shnum, plural(h.e_shnum as u64, "запись", "записи", "записей"),
                 h.e_shentsize, plural(h.e_shentsize as u64, "байт", "байта", "байт"))?;
        writeln!(out, "  {:<22}{}", "Флаги процессора:", hex(h.e_flags as u64, self.addr_w))?;
        writeln!(out, "  {:<22}{} байт", "Размер заголовка:", h.e_ehsize)?;
        // Индекс секции, в которой лежат имена всех секций (shstrtab).
        writeln!(out, "  {:<22}{}", "Индекс shstrtab:", h.e_shstrndx)?;
        Ok(())
    }

    /// Раздел 2. Программные заголовки (struct Elf32/64_Phdr).
    /// Их читает загрузчик ядра: какие части файла и куда отображать в память.
    fn print_program_headers(&self, out: &mut dyn Write) -> io::Result<()> {
        let phs = &self.elf.program_headers;
        writeln!(out, "\n─── ПРОГРАММНЫЕ ЗАГОЛОВКИ (СЕГМЕНТЫ) ───")?;

        if phs.is_empty() {
            writeln!(out, "  Сегментов нет (например, объектный файл .o).")?;
            return Ok(());
        }

        // Шаг 1: шапка таблицы. Адресные колонки выровнены под класс файла.
        writeln!(out, "  Всего сегментов: {}", phs.len())?;
        writeln!(out,
                 "  {:>3} {:<14} {:<aw$} {:<aw$} {:>10} {:>10} {:<5} {:>8}",
                 "№", "Тип", "Смещение", "Вирт. адрес", "Файл, байт", "Память, байт", "Флаги", "Выравн.",
                 aw = self.addr_w)?;

        // Шаг 2: строки таблицы.
        for (i, p) in phs.iter().enumerate() {
            writeln!(out,
                     "  {:>3} {:<14} {:<aw$} {:<aw$} {:>10} {:>10} {:<5} {:>8}",
                     i,
                     pt_type_to_str(p.p_type),
                     hex(p.p_offset, self.addr_w),
                     hex(p.p_vaddr, self.addr_w),
                     p.p_filesz,
                     p.p_memsz,
                     ph_flags_to_str(p.p_flags),
                     hex(p.p_align, self.addr_w),
                     aw = self.addr_w)?;
        }
        writeln!(out, "  (флаги: R — чтение, W — запись, E — исполнение)")?;
        Ok(())
    }

    /// Раздел 3. Интерпретатор — путь к динамическому загрузчику (ld.so).
    fn print_interpreter(&self, out: &mut dyn Write) -> io::Result<()> {
        writeln!(out, "\n─── ИНТЕРПРЕТАТОР ───")?;
        // Шаг 1: ищем сегмент PT_INTERP (константа 3 из спецификации).
        if let Some(p) = self.elf.program_headers.iter().find(|p| p.p_type == PT_INTERP) {
            // Шаг 2: строка лежит в файле со смещения p_offset длиной
            // p_filesz и завершается нулевым байтом — вырезаем её из
            // сырых байтов (обрезаем по границам файла на всякий случай).
            let start = (p.p_offset as usize).min(self.bytes.len());
            let end = ((p.p_offset + p.p_filesz) as usize).min(self.bytes.len());
            let raw = &self.bytes[start..end];
            let len = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            writeln!(out, "  {} (динамический бинарник)", String::from_utf8_lossy(&raw[..len]))?;
        } else {
            // Шаг 3: PT_INTERP отсутствует — статический бинарник или ядро.
            writeln!(out, "  отсутствует — бинарник статический или не требует загрузчика")?;
        }
        Ok(())
    }

    /// Раздел 4. Заголовки секций (struct Elf32/64_Shdr) — «карта» файла
    /// для компоновщика, отладчика и инструментов вроде этого инспектора.
    fn print_sections(&self, out: &mut dyn Write) -> io::Result<()> {
        let shs = &self.elf.section_headers;
        writeln!(out, "\n─── ЗАГОЛОВКИ СЕКЦИЙ ───")?;

        if shs.is_empty() {
            writeln!(out, "  Секций нет (файл без таблицы секций).")?;
            return Ok(());
        }

        // Шаг 1: шапка таблицы.
        writeln!(out, "  Всего секций: {}", shs.len())?;
        writeln!(out,
                 "  [{:>3}] {:<17} {:<14} {:<aw$} {:<aw$} {:>9} {:>5} {:>5} {}",
                 "№", "Имя", "Тип", "Адрес", "Смещение", "Размер", "Эл-т", "Выр.", "Флаги",
                 aw = self.addr_w)?;

        // Шаг 2: строки таблицы.
        for (i, sh) in shs.iter().enumerate() {
            // Шаг 3: имя секции лежит не здесь, а в shstrtab;
            // sh_name — смещение строки внутри этой таблицы.
            let name = self.section_name(i);
            writeln!(out,
                     "  [{:>3}] {:<17} {:<14} {:<aw$} {:<aw$} {:>9} {:>5} {:>5} {}",
                     i,
                     name,
                     sht_to_str(sh.sh_type),
                     hex(sh.sh_addr, self.addr_w),
                     hex(sh.sh_offset, self.addr_w),
                     sh.sh_size,
                     sh.sh_entsize,
                     sh.sh_addralign,
                     sh_flags_to_str(sh.sh_flags),
                     aw = self.addr_w)?;
        }
        Ok(())
    }

    /// Раздел 5. Строковые таблицы: где хранятся все имена файла.
    fn print_string_tables(&self, out: &mut dyn Write) -> io::Result<()> {
        writeln!(out, "\n─── СТРОКОВЫЕ ТАБЛИЦЫ ───")?;
        let mut found = false;

        // Шаг 1: перебираем секции, ищем тип SHT_STRTAB (= 3).
        for (i, sh) in self.elf.section_headers.iter().enumerate() {
            if sh.sh_type != 3 || sh.sh_size == 0 {
                continue;
            }
            found = true;
            // Шаг 2: считаем непустые строки в сырых байтах секции —
            // строки разделены нулевыми байтами.
            let start = (sh.sh_offset as usize).min(self.bytes.len());
            let end = ((sh.sh_offset + sh.sh_size) as usize).min(self.bytes.len());
            let count = self.bytes[start..end]
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .count();

            // Шаг 3: поясняем роль каждой таблицы по её имени.
            let name = self.section_name(i);
            let role = match name {
                ".shstrtab" => "имена секций",
                ".strtab" => "имена символов из .symtab",
                ".dynstr" => "имена символов .dynsym и зависимостей",
                _ => "строковые данные",
            };
            writeln!(out, "  [{:>3}] {:<10} размер {:>7} байт, строк: {:>4} — {}",
                     i, name, sh.sh_size, count, role)?;
        }
        if !found {
            writeln!(out, "  Строковых таблиц нет.")?;
        }
        Ok(())
    }

    /// Раздел 6. Таблицы символов .symtab и .dynsym.
    fn print_symbols(
        &self,
        out: &mut dyn Write,
        table: &str,
        syms: &Symtab<'_>,
        strtab: &Strtab<'_>,
        limit: usize,
    ) -> io::Result<()> {
        writeln!(out, "\n─── ТАБЛИЦА СИМВОЛОВ {} ───", table)?;

        // Шаг 1: пустая таблица — нормальная ситуация. В stripped-файлах
        // нет .symtab, у статических бинарников нет .dynsym.
        if syms.len() == 0 {
            writeln!(out, "  Таблица отсутствует (0 записей).")?;
            return Ok(());
        }

        // Шаг 2: сколько записей печатать (опция --limit).
        let shown = if limit > 0 { syms.len().min(limit) } else { syms.len() };

        // Шаг 3: шапка.
        writeln!(out,
                 "  {:>4} {:<aw$} {:>8} {:<9} {:<8} {:<10} {:<15} Имя",
                 "№", "Значение", "Размер", "Тип", "Связка", "Видимость", "Секция",
                 aw = self.addr_w)?;

        // Шаг 4: цикл по символам.
        for i in 0..shown {
            let Some(sym) = syms.get(i) else { break };

            // st_info упаковывает два поля: связь — старшие 4 бита,
            // тип — младшие 4 бита.
            let bind = st_bind_to_str(sym.st_info >> 4);
            let typ = st_type_to_str(sym.st_info & 0xf);
            // st_other хранит видимость в младших 2 битах.
            let vis = st_vis_to_str(sym.st_other & 0x3);
            // st_shndx — индекс секции, где определён символ (или UND/ABS/COM).
            let sec = self.symbol_section_label(sym.st_shndx as usize);
            // Имя символа — строка из соответствующей строковой таблицы;
            // st_name — смещение внутри неё.
            let name = strtab.get_at(sym.st_name as usize).unwrap_or("");

            writeln!(out,
                     "  {:>4} {:<aw$} {:>8} {:<9} {:<8} {:<10} {:<15} {}",
                     i,
                     hex(sym.st_value, self.addr_w),
                     sym.st_size,
                     typ,
                     bind,
                     vis,
                     sec,
                     name,
                     aw = self.addr_w)?;
        }
        if shown < syms.len() {
            writeln!(out, "  … показано {} из {} записей (лимит --limit)", shown, syms.len())?;
        }
        Ok(())
    }

    /// Раздел 7. Динамическая секция .dynamic — «инструкция по загрузке»
    /// для динамического линковщика.
    fn print_dynamic(&self, out: &mut dyn Write) -> io::Result<()> {
        writeln!(out, "\n─── ДИНАМИЧЕСКАЯ СЕКЦИЯ (.dynamic) ───")?;

        // Шаг 1: секции может не быть (статический бинарник, .o, ядро).
        let Some(dynsec) = &self.elf.dynamic else {
            writeln!(out, "  Секция отсутствует.")?;
            return Ok(());
        };

        // Шаг 2: таблица записей tag/значение с расшифровкой.
        writeln!(out, "  Записей: {}", dynsec.dyns.len())?;
        writeln!(out, "  {:<16} {:<aw$} {}", "Метка", "Значение", "Расшифровка",
                 aw = self.addr_w)?;
        for e in &dynsec.dyns {
            writeln!(out, "  {:<16} {:<aw$} {}",
                     dt_tag_to_str(e.d_tag),
                     hex(e.d_val, self.addr_w),
                     self.describe_dynamic(e.d_tag, e.d_val),
                     aw = self.addr_w)?;
        }

        // Шаг 3: сводка — зависимости и пути поиска, самое нужное сверху.
        let needed: Vec<&str> = dynsec.dyns.iter()
            .filter(|e| e.d_tag == DT_NEEDED)
            .filter_map(|e| self.elf.dynstrtab.get_at(e.d_val as usize))
            .collect();
        if !needed.is_empty() {
            writeln!(out, "  Зависимости (DT_NEEDED):")?;
            for lib in needed {
                writeln!(out, "    - {}", lib)?;
            }
        }
        for tag in [DT_SONAME, DT_RUNPATH, DT_RPATH] {
            if let Some(e) = dynsec.dyns.iter().find(|e| e.d_tag == tag) {
                if let Some(s) = self.elf.dynstrtab.get_at(e.d_val as usize) {
                    let label = match tag {
                        DT_SONAME => "SONAME",
                        DT_RUNPATH => "RUNPATH",
                        _ => "RPATH",
                    };
                    writeln!(out, "  {}: {}", label, s)?;
                }
            }
        }
        Ok(())
    }

    /// Расшифровка значения конкретной записи .dynamic.
    fn describe_dynamic(&self, tag: u64, val: u64) -> String {
        match tag {
            // Имена библиотек — смещения строк в .dynstr.
            DT_NEEDED | DT_SONAME | DT_RPATH | DT_RUNPATH => {
                self.elf.dynstrtab.get_at(val as usize).unwrap_or("?").to_string()
            }
            DT_FLAGS => dt_flags_to_str(val),
            DT_FLAGS_1 => dt_flags1_to_str(val),
            // Тип перемещений PLT: 7 = RELA, 17 = REL.
            DT_PLTREL => match val {
                7 => "RELA".into(),
                17 => "REL".into(),
                _ => String::new(),
            },
            // Остальные значения (адреса, размеры) оставляем в hex-колонке.
            _ => String::new(),
        }
    }

    /// Имя секции по её индексу (строка берётся из shstrtab).
    fn section_name(&self, idx: usize) -> &str {
        self.elf.section_headers
            .get(idx)
            .and_then(|sh| self.elf.shdr_strtab.get_at(sh.sh_name as usize))
            .unwrap_or("")
    }

    /// Пометка секции символа: специальные индексы расшифровываем словами.
    fn symbol_section_label(&self, shndx: usize) -> String {
        match shndx {
            0 => "UND (внешний)".into(),
            0xfff1 => "ABS (абсолют.)".into(),
            0xfff2 => "COM (общий)".into(),
            _ => {
                let name = self.section_name(shndx);
                if name.is_empty() { format!("[{}]", shndx) } else { name.to_string() }
            }
        }
    }

    /// Список функций из таблиц символов — точка расширения.
    ///
    /// Будущие режимы (декодирование, обфускация/деобфускация) могут
    /// взять отсюда адрес и размер каждой функции и вырезать её байты
    /// из файла: смещение функции в файле = addr - смещение_сегмента_LOAD
    /// + offset_сегмента (для простых случаев addr == смещению).
    #[allow(dead_code)] // публичный API-задел: отчёт им пока не пользуется
    pub fn function_symbols(&self) -> Vec<FunctionInfo> {
        let mut result = Vec::new();
        let mut seen: HashSet<(u64, u64)> = HashSet::new();

        // Шаг 1: проходим обе таблицы. В stripped-файлах .symtab пуста,
        // тогда функции остаются только в .dynsym.
        let tables = [
            (&self.elf.syms, &self.elf.strtab, true),
            (&self.elf.dynsyms, &self.elf.dynstrtab, false),
        ];
        for (symtab, strtab, from) in tables {
            for i in 0..symtab.len() {
                let Some(sym) = symtab.get(i) else { continue };
                // Шаг 2: оставляем только STT_FUNC с известным размером.
                if sym.st_info & 0xf != STT_FUNC || sym.st_size == 0 {
                    continue;
                }
                // Шаг 3: дедупликация по паре (адрес, размер) — один и тот
                // же символ может попасть в обе таблицы.
                if seen.insert((sym.st_value, sym.st_size)) {
                    result.push(FunctionInfo {
                        name: strtab.get_at(sym.st_name as usize).unwrap_or("").to_string(),
                        addr: sym.st_value,
                        size: sym.st_size,
                        from_symtab: from,
                    });
                }
            }
        }
        result
    }

    /// Кандидаты на обфускацию — входной список для обфускатора.
    ///
    /// Условия отбора:
    ///   1. символ типа STT_FUNC с ненулевым размером (есть что переписывать);
    ///   2. функция целиком лежит в исполняемой секции (SHF_EXECINSTR) —
    ///      значит, её байты действительно машинный код x86/x86-64;
    ///   3. дубликаты из .symtab и .dynsym считаем один раз.
    /// Для каждого кандидата сразу вычисляем file_offset — смещение кода
    /// в файле: addr - sh_addr + sh_offset содержащей секции.
    pub fn candidates(&self) -> Vec<Candidate> {
        let mut out = Vec::new();
        let mut seen: HashSet<(u64, u64, usize)> = HashSet::new();
        let tables = [
            (&self.elf.syms, &self.elf.strtab, true),
            (&self.elf.dynsyms, &self.elf.dynstrtab, false),
        ];
        for (symtab, strtab, from) in tables {
            for i in 0..symtab.len() {
                let Some(sym) = symtab.get(i) else { continue };
                if sym.st_info & 0xf != STT_FUNC || sym.st_size == 0 || sym.st_shndx == 0 {
                    continue;
                }
                // Шаг 1: ищем исполняемую секцию, целиком накрывающую функцию.
                let mut holder: Option<(usize, u64)> = None; // (индекс, sh_offset)
                for (si, sh) in self.elf.section_headers.iter().enumerate() {
                    let exec = sh.sh_flags & 0x4 != 0; // SHF_EXECINSTR
                    if exec
                        && sym.st_value >= sh.sh_addr
                        && sym.st_value + sym.st_size <= sh.sh_addr + sh.sh_size
                    {
                        holder = Some((si, sh.sh_offset));
                        break;
                    }
                }
                let Some((si, sh_off)) = holder else { continue };
                // Шаг 2: дедупликация — одна функция может попасть в обе таблицы.
                if !seen.insert((sym.st_value, sym.st_size, si)) {
                    continue;
                }
                out.push(Candidate {
                    name: strtab.get_at(sym.st_name as usize).unwrap_or("").to_string(),
                    addr: sym.st_value,
                    size: sym.st_size,
                    file_offset: sym.st_value - self.elf.section_headers[si].sh_addr + sh_off,
                    section: self.section_name(si).to_string(),
                    section_index: si,
                    from_symtab: from,
                });
            }
        }
        out.sort_by_key(|c| c.addr);
        out
    }

    /// Выгрузка кандидатов в JSON. Формат — свой, минимальный (v1):
    /// его читает обфускатор (parse_candidates ниже), поэтому без
    /// внешних крейтов и без serde. Возвращает число записанных
    /// кандидатов.
    pub fn write_candidates_json(&self, path: &str) -> io::Result<usize> {
        let list = self.candidates();
        let bits = if self.elf.is_64 { 64 } else { 32 };
        // Архитектура определяет, чем вообще можно обфусцировать код.
        let arch = match self.elf.header.e_machine {
            62 => "x86-64",
            3 => "x86",
            m => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("архитектура machine={} не поддерживается (нужен x86/x86-64)", m),
                ));
            }
        };
        let mut s = String::new();
        s.push_str("{\n");
        s.push_str("  \"format\": \"elf-inspector-candidates-v1\",\n");
        s.push_str(&format!("  \"file\": \"{}\",\n", json_escape(&self.path)));
        s.push_str(&format!("  \"bits\": {},\n", bits));
        s.push_str(&format!("  \"arch\": \"{}\",\n", arch));
        s.push_str("  \"functions\": [\n");
        for (k, c) in list.iter().enumerate() {
            s.push_str("    {\n");
            s.push_str(&format!("      \"name\": \"{}\",\n", json_escape(&c.name)));
            s.push_str(&format!("      \"addr\": {},\n", c.addr));
            s.push_str(&format!("      \"addr_hex\": \"0x{:x}\",\n", c.addr));
            s.push_str(&format!("      \"size\": {},\n", c.size));
            s.push_str(&format!("      \"file_offset\": {},\n", c.file_offset));
            s.push_str(&format!("      \"section\": \"{}\",\n", json_escape(&c.section)));
            s.push_str(&format!("      \"section_index\": {},\n", c.section_index));
            s.push_str(&format!("      \"from_symtab\": {}\n", c.from_symtab));
            s.push_str(if k + 1 == list.len() { "    }\n" } else { "    },\n" });
        }
        s.push_str("  ]\n}\n");
        std::fs::write(path, s)?;
        Ok(list.len())
    }
}

/// Экранирование строки для JSON (имена символов почти всегда безопасны,
/// но лучше не полагаться на «почти»).
fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

// ═══════════════════════════════════════════════════════════════════
// РАЗДЕЛ 2. ЧТЕНИЕ JSON КАНДИДАТОВ.
//
// Формат целиком создаётся write_candidates_json, поэтому достаточно
// минимального разбора: поиск ключей и вырезание массива объектов.
// ═══════════════════════════════════════════════════════════════════

/// Разобранный JSON-файл кандидатов.
pub struct CandidatesFile {
    /// Путь к ELF, на котором делался анализ.
    pub file: String,
    /// Разрядность (32 или 64).
    pub bits: u32,
    /// Архитектура («x86» или «x86-64»).
    pub arch: String,
    /// Список кандидатов.
    pub functions: Vec<Candidate>,
}

/// Разбор JSON-формата elf-inspector-candidates-v1.
pub fn parse_candidates(text: &str) -> Result<CandidatesFile, String> {
    // Шаг 1: разрядность и архитектура — от них зависит выбор функций.
    let bits = json_u64_field(text, "bits")?;
    let arch = json_str_field(text, "arch")?;
    let file = json_str_field(text, "file")?;
    if bits != 32 && bits != 64 {
        return Err(format!("неизвестная разрядность {}", bits));
    }
    if arch != "x86" && arch != "x86-64" {
        return Err(format!("архитектура «{}» не поддерживается (нужен x86/x86-64)", arch));
    }
    // Шаг 2: массив "functions": [ {...}, ... ].
    let arr = json_array_field(text, "functions")?;
    let mut functions = Vec::new();
    for obj in split_json_objects(&arr)? {
        functions.push(Candidate {
            name: json_str_field(&obj, "name")?,
            addr: json_u64_field(&obj, "addr")?,
            size: json_u64_field(&obj, "size")?,
            file_offset: json_u64_field(&obj, "file_offset")?,
            section: json_str_field(&obj, "section")?,
            section_index: json_u64_field(&obj, "section_index")? as usize,
            from_symtab: json_bool_field(&obj, "from_symtab")?,
        });
    }
    Ok(CandidatesFile { file, bits: bits as u32, arch, functions })
}

/// Значение числового поля «ключ»: N.
fn json_u64_field(text: &str, key: &str) -> Result<u64, String> {
    let needle = format!("\"{}\"", key);
    let pos = text.find(&needle).ok_or_else(|| format!("нет поля «{}»", key))?;
    let rest = text[pos + needle.len()..].trim_start();
    let rest = rest.strip_prefix(':').ok_or_else(|| format!("поле «{}»: нет «:»", key))?;
    let digits: String = rest.trim_start().chars().take_while(|c| c.is_ascii_digit()).collect();
    digits
        .parse::<u64>()
        .map_err(|_| format!("поле «{}»: не число «{}»", key, digits))
}

/// Значение логического поля «ключ»: true/false (JSON пишет их без кавычек).
fn json_bool_field(text: &str, key: &str) -> Result<bool, String> {
    let needle = format!("\"{}\"", key);
    let pos = text.find(&needle).ok_or_else(|| format!("нет поля «{}»", key))?;
    let rest = text[pos + needle.len()..].trim_start();
    let rest = rest.strip_prefix(':').ok_or_else(|| format!("поле «{}»: нет «:»", key))?;
    let word: String = rest
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_alphabetic())
        .collect();
    match word.as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("поле «{}»: не логическое значение «{}»", key, word)),
    }
}

/// Значение строкового поля «ключ»: "..." (с минимальным анэкранированием).
fn json_str_field(text: &str, key: &str) -> Result<String, String> {
    let needle = format!("\"{}\"", key);
    let pos = text.find(&needle).ok_or_else(|| format!("нет поля «{}»", key))?;
    let rest = text[pos + needle.len()..].trim_start();
    let rest = rest.strip_prefix(':').ok_or_else(|| format!("поле «{}»: нет «:»", key))?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('"').ok_or_else(|| format!("поле «{}»: не строка", key))?;
    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Ok(out),
            '\\' => match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                // «\"» и «\\» и прочие — берём следующий символ как есть.
                Some(other) => out.push(other),
                None => return Err(format!("поле «{}»: обрыв после «\\»", key)),
            },
            other => out.push(other),
        }
    }
    Err(format!("поле «{}»: строка не закрыта", key))
}

/// Тело массива «ключ»: [ ... ] (без внешних скобок).
fn json_array_field(text: &str, key: &str) -> Result<String, String> {
    let needle = format!("\"{}\"", key);
    let pos = text.find(&needle).ok_or_else(|| format!("нет поля «{}»", key))?;
    let rest = text[pos + needle.len()..].trim_start();
    let rest = rest.strip_prefix(':').ok_or_else(|| format!("поле «{}»: нет «:»", key))?;
    let start = rest.find('[').ok_or_else(|| format!("поле «{}»: не массив", key))?;
    let body = &rest[start..];
    let mut depth = 0usize;
    for (i, ch) in body.char_indices() {
        match ch {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(body[1..i].to_string());
                }
            }
            _ => {}
        }
    }
    Err(format!("поле «{}»: массив не закрыт", key))
}

/// Разрезает тело массива на тексты объектов { ... }.
fn split_json_objects(arr: &str) -> Result<Vec<String>, String> {
    let mut objs = Vec::new();
    let mut depth = 0usize;
    let mut cur = String::new();
    for ch in arr.chars() {
        if depth == 0 {
            // Запятые и пробелы между объектами пропускаем.
            if ch == '{' {
                depth = 1;
                cur.push(ch);
            }
            continue;
        }
        cur.push(ch);
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    objs.push(std::mem::take(&mut cur));
                }
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err("незакрытый объект в массиве functions".into());
    }
    Ok(objs)
}

// ═══════════════════════════════════════════════════════════════════
// РАЗДЕЛ 3. КОНСОЛЬНЫЙ ИНТЕРФЕЙС ИНСПЕКТОРА (бинарник bin/elf-inspector.rs).
// ═══════════════════════════════════════════════════════════════════

/// Короткая подсказка при неверных аргументах.
fn print_usage() {
    eprintln!("Использование: elf-inspector <файл> [-n ЛИМИТ] [--json ОТЧЁТ.json]");
    eprintln!("Подробнее: elf-inspector --help");
}

/// Полная справка.
fn print_help() {
    println!("Инспектор ELF — читает ELF-файл и печатает его структуру.");
    println!();
    println!("Использование:");
    println!("  elf-inspector <файл> [ключи]");
    println!();
    println!("Ключи:");
    println!("  -n, --limit N   показывать не более N записей в каждой таблице символов");
    println!("  -j, --json F    записать кандидатов на обфускацию в JSON-файл F");
    println!("                  (для обфускатора — bin/obfuscator.rs и obfuscator-core)");
    println!("  -h, --help      эта справка");
    println!();
    println!("Отчёт включает: ELF-заголовок, программные заголовки (сегменты),");
    println!("интерпретатор, секции, строковые таблицы, таблицы символов");
    println!(".symtab и .dynsym, динамическую секцию .dynamic с зависимостями.");
}

/// Точка входа бинарника elf-inspector. Общий план работы:
///   1. разобрать аргументы командной строки;
///   2. прочитать файл целиком в память;
///   3. передать байты инспектору и напечатать отчёт;
///   4. по ключу --json выгрузить кандидатов на обфускацию.
pub fn run(args: &[String]) -> ExitCode {
    // ── Шаг 1. Аргументы командной строки ──
    let mut path: Option<String> = None; // путь к анализируемому файлу
    let mut limit: usize = 0;            // 0 означает «без ограничения»
    let mut json_out: Option<String> = None; // файл для JSON с кандидатами (--json)

    let mut i = 1; // args[0] — имя самой программы, начинаем с 1
    while i < args.len() {
        match args[i].as_str() {
            "-n" | "--limit" => {
                // Шаг 1а: после ключа должно идти число — лимит записей.
                i += 1;
                match args.get(i).and_then(|s| s.parse::<usize>().ok()) {
                    Some(v) => limit = v,
                    None => {
                        eprintln!("Ошибка: после ключа «{}» нужно указать число.", args[i - 1]);
                        return ExitCode::FAILURE;
                    }
                }
            }
            "-j" | "--json" => {
                // Шаг 1б: после ключа должно идти имя файла для JSON.
                i += 1;
                match args.get(i) {
                    Some(p) => json_out = Some(p.clone()),
                    None => {
                        eprintln!("Ошибка: после ключа «{}» нужно указать имя файла.", args[i - 1]);
                        return ExitCode::FAILURE;
                    }
                }
            }
            "-h" | "--help" => {
                print_help();
                return ExitCode::SUCCESS;
            }
            other => {
                // Шаг 1в: любой другой аргумент считаем путём к файлу;
                // второй такой аргумент — ошибка.
                if path.is_some() {
                    eprintln!("Ошибка: лишний аргумент «{}».", other);
                    print_usage();
                    return ExitCode::FAILURE;
                }
                path = Some(other.to_string());
            }
        }
        i += 1;
    }

    // Шаг 1г: без пути работать нечего — показываем подсказку.
    let Some(path) = path else {
        print_usage();
        return ExitCode::FAILURE;
    };

    // ── Шаг 2. Читаем файл целиком в память ──
    // ELF-файлы обычно невелики; goblin разбирает данные по срезу байтов,
    // без копий, поэтому одного fs::read достаточно.
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Не удалось прочитать «{}»: {}", path, e);
            return ExitCode::FAILURE;
        }
    };

    // ── Шаг 3. Разбираем ELF и печатаем отчёт ──
    // Буферизованный вывод: таблицы символов могут быть длинными.
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());

    match ElfInspector::parse(&path, &bytes) {
        Ok(insp) => {
            // Файл разобран — печатаем все разделы отчёта.
            let result = insp.report(&mut out, limit);
            let _ = out.flush();
            match result {
                Ok(()) => {
                    // По запросу --json выгружаем кандидатов на обфускацию.
                    if let Some(jp) = &json_out {
                        match insp.write_candidates_json(jp) {
                            Ok(count) => println!(
                                "Кандидатов на обфускацию: {}. JSON сохранён: {}",
                                count, jp
                            ),
                            Err(e) => {
                                eprintln!("Не удалось записать «{}»: {}", jp, e);
                                return ExitCode::FAILURE;
                            }
                        }
                    }
                    ExitCode::SUCCESS
                }
                // Пайп закрыт получателем (например, вывод передали в head)
                // — стандартные утилиты в этом случае завершаются тихо.
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("Ошибка при выводе отчёта: {}", e);
                    ExitCode::FAILURE
                }
            }
        }
        Err(e) => {
            // goblin вернул ошибку: это не ELF (нет магии \x7fELF) либо
            // файл обрезан/повреждён.
            let _ = out.flush();
            eprintln!("Не удалось разобрать «{}» как ELF: {}", path, e);
            eprintln!("Подсказка: первые 4 байта ELF-файла должны быть 7f 45 4c 46.");
            ExitCode::FAILURE
        }
    }
}
