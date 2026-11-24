//! Байтовая полиморфная обфускация готового ELF-файла.
//!
//! Конвейер «C-исходник → ELF» умеет переписывать тело функции, потому
//! что у него есть исходник. У готового бинарника (/bin/ls и т.п.)
//! исходника нет: переписывать машинный код без дизассемблера нельзя.
//! Поэтому здесь обфусцируется всё ВОКРУГ кода — причём только те
//! области, которые гарантированно не участвуют в работе программы:
//!
//!   1. свободное место в исполняемых секциях («code caves»): серии
//!      паддинга (00 / 90 / CC) длиной от 6 байт, лежащие строго МЕЖДУ
//!      двумя соседними границами функций, зазор между которыми не
//!      превышает 32 байт. Границы функций берутся из двух источников:
//!      кандидаты инспектора (символы .symtab/.dynsym) и unwind-таблица
//!      .eh_frame (записи FDE — точные диапазоны каждого тела, есть даже
//!      у stripped-бинарников). Зазор ≤ 32 байт может быть только
//!      выравниванием между функциями; всё, что крупнее (тело функции
//!      без unwind-информации), не трогается вовсе. Такая строгость
//!      обязательна: серия нулей может оказаться частью настоящей
//!      инструкции (disp32+imm32 дают подряд до 8 нулей внутри
//!      «mov $0, 0xc8(%r12)»), а nop-сани — исполняемым кодом. Проверено
//!      запуском на /bin/ls, /bin/cat, /bin/bash, gcc и curl: наивная
//!      эвристика «нули — это паддинг» ломает бинарник, правило
//!      «между соседними FDE ≤ 32 байт» — нет;
//!   2. секция .comment (подпись компилятора — «антифингерпринт»);
//!   3. межсекционные гэпы файла (выравнивание секций, не покрытые ни
//!      секциями, ни таблицами заголовков);
//!   4. в конец файла добавляется безымянная junk-секция — файл
//!      меняет размер и «отпечаток», загрузчик секции не читает.
//!
//! Паддинг e_ident[EI_PAD] заголовка намеренно НЕ трогается: glibc
//! (ld.so --verify, а значит и ldd) требует нулевой EI_PAD, и на его
//! изменение отвечает «not a dynamic executable» при полностью
//! работоспособном файле.
//!
//! Все решения и содержимое мусора берёт ГПСЧ (SplitMix64, тот же, что
//! и в обфускаторе исходников): без -s каждый запуск даёт новый вариант,
//! одинаковый seed — побайтово одинаковый результат. Кандидаты инспектора
//! (имя, адрес, размер, смещение каждой функции) — это карта «что не
//! трогать»: байты функций защищены от всех преобразований.
//!
//! Все замены, кроме junk-секции, сохраняют длину файла, поэтому ни
//! адреса, ни смещения не сдвигаются. Проверка эквивалентности — запуск
//! оригинала и варианта со сравнением вывода (как и в C-конвейере).

use goblin::elf::Elf;

use crate::inspector::Candidate;
use crate::obfsource::{random_seed, Rng};

/// Байты, из которых состоит паддинг исполняемых секций: нулевое
/// выравнивание, однобайтовый nop (0x90) и int3-заполнитель (0xCC).
const PAD_BYTES: [u8; 3] = [0x00, 0x90, 0xCC];
/// Минимальная длина «пещеры»: серии короче не трогаем — такая серия
/// может оказаться частью инструкции (imm32/displacement).
const MIN_CAVE: usize = 6;
/// Максимальный зазор между двумя соседними границами функций, внутри
/// которого разрешено заполнять пещеры: больше может быть только тело
/// функции без unwind-информации, а его трогать нельзя.
const MAX_PROT_GAP: usize = 32;
/// Минимальный размер межсекционного гэпа, который стоит заполнять.
const MIN_GAP: usize = 8;

/// Итог байтовой обфускации ELF.
pub struct ElfObfResult {
    /// Новый (обфусцированный) файл целиком.
    pub new_bytes: Vec<u8>,
    /// Зерно ГПСЧ, на котором построен именно этот вариант.
    pub seed: u64,
    /// Сколько code caves заполнено.
    pub caves: usize,
    /// Сколько байт мусора записано в code caves.
    pub cave_bytes: usize,
    /// Сколько байт секции .comment обезличено (0 — секции нет).
    pub comment_bytes: usize,
    /// Сколько байт межсекционных гэпов заполнено.
    pub gap_bytes: usize,
    /// (смещение, размер) добавленной junk-секции; None — не добавлялась.
    pub junk_section: Option<(u64, u64)>,
}

/// Снимок нужных полей ELF-заголовка и таблицы секций: разбор крейтом
/// goblin «нулевого копирования» заимствует байты файла, а перед
/// мутацией заём надо отпустить. Поэтому сначала снимаем копию
/// метаданных, потом работаем с файлом как с обычным Vec<u8>.
struct Snap {
    is64: bool,
    le: bool,
    ehsize: usize,
    phoff: usize,
    phnum: usize,
    phentsize: usize,
    shoff: usize,
    shnum: usize,
    shentsize: usize,
    secs: Vec<Sec>,
    segs: Vec<Seg>,
}

/// Копия одной записи таблицы секций (только то, что нужно обфускатору).
struct Sec {
    name: String,
    ty: u32,
    flags: u64,
    addr: u64,
    offset: usize,
    size: usize,
}

/// Копия программного заголовка: нужен для перевода виртуальных адресов
/// unwind-таблицы в смещения в файле.
struct Seg {
    ty: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
}

/// Тип сегмента PT_LOAD.
const PT_LOAD: u32 = 1;

/// Разбор файла: магия \x7fELF + снимок метаданных через goblin.
fn snapshot(bytes: &[u8]) -> Result<Snap, String> {
    if bytes.len() < 52 || &bytes[0..4] != &[0x7f, b'E', b'L', b'F'] {
        return Err("файл не начинается с магии \\x7fELF — это не ELF".into());
    }
    let elf = Elf::parse(bytes).map_err(|e| format!("ELF не разобрать: {}", e))?;
    let h = &elf.header;
    Ok(Snap {
        is64: elf.is_64,
        le: bytes[5] == 1, // EI_DATA: 1 — little endian
        ehsize: h.e_ehsize as usize,
        phoff: h.e_phoff as usize,
        phnum: h.e_phnum as usize,
        phentsize: h.e_phentsize as usize,
        shoff: h.e_shoff as usize,
        shnum: h.e_shnum as usize,
        shentsize: h.e_shentsize as usize,
        secs: elf
            .section_headers
            .iter()
            .map(|sh| Sec {
                name: elf
                    .shdr_strtab
                    .get_at(sh.sh_name as usize)
                    .unwrap_or("")
                    .to_string(),
                ty: sh.sh_type,
                flags: sh.sh_flags,
                addr: sh.sh_addr,
                offset: sh.sh_offset as usize,
                size: sh.sh_size as usize,
            })
            .collect(),
        segs: elf
            .program_headers
            .iter()
            .map(|p| Seg {
                ty: p.p_type,
                offset: p.p_offset,
                vaddr: p.p_vaddr,
                filesz: p.p_filesz,
            })
            .collect(),
    })
}

/// Запись целого фиксированной ширины (1/2/4/8 байт) с учётом порядка байт.
fn put(buf: &mut [u8], pos: usize, val: u64, width: usize, le: bool) {
    let all = if le { val.to_le_bytes() } else { val.to_be_bytes() };
    let chunk = if le { &all[..width] } else { &all[8 - width..] };
    buf[pos..pos + width].copy_from_slice(chunk);
}

/// Виртуальный адрес → смещение в файле по PT_LOAD-сегментам.
fn vaddr_to_off(snap: &Snap, vaddr: u64) -> Option<usize> {
    snap.segs.iter().find(|s| {
        s.ty == PT_LOAD && s.vaddr <= vaddr && vaddr < s.vaddr + s.filesz
    }).map(|s| (vaddr - s.vaddr + s.offset) as usize)
}

/// Диапазоны функций из unwind-таблицы .eh_frame (записи FDE).
///
/// Формат (gcc, x86-64, augmentation «zR»): цепочка записей
/// «длина (4 байта) …», у CIE поле на +4 равно 0, у FDE там указатель
/// на CIE. Нас интересует только пара pc_begin (pcrel sdata4 — смещение
/// относительно адреса самого поля) и pc_range (udata4) — точный диапазон
/// тела функции в памяти. Любая аномалия формата → Err: пещеры тогда
/// отключаются целиком, безопаснее не трогать ничего.
fn parse_fdes(bytes: &[u8], snap: &Snap) -> Result<Vec<(usize, usize)>, String> {
    let eh = snap
        .secs
        .iter()
        .find(|s| s.name == ".eh_frame" && s.ty == 1 && s.size >= 8)
        .ok_or_else(|| "нет секции .eh_frame".to_string())?;
    let (base_off, base_addr, size) = (eh.offset, eh.addr, eh.size);
    let mut fdes = Vec::new();
    let mut pos = 0usize;
    while pos + 4 <= size {
        let len = u32::from_le_bytes([
            bytes[base_off + pos],
            bytes[base_off + pos + 1],
            bytes[base_off + pos + 2],
            bytes[base_off + pos + 3],
        ]) as usize;
        if len == 0 {
            break; // терминатор таблицы
        }
        if len == 0xFFFFFFFF || pos + 4 + len > size {
            // 64-битный DWARF или обрыв — формат не тот, на что рассчитывали.
            return Err("неожиданный формат записи .eh_frame".into());
        }
        let cie_id = u32::from_le_bytes([
            bytes[base_off + pos + 4],
            bytes[base_off + pos + 5],
            bytes[base_off + pos + 6],
            bytes[base_off + pos + 7],
        ]);
        if cie_id == 0 {
            pos += 4 + len; // CIE — пропускаем целиком
            continue;
        }
        // FDE: pc_begin (pcrel sdata4) и pc_range (udata4) после заголовка.
        let pcrel_at = pos + 8;
        if pcrel_at + 8 > size {
            return Err("обрезанная запись FDE".into());
        }
        let rd32 = |at: usize| {
            u32::from_le_bytes([
                bytes[base_off + at],
                bytes[base_off + at + 1],
                bytes[base_off + at + 2],
                bytes[base_off + at + 3],
            ])
        };
        let delta = rd32(pcrel_at) as i32 as i64;
        let range = rd32(pcrel_at + 4) as u64;
        if range == 0 {
            return Err("FDE с нулевым диапазоном".into());
        }
        // pc_begin = адрес поля + pcrel-смещение; в файл — через сегменты.
        let field_vaddr = base_addr + pcrel_at as u64;
        let begin_vaddr = (field_vaddr as i64 + delta) as u64;
        let begin_off = vaddr_to_off(snap, begin_vaddr)
            .ok_or_else(|| format!("адрес FDE 0x{begin_vaddr:x} вне сегментов"))?;
        fdes.push((begin_off, begin_off + range as usize));
        pos += 4 + len;
    }
    Ok(fdes)
}

/// Случайный мусорный байт для кодовых областей: без 0x00, чтобы
/// «пещера» перестала выглядеть паддингом даже побайтово.
fn junk_byte(rng: &mut Rng) -> u8 {
    rng.range(1, 255) as u8
}

/// Случайный печатный ASCII-байт для строковых метаданных (.comment).
fn printable(rng: &mut Rng) -> u8 {
    rng.range(0x20, 0x7e) as u8
}

/// Поиск code caves в ОДНОЙ секции: серии паддинга длиной от MIN_CAVE,
/// для которых выполнено ВСЕ:
///   1. пещера не пересекается ни с одной защищённой функцией;
///   2. слева вплотную примыкает конец какой-то защищённой функции (L),
///      справа — начало какой-то (R);
///   3. зазор R − L не больше MAX_PROT_GAP — иначе это не выравнивание,
///      а, возможно, тело функции без unwind-информации.
/// `section_start` — смещение секции в файле (байты `blob` начинаются с
/// него); `protected` — пары (начало, конец) функций в файле.
/// Возвращает пары (смещение в файле, длина).
fn scan_exec_section(
    blob: &[u8],
    section_start: usize,
    protected: &[(usize, usize)],
) -> Vec<(usize, usize)> {
    let mut caves = Vec::new();
    let mut i = 0usize;
    while i < blob.len() {
        if PAD_BYTES.contains(&blob[i]) {
            let st = i;
            while i < blob.len() && PAD_BYTES.contains(&blob[i]) {
                i += 1;
            }
            let len = i - st;
            if len >= MIN_CAVE {
                let gs = section_start + st;
                let ge = gs + len;
                if protected.iter().any(|&(a, b)| gs < b && a < ge) {
                    continue; // внутри функции — не трогаем
                }
                let left = protected.iter().map(|&(_, b)| b).filter(|&b| b <= gs).max();
                let right = protected.iter().map(|&(a, _)| a).filter(|&a| a >= ge).min();
                if let (Some(l), Some(r)) = (left, right) {
                    if r - l <= MAX_PROT_GAP {
                        caves.push((gs, len));
                    }
                }
            }
        } else {
            i += 1;
        }
    }
    caves
}

/// Поиск code caves во всех исполняемых секциях файла.
fn find_caves(bytes: &[u8], protected: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let snap = match snapshot(bytes) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let mut caves = Vec::new();
    for s in &snap.secs {
        // SHF_EXECINSTR (0x4) + PROGBITS (1): только настоящий код.
        if s.flags & 0x4 == 0 || s.ty != 1 || s.size == 0 {
            continue;
        }
        let start = s.offset.min(bytes.len());
        let end = s.offset.saturating_add(s.size).min(bytes.len());
        caves.extend(scan_exec_section(&bytes[start..end], start, protected));
    }
    caves
}

/// Занятые диапазоны файла: заголовок ELF, таблица программных заголовков,
/// все содержательные секции (кроме NULL/NOBITS) и таблица секций.
/// NOBITS (.bss) исключён: его «размер» живёт в памяти, а не в файле.
/// Размер заголовка берём не только из e_ehsize: поле может быть
/// испорчено, поэтому пол — минимальный размер заголовка по классу.
fn occupied_ranges(snap: &Snap) -> Vec<(usize, usize)> {
    let hdr_floor = if snap.is64 { 64 } else { 52 };
    let hdr = snap.ehsize.max(hdr_floor).min(hdr_floor * 4);
    let mut occ = vec![(0usize, hdr)];
    if snap.phoff > 0 && snap.phnum > 0 {
        occ.push((snap.phoff, snap.phoff + snap.phnum * snap.phentsize));
    }
    if snap.shoff > 0 && snap.shnum > 0 {
        occ.push((snap.shoff, snap.shoff + snap.shnum * snap.shentsize));
    }
    for s in &snap.secs {
        if s.ty != 0 && s.ty != 8 && s.size > 0 {
            occ.push((s.offset, s.offset.saturating_add(s.size)));
        }
    }
    occ.sort_unstable();
    occ
}

/// Свободные гэпы между занятыми диапазонами длиной от MIN_GAP.
/// Оба конца зажимаются по длине файла: испорченные заголовки секций
/// могут указывать за пределы файла, и такой «гэп» нельзя трогать.
fn find_gaps(occupied: &[(usize, usize)], file_len: usize) -> Vec<(usize, usize)> {
    let mut gaps = Vec::new();
    let mut end = 0usize;
    for &(a, b) in occupied {
        let a = a.min(file_len);
        let b = b.min(file_len);
        if a >= end && a - end >= MIN_GAP {
            gaps.push((end, a - end));
        }
        end = end.max(b);
    }
    if file_len >= end && file_len - end >= MIN_GAP {
        gaps.push((end, file_len - end));
    }
    gaps
}

/// Добавление junk-секции в конец файла: одна запись в таблицу секций +
/// блоб мусора. Секция без имени (sh_name = 0), без флага SHF_ALLOC —
/// загрузчик её не отображает и не читает; инструменты же видят, что
/// файл изменился. Применяется только при классической раскладке:
/// таблица секций заканчивается ровно на конце файла.
fn add_junk_section(out: &mut Vec<u8>, rng: &mut Rng, snap: &Snap) -> Option<(u64, u64)> {
    if snap.shoff == 0 || snap.shnum == 0 || snap.shnum >= 0xff00 {
        return None; // нет таблицы секций или расширенная нумерация
    }
    let want_ent = if snap.is64 { 64 } else { 40 };
    if snap.shentsize != want_ent {
        return None;
    }
    let table_end = snap.shoff + snap.shnum * snap.shentsize;
    if table_end != out.len() {
        return None; // после таблицы секций есть чужие данные — не рискуем
    }
    let blob_len = rng.range(64, 512) as usize;

    // Новая запись Shdr: имя пустое, тип PROGBITS, флаги нулевые.
    let w4 = 4usize;
    let w = if snap.is64 { 8 } else { 4 };
    let (off_flags, off_addr, off_offset, off_size, off_align) = if snap.is64 {
        (8usize, 16, 24, 32, 48)
    } else {
        (8usize, 12, 16, 20, 32)
    };
    let mut entry = vec![0u8; snap.shentsize];
    let blob_off = table_end + snap.shentsize;
    let fields = [
        (0usize, w4),      // sh_name: без имени
        (4usize, w4),      // sh_type: PROGBITS
        (off_flags, w),    // sh_flags: не ALLOC — загрузчик не читает
        (off_addr, w),     // sh_addr: в память не отображается
        (off_offset, w),   // sh_offset: сразу за таблицей секций
        (off_size, w),     // sh_size
        (off_align, w),    // sh_addralign
    ];
    let vals = [0u64, 1, 0, 0, blob_off as u64, blob_len as u64, 1];
    for ((pos, width), v) in fields.iter().zip(vals.iter()) {
        put(&mut entry, *pos, *v, *width, snap.le);
    }

    out.extend_from_slice(&entry);
    let mut blob = Vec::with_capacity(blob_len);
    for _ in 0..blob_len {
        blob.push(junk_byte(rng));
    }
    let blob_at = blob_off;
    out.extend_from_slice(&blob);

    // e_shnum += 1: ELF64 — смещение 60, ELF32 — 48; ширина 2 байта.
    let shnum_at = if snap.is64 { 60 } else { 48 };
    put(out, shnum_at, (snap.shnum + 1) as u64, 2, snap.le);
    Some((blob_at as u64, blob_len as u64))
}

/// Главная функция модуля: полиморфная байтовая обфускация ELF.
///
/// `cands` — карта функций от инспектора (см. ElfInspector::candidates):
/// байты этих функций защищены от всех преобразований. `seed` — зерно
/// ГПСЧ: None → случайное, Some(n) → воспроизводимый вариант.
pub fn obfuscate(
    mut bytes: Vec<u8>,
    cands: &[Candidate],
    seed: Option<u64>,
) -> Result<ElfObfResult, String> {
    let seed = seed.unwrap_or_else(random_seed);
    let mut rng = Rng(seed);
    let snap = snapshot(&bytes)?;
    let file_len = bytes.len();

    // ── 1. Code caves: свободное место в исполняемых секциях.
    // e_ident[EI_PAD] не трогаем: glibc (ld.so --verify, ldd) требует
    // нулевой паддинг заголовка.
    //
    // Карта защиты = кандидаты инспектора + диапазоны FDE из .eh_frame
    // (покрывает и stripped-файлы). Разобрать unwind-таблицу не удалось —
    // пещеры просто отключаются, остальное работает.
    let mut protected: Vec<(usize, usize)> = cands
        .iter()
        .map(|c| (c.file_offset as usize, (c.file_offset + c.size) as usize))
        .collect();
    if let Ok(fdes) = parse_fdes(&bytes, &snap) {
        protected.extend(fdes);
    }
    let caves = find_caves(&bytes, &protected);
    let mut cave_bytes = 0usize;
    for &(at, len) in &caves {
        for b in &mut bytes[at..at + len] {
            *b = junk_byte(&mut rng);
            cave_bytes += 1;
        }
    }

    // ── 2. .comment — подпись тулчейна; забираем «отпечаток» компилятора.
    let mut comment_bytes = 0usize;
    if let Some(sec) = snap.secs.iter().find(|s| s.name == ".comment" && s.ty == 1 && s.size > 0) {
        let start = sec.offset.min(file_len);
        let end = sec.offset.saturating_add(sec.size).min(file_len);
        for b in &mut bytes[start..end] {
            *b = printable(&mut rng);
            comment_bytes += 1;
        }
    }

    // ── 3. Межсекционные гэпы файла.

    // ── 4. Межсекционные гэпы файла.
    let occupied = occupied_ranges(&snap);
    let mut gap_bytes = 0usize;
    for &(at, len) in &find_gaps(&occupied, file_len) {
        for b in &mut bytes[at..at + len] {
            *b = junk_byte(&mut rng);
            gap_bytes += 1;
        }
    }

    // ── 4. Junk-секция в конце файла (меняет размер и карту секций).
    let junk_section = add_junk_section(&mut bytes, &mut rng, &snap);

    // Контрольная перепроверка: файл обязан остаться валидным ELF.
    snapshot(&bytes)
        .map(|_| ())
        .map_err(|e| format!("после обфускации ELF не разбирается — откат: {}", e))?;

    Ok(ElfObfResult {
        new_bytes: bytes,
        seed,
        caves: caves.len(),
        cave_bytes,
        comment_bytes,
        gap_bytes,
        junk_section,
    })
}

// ── Тесты внутренностей ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Минимальный валидный ELF64-заголовок (LE) для синтетических тестов.
    fn minimal_elf64() -> Vec<u8> {
        let mut b = vec![0u8; 64];
        b[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        b[4] = 2; // класс: ELF64
        b[5] = 1; // порядок байт: LE
        b[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        b
    }

    #[test]
    fn obfuscate_rejects_non_elf() {
        assert!(obfuscate(vec![1, 2, 3, 4], &[], Some(1)).is_err());
        assert!(obfuscate(Vec::new(), &[], Some(1)).is_err());
    }

    #[test]
    fn obfuscate_same_seed_same_bytes() {
        let a = obfuscate(minimal_elf64(), &[], Some(42)).unwrap();
        let b = obfuscate(minimal_elf64(), &[], Some(42)).unwrap();
        assert_eq!(a.new_bytes, b.new_bytes);
        assert_eq!(a.seed, 42);
        // Без секций менять нельзя ничего; EI_PAD обязан остаться нулевым
        // (glibc --verify/ldd не принимают ненулевой паддинг заголовка).
        assert_eq!(a.caves, 0);
        assert_eq!(a.junk_section, None);
        assert_eq!(a.gap_bytes, 0);
        assert_eq!(&a.new_bytes[9..16], &[0u8; 7]);
        assert_eq!(&a.new_bytes[0..4], &[0x7f, b'E', b'L', b'F']);
    }

    #[test]
    fn obfuscate_header_only_changes_nothing() {
        // В файле без секций менять нечего: пещеры отключены, гэпов нет,
        // junk-секция не добавляется — результат обязан совпасть с исходником
        // на любом зерне (полиморфизм на настоящих бинарниках проверяют
        // интеграционные тесты tests/elf_tests.rs).
        let orig = minimal_elf64();
        for s in 1u64..=5 {
            let r = obfuscate(orig.clone(), &[], Some(s)).unwrap();
            assert_eq!(r.new_bytes, orig, "файл без секций не должен изменяться");
            assert_eq!(r.caves, 0);
            assert_eq!(r.gap_bytes, 0);
            assert_eq!(r.junk_section, None);
        }
    }

    #[test]
    fn obfuscate_preserves_file_length_without_junk_section() {
        let r = obfuscate(minimal_elf64(), &[], Some(7)).unwrap();
        assert_eq!(r.new_bytes.len(), 64);
    }

    /// Синтетическое тело исполняемой секции (файл-смещение начала — 64):
    /// [функция A 8][паддинг 6][функция B 8][паддинг 8][функция C 8].
    /// Код — не паддинг, промежутки — паддинг нужного вида.
    fn cave_fixture() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend([0x55u8, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3]); // A: 64..72
        b.extend([0x00, 0x90, 0x00, 0xcc, 0x00, 0x90]);               // пещера 72..78
        b.extend([0x55u8, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3]); // B: 78..86
        b.extend([0x00u8; 8]);                                        // пещера 86..94
        b.extend([0x55u8, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3]); // C: 94..102
        b
    }

    #[test]
    fn caves_only_between_close_protected_ranges() {
        let blob = cave_fixture();
        let prot = [(64usize, 72usize), (78, 86), (94, 102)];
        // Обе пещеры сидят в зазорах ≤ 32 между соседями — разрешены.
        assert_eq!(scan_exec_section(&blob, 64, &prot), vec![(72, 6), (86, 8)]);

        // Без защиты соседей пещер нет: справа/слева пусто → запрет.
        assert_eq!(scan_exec_section(&blob, 64, &[]), Vec::<(usize, usize)>::new());

        // Только один сосед — вторая пещера запрещена, первая разрешена.
        assert_eq!(scan_exec_section(&blob, 64, &[(64, 72), (78, 86)]), vec![(72, 6)]);
    }

    #[test]
    fn caves_rejected_in_wide_gaps_and_inside_functions() {
        let blob = cave_fixture();
        // Пещеры между (64,72) и (120,128) — зазор 48 > 32, обе запрещены.
        let prot = [(64usize, 72usize), (120, 128)];
        assert_eq!(scan_exec_section(&blob, 64, &prot), Vec::<(usize, usize)>::new());

        // Пещера внутри защищённой функции — пересечение, запрет:
        // первые два байта функции A заменяем паддингом, серия 70..78
        // задевает A (64..72) и потому целиком отвергается.
        let mut blob2 = cave_fixture();
        blob2[6] = 0x00;
        blob2[7] = 0x90;
        let prot2 = [(64usize, 72usize), (78, 86), (94, 102)];
        assert_eq!(scan_exec_section(&blob2, 64, &prot2), vec![(86, 8)]);
    }

    #[test]
    fn gaps_found_between_occupied_ranges() {
        let snap = Snap {
            is64: true,
            le: true,
            ehsize: 64,
            phoff: 64,
            phnum: 2,
            phentsize: 56,
            shoff: 300,
            shnum: 2,
            shentsize: 64,
            secs: vec![Sec {
                name: "a".into(),
                ty: 1,
                flags: 0,
                addr: 0,
                offset: 200,
                size: 20,
            }],
            segs: Vec::new(),
        };
        // Занято: 0..64 (заголовок), 64..176 (PH), 200..220 (секция),
        // 300..428 (SH). Гэпы: 176..200 (24) и 220..300 (80).
        let gaps = find_gaps(&occupied_ranges(&snap), 428);
        assert_eq!(gaps, vec![(176, 24), (220, 80)]);

        // При обрезке файла хвостовой гэп укорачивается, но остаётся.
        let gaps2 = find_gaps(&occupied_ranges(&snap), 290);
        assert_eq!(gaps2, vec![(176, 24), (220, 70)]);
    }

    #[test]
    fn put_respects_width_and_endianness() {
        let mut b = [0u8; 8];
        put(&mut b, 0, 0x0102_0304_0506_0708, 8, true);
        assert_eq!(b, [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
        put(&mut b, 0, 0x0102_0304_0506_0708, 8, false);
        assert_eq!(b, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        put(&mut b, 0, 0xabcd, 2, true);
        assert_eq!(b[..2], [0xcd, 0xab]);
    }
}
