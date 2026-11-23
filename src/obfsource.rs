//! Полиморфная обфускация одной функции в исходнике на C.
//!
//! Получив от инспектора имя функции (и её адрес/размер в ELF — они
//! нужны, чтобы убедиться, что речь об интересующей нас функции),
//! обфускатор находит её определение в исходнике (csource) и переписывает
//! тело эквивалентными преобразованиями. Ключевое свойство полиморфного
//! режима: все решения принимает ГПСЧ, посеянный зерном (seed), поэтому
//! каждый запуск создаёт НОВЫЙ вариант кода — с тем же поведением:
//!
//!   1. переименование локальных переменных и параметров — имя берётся
//!      из пула случайных «безликих» имён, уникальное для этого запуска;
//!   2. разложение десятичных литералов на случайные выражения
//!      («(a ^ b)», «(a + b)», «(a - b)», «(a * b ± c)», «(a << k) + b»):
//!      форма, константы и глубина вложенности (до трёх слоёв) случайны;
//!   3. вставка мёртвых блоков двух семейств: с volatile-флагом, который
//!      всегда равен нулю, и под непрозрачным предикатом «p*(p+1) всегда
//!      чётно» — ветвь никогда не выполняется, но компилятор не может её
//!      выбросить, поэтому функция в ELF вырастает;
//!   4. безвредные блоки под всегда истинным предикатом «v*v+v чётно»;
//!   5. мусорные комментарии и случайный порядок вставок — меняют
//!      «облик» файла, не трогая семантику.
//!
//! Эквивалентность гарантируется построением: каждая замена заменяет
//! выражение арифметически равным, мёртвый код не выполняется вовсе,
//! а «живой» блок под истинным предикатом пишет только в собственную
//! локальную переменную. Зерно можно зафиксировать ключом -s: одинаковый
//! seed → одинаковый результат (воспроизводимость для отладки), разные
//! seed → непохожие варианты (полиморфизм).
//!
//! Токенизатор пропускает строки, символьные литералы и комментарии,
//! поэтому содержимое «printf("%d", 0)» не искажается; препроцессорные
//! строки (#include, #if) не трогаются вовсе.

use std::collections::HashSet;

use crate::csource::{self, CSpan};

/// Ключевые слова-типы: с них начинается объявление.
const TYPE_KW: &[&str] = &[
    "void", "char", "short", "int", "long", "float", "double", "signed", "unsigned",
    "bool", "_Bool", "size_t", "ssize_t", "ptrdiff_t", "intptr_t", "uintptr_t",
    "int8_t", "int16_t", "int32_t", "int64_t", "uint8_t", "uint16_t", "uint32_t",
    "uint64_t", "FILE",
];
/// Квалификаторы и классы памяти: могут стоять перед типом.
const QUAL_KW: &[&str] = &[
    "static", "extern", "register", "auto", "const", "volatile", "inline",
    "restrict", "struct", "union", "enum", "_Atomic", "thread_local", "_Noreturn",
];

/// Итог обфускации одной функции.
pub struct ObfResult {
    /// Весь файл с заменённой функцией.
    pub new_source: String,
    /// Переименования: (старое имя, новое имя).
    pub renames: Vec<(String, String)>,
    /// Сколько вхождений идентификаторов заменено.
    pub rename_hits: usize,
    /// Сколько литералов разложено на выражения.
    pub const_hits: usize,
    /// Сколько вставлено мёртвых блоков (не выполняются никогда).
    pub dead_blocks: usize,
    /// Сколько вставлено безвредных блоков под истинным предикатом.
    pub opaque_blocks: usize,
    /// Сколько вставлено мусорных комментариев.
    pub junk_comments: usize,
    /// Зерно ГПСЧ, на котором построен именно этот вариант.
    pub seed: u64,
    /// Где функция находится в новом файле.
    pub new_span: CSpan,
}

// ── Полиморфное ядро: ГПСЧ ─────────────────────────────────────────

/// Зерно по умолчанию: наносекунды системных часов, смешанные с PID.
/// Два запуска в одну наносекунду в одном процессе не встречаются на
/// практике, поэтому каждый прогон конвейера получает новое зерно.
pub fn random_seed() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x5EED_C0FF_EE5E_ED5);
    let pid = u64::from(std::process::id());
    nanos.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ pid.rotate_left(32)
}

/// Разбор зерна из аргумента командной строки: десятичное или 0x-hex.
pub fn parse_seed(s: &str) -> Option<u64> {
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

/// SplitMix64 — компактный и качественный ГПСЧ без внешних крейтов.
/// Одного u64-состояния хватает на весь прогон обфускации.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Случайное число из [lo, hi] включительно.
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        debug_assert!(lo <= hi);
        lo + self.next_u64() % (hi - lo + 1)
    }

    /// Выпадение с вероятностью pct процентов.
    fn chance(&mut self, pct: u64) -> bool {
        self.range(1, 100) <= pct
    }

    /// Случайный элемент среза.
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.range(0, xs.len() as u64 - 1) as usize]
    }

    /// Четыре hex-цифры — строительный блок имён.
    fn hex4(&mut self) -> String {
        format!("{:04x}", self.next_u64() & 0xFFFF)
    }
}

// ── Полиморфное ядро: случайные имена ──────────────────────────────

/// Префиксы «безликих» имён переменных: не раскрывают смысла и при
/// этом похожи на обычный код.
const NAME_PRE: &[&str] = &[
    "var", "tmp", "val", "buf", "aux", "dat", "ndx", "ptr", "cnt", "res", "obf",
];
/// Буквы для коротких имён вида «q42», «z7».
const NAME_LET: &[char] = &['a', 'b', 'q', 'v', 'w', 'x', 'z'];
/// Префиксы имён для мёртвого кода: по ним видно, что блок служебный.
const DEAD_PRE: &[&str] = &[
    "obf_gate", "obf_sink", "dead", "junk", "scratch", "spare", "unused",
];

/// Случайное «безликое» имя одного из пяти стилей; имя проверяется на
/// уникальность по множеству занятых и сразу туда заносится. Одинаковое
/// зерно → одинаковые имена, разное → полностью другие.
fn poly_name(rng: &mut Rng, used: &mut HashSet<String>) -> String {
    for _ in 0..64 {
        let cand = match rng.range(0, 4) {
            0 => format!("obf_v_{}", rng.hex4()),
            1 => format!(
                "{}{}{}",
                rng.pick(NAME_LET),
                rng.pick(NAME_LET),
                rng.range(1, 99)
            ),
            2 => format!("_x{}", rng.hex4()),
            3 => format!("{}_{}", rng.pick(NAME_PRE), rng.range(0, 999)),
            _ => format!("{}{}", rng.pick(NAME_LET), rng.range(1, 9999)),
        };
        if !used.contains(&cand) {
            used.insert(cand.clone());
            return cand;
        }
    }
    // Практически недостижимый запасной путь: добираем «_», пока свободно.
    let mut cand = format!("obf_v_{}", rng.hex4());
    while used.contains(&cand) {
        cand.push('_');
    }
    used.insert(cand.clone());
    cand
}

/// Случайное имя для мёртвого кода: префикс из служебного пула + hex.
fn dead_name(rng: &mut Rng, used: &mut HashSet<String>) -> String {
    for _ in 0..64 {
        let cand = format!("{}_{}", rng.pick(DEAD_PRE), rng.hex4());
        if !used.contains(&cand) {
            used.insert(cand.clone());
            return cand;
        }
    }
    let mut cand = format!("obf_gate_{}", rng.hex4());
    while used.contains(&cand) {
        cand.push('_');
    }
    used.insert(cand.clone());
    cand
}

// ── Полиморфное ядро: разложение литералов ─────────────────────────

/// Случайное выражение на C, значение которого равно n. depth — сколько
/// слоёв вложенности разрешено (0 — просто число); константы каждого
/// слоя сами разлагаются на следующем, поэтому варианты глубоко
/// различаются между запусками. Все формы арифметически точны.
fn lit_expr(rng: &mut Rng, n: u64, depth: u32) -> String {
    if depth == 0 {
        return n.to_string();
    }
    match rng.range(0, 5) {
        // n = a ^ b, где b = n ^ a — точно для любого n, включая 0 и 1.
        0 => {
            let a = rng.range(1, 0xFFFF);
            let b = n ^ a;
            let (ta, tb) = two_slots(rng, a, b, depth - 1);
            format!("({ta} ^ {tb})")
        }
        // n = a + b, a выбирается внутри [0, n].
        1 => {
            let a = if n == 0 { 0 } else { rng.range(0, n) };
            let b = n - a;
            let (ta, tb) = two_slots(rng, a, b, depth - 1);
            format!("({ta} + {tb})")
        }
        // n = a - b, где a = n + b; при переполнении откат на xor-форму.
        2 => {
            let b = rng.range(1, 0x0800);
            match n.checked_add(b) {
                Some(a) => {
                    let (ta, tb) = two_slots(rng, a, b, depth - 1);
                    format!("({ta} - {tb})")
                }
                None => {
                    let a = 0x2B;
                    let (ta, tb) = two_slots(rng, a, n ^ a, depth - 1);
                    format!("({ta} ^ {tb})")
                }
            }
        }
        // n = a*b + c либо a*b - c — работает для любого n.
        3 => {
            let a = rng.range(2, 12);
            let b = rng.range(2, 12);
            let p = a * b;
            let (ta, tb) = two_slots(rng, a, b, depth - 1);
            if p <= n {
                let tc = lit_expr(rng, n - p, depth - 1);
                format!("({ta} * {tb} + {tc})")
            } else {
                let tc = lit_expr(rng, p - n, depth - 1);
                format!("({ta} * {tb} - {tc})")
            }
        }
        // n = (a << k) + b, где a = n >> k, b = n & ((1 << k) - 1).
        _ => {
            let k = rng.range(0, 3);
            let mask = (1u64 << k) - 1;
            let a = n >> k;
            let b = n & mask;
            let (ta, tb) = two_slots(rng, a, b, depth - 1);
            let tk = lit_expr(rng, k, depth - 1);
            format!("(({ta} << {tk}) + {tb})")
        }
    }
}

/// Тексты для двух позиций со значениями va и vb. Когда значения равны
/// (например, «(t - t)» или «(t ^ t)» для нуля), текст обязан быть
/// ОДНИМ И ТЕМ ЖЕ: две независимые развертки одной константы дали бы
/// разные выражения и разрушили равенство.
fn two_slots(rng: &mut Rng, va: u64, vb: u64, depth: u32) -> (String, String) {
    if va == vb {
        let t = lit_expr(rng, va, depth);
        (t.clone(), t)
    } else {
        (lit_expr(rng, va, depth), lit_expr(rng, vb, depth))
    }
}

// ── Полиморфное ядро: мёртвые и безвредные блоки ───────────────────

/// Мёртвый блок семейства A: ветвь под volatile-флагом, который в любой
/// точке программы равен нулю, поэтому тело никогда не выполняется, но
/// компилятор обязан его сохранить — функция в ELF растёт. Все константы
/// внутри уже разложены случайно, имена и форма уникальны для запуска.
fn dead_block_volatile(rng: &mut Rng, used: &mut HashSet<String>) -> String {
    let gate = dead_name(rng, used);
    let sink = dead_name(rng, used);
    let e0 = lit_expr(rng, 0, 1); // значение флага: выражение, равное 0
    let c0 = rng.range(0x10, 0xFFFF);
    let s0 = lit_expr(rng, c0, 1);
    let c1 = rng.range(0x100, 0xFFFF);
    let e1 = lit_expr(rng, c1, 1);
    let c2 = rng.range(0x100, 0xFFFF);
    let e2 = lit_expr(rng, c2, 1);
    format!(
        "\n    /* мёртвый код: volatile-флаг всегда 0, тело не выполняется */\n    static volatile long {gate} = {e0};\n    if ({gate}) {{\n        static long {sink} = {s0};\n        {sink} += {e1};\n        {sink} ^= {e2};\n    }}",
        gate = gate,
        e0 = e0,
        sink = sink,
        s0 = s0,
        e1 = e1,
        e2 = e2,
    )
}

/// Мёртвый блок семейства B: ветвь под непрозрачным предикатом.
/// Произведение двух последовательных целых p*(p+1) всегда чётно,
/// поэтому «% 2 != 0» ложно при любом значении p — тело недостижимо.
/// Анализатор же видит зависимость от переменной и обязан её разбирать.
fn dead_block_predicate(rng: &mut Rng, used: &mut HashSet<String>) -> String {
    let p = dead_name(rng, used);
    let sink = dead_name(rng, used);
    let cv = rng.range(0x100, 0xFFFF);
    let ev = lit_expr(rng, cv, 1);
    let c1 = rng.range(0x10, 0xFFFF);
    let j1 = lit_expr(rng, c1, 2);
    let c2 = rng.range(0x01, 0x0FFF);
    let j2 = lit_expr(rng, c2, 1);
    format!(
        "\n    /* мёртвая ветвь: p*(p+1) всегда чётно, условие ложно */\n    long {p} = {ev};\n    if ((({p} * ({p} + 1)) % 2) != 0) {{\n        long {sink} = {j1};\n        {sink} ^= {j2};\n        (void){sink};\n    }}",
        p = p,
        ev = ev,
        sink = sink,
        j1 = j1,
        j2 = j2,
    )
}

/// Безвредный блок под всегда ИСТИННЫМ предикатом: v*v+v — тоже
/// произведение последовательных целых, всегда чётно. Тело выполняется,
/// но пишет только в собственную локальную переменную, поэтому поведение
/// программы не меняется. Такие блоки маскируют реальную логику.
fn opaque_block_always_true(rng: &mut Rng, used: &mut HashSet<String>) -> String {
    let p = dead_name(rng, used);
    let sink = dead_name(rng, used);
    let cv = rng.range(0x100, 0xFFFF);
    let ev = lit_expr(rng, cv, 1);
    let c1 = rng.range(0x10, 0xFFFF);
    let j1 = lit_expr(rng, c1, 2);
    let c2 = rng.range(0x01, 0x0FFF);
    let j2 = lit_expr(rng, c2, 1);
    format!(
        "\n    /* всегда истинно: v*v+v чётно; блок безвреден */\n    long {p} = {ev};\n    if ((({p} * {p} + {p}) % 2) == 0) {{\n        long {sink} = {j1};\n        {sink} = {sink} ^ {j2};\n        (void){sink};\n    }}",
        p = p,
        ev = ev,
        sink = sink,
        j1 = j1,
        j2 = j2,
    )
}

/// Мусорный комментарий: меняет облик файла, компилятор его игнорирует.
fn junk_comment(rng: &mut Rng) -> String {
    format!("\n    /* {:#08x} */", rng.next_u64() & 0xFFFFFF)
}

// ── Токены ─────────────────────────────────────────────────────────

/// Вид токена. Opaque — куски, которые нельзя менять (строки,
/// литералы, комментарии); Preproc — токены строк с «#».
#[derive(Clone, Copy, PartialEq)]
enum TokKind {
    Ident,
    Number,
    Opaque,
    Preproc,
    Other,
}

struct Tok {
    start: usize,
    end: usize,
    kind: TokKind,
}

impl Tok {
    fn text<'a>(&self, s: &'a str) -> &'a str {
        &s[self.start..self.end]
    }
}

/// Разбор текста функции на токены. Пробелы в список не попадают.
fn tokenize(s: &str) -> Vec<Tok> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut line_start = true; // начало строки: там может стоять «#»
    let mut hash_line = false; // текущая строка — препроцессорная

    while i < b.len() {
        let c = b[i];
        if c == b'\n' {
            out.push(Tok { start: i, end: i + 1, kind: TokKind::Other });
            i += 1;
            line_start = true;
            hash_line = false;
            continue;
        }
        if (c as char).is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if line_start {
            // Заглядываем вперёд: если первый непробельный символ строки
            // «#», все её токены помечаем Preproc и не трогаем.
            let mut j = i;
            while j < b.len() && (b[j] as char).is_ascii_whitespace() {
                j += 1;
            }
            hash_line = b.get(j) == Some(&b'#');
            line_start = false;
        }
        let kind0 = if hash_line { TokKind::Preproc } else { TokKind::Other };
        // ВАЖНО: числа проверяем раньше идентификаторов — иначе «0»
        // уйдёт в ветку идентификаторов (цифра тоже «буква» по is_ident).
        if c.is_ascii_digit() {
            // Число целиком: 0, 10, 0x1F, 1.5, 5ULL — чтобы заменять
            // только отдельные литералы, а не цифры внутри чисел.
            let st = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'.' || b[i] == b'_') {
                i += 1;
            }
            out.push(Tok { start: st, end: i, kind: if hash_line { TokKind::Preproc } else { TokKind::Number } });
        } else if is_ident(c) {
            let st = i;
            while i < b.len() && is_ident(b[i]) {
                i += 1;
            }
            out.push(Tok { start: st, end: i, kind: if hash_line { TokKind::Preproc } else { TokKind::Ident } });
        } else if c == b'"' || c == b'\'' {
            // Строка или символьный литерал — один непрозрачный токен.
            let end = lit_end(b, i);
            out.push(Tok { start: i, end, kind: TokKind::Opaque });
            i = end;
        } else if c == b'/' && i + 1 < b.len() && (b[i + 1] == b'/' || b[i + 1] == b'*') {
            let end = if b[i + 1] == b'/' {
                b[i..].iter().position(|&x| x == b'\n').map(|p| i + p).unwrap_or(b.len())
            } else {
                b[i..]
                    .windows(2)
                    .position(|w| w == b"*/")
                    .map(|p| i + p + 2)
                    .unwrap_or(b.len())
            };
            out.push(Tok { start: i, end, kind: TokKind::Opaque });
            i = end;
        } else {
            out.push(Tok { start: i, end: i + 1, kind: kind0 });
            i += 1;
        }
    }
    out
}

/// Конец строкового/символьного литерала (позиция за закрывающей кавычкой).
fn lit_end(b: &[u8], i: usize) -> usize {
    let quote = b[i];
    let mut j = i + 1;
    while j < b.len() {
        match b[j] {
            b'\\' => j += 2,
            c if c == quote => return j + 1,
            _ => j += 1,
        }
    }
    b.len()
}

fn is_ident(c: u8) -> bool {
    c == b'_' || c.is_ascii_alphanumeric()
}

/// Слово-тип или квалификатор: может начинать объявление.
fn is_type_word(s: &str) -> bool {
    TYPE_KW.contains(&s) || QUAL_KW.contains(&s)
}

/// Любое ключевое слово C, которое не может быть именем типа:
/// защищает эвристику от «return steps» и похожих конструкций.
fn is_kw(s: &str) -> bool {
    is_type_word(s)
        || matches!(
            s,
            "return" | "if" | "else" | "while" | "for" | "do" | "switch" | "case"
                | "default" | "break" | "continue" | "goto" | "sizeof" | "typedef"
        )
}

/// Управляющее ключевое слово (не тип): перед объявлением стоять не может.
fn is_control_kw(s: &str) -> bool {
    is_kw(s) && !is_type_word(s)
}

// ── Сбор локальных имён ────────────────────────────────────────────

/// Сбор имён локальных переменных и параметров функции.
///
/// Так как в списке токенов нет пробелов, «следующий токен» — это
/// просто tokens[k + 1]. Объявление узнаётся по огрызку грамматики:
///     [квалификаторы/типы...] [*...] имя [= , ; [ ]
/// причём цепочка типов может содержать не более одного «постороннего»
/// идентификатора (имя типа из typedef или тег структуры).
fn collect_locals(text: &str, toks: &[Tok], func_name: &str) -> Vec<String> {
    let b = text.as_bytes();

    // Шаг 1: область параметров — первая «(» в определении и её пара.
    let param_range = toks
        .iter()
        .position(|t| t.kind == TokKind::Other && t.text(text) == "(")
        .and_then(|open| {
            csource::match_bracket(b, toks[open].start, b'(', b')').map(|close| (open, close))
        });

    // Шаг 2: глубина круглых скобок перед каждым токеном + диапазоны
    // заголовков for (там объявления тоже разрешены грамматикой C).
    let mut depth = vec![0i32; toks.len()];
    let mut for_ranges: Vec<(usize, usize)> = Vec::new();
    {
        let mut d = 0i32;
        let mut k = 0usize;
        while k < toks.len() {
            depth[k] = d;
            let t = &toks[k];
            if t.kind == TokKind::Other {
                match t.text(text) {
                    "(" => {
                        // Заголовок цикла for( ... )?
                        if k > 0 && toks[k - 1].kind == TokKind::Ident
                            && toks[k - 1].text(text) == "for"
                        {
                            if let Some(close) = csource::match_bracket(b, t.start, b'(', b')') {
                                let close_idx = toks.iter().position(|x| x.start == close);
                                if let Some(ci) = close_idx {
                                    for_ranges.push((k, ci));
                                }
                            }
                        }
                        d += 1;
                    }
                    ")" => d -= 1,
                    _ => {}
                }
            }
            k += 1;
        }
    }
    let in_ctx = |k: usize| -> bool {
        if let Some((po, pc)) = param_range {
            if po <= k && k <= pc {
                return true; // внутри списка параметров
            }
        }
        if depth[k] == 0 {
            return true; // уровень оператора (вне круглых скобок)
        }
        for_ranges.iter().any(|&(a, z)| a <= k && k <= z)
    };

    // Шаг 3: обход токенов и распознавание объявлений.
    let mut decls: Vec<String> = Vec::new();
    for k in 0..toks.len() {
        let t = &toks[k];
        if t.kind != TokKind::Ident || !in_ctx(k) {
            continue;
        }
        let name = t.text(text);
        if TYPE_KW.contains(&name) || QUAL_KW.contains(&name) {
            continue; // это ключевое слово, а не имя
        }
        // Следующий токен: у объявленного имени дальше = , ; [ или )
        let Some(next) = toks.get(k + 1) else { continue };
        let ok_next = next.kind == TokKind::Other
            && matches!(next.text(text), "=" | "," | ";" | "[" | ")");
        if !ok_next {
            continue;
        }
        // Смотрим назад: перед именем должны быть «*» и/или типы.
        let mut j = k;
        let mut saw_star = false;
        while j > 0 && toks[j - 1].kind == TokKind::Other && toks[j - 1].text(text) == "*" {
            saw_star = true;
            j -= 1;
        }
        // Особый случай для «long *a, *b»: после цепочки «*» обязан
        // стоять тип, имя typedef с типом перед ним или запятая —
        // иначе «a * b;» (умножение) примем за объявление.
        let star_ok = !saw_star
            || (j > 0 && {
                let p = toks[j - 1].text(text);
                let pk = toks[j - 1].kind;
                if p == "," {
                    true
                } else if pk == TokKind::Ident && !is_control_kw(p) {
                    // Тип или имя typedef: «long *a», «struct Point *p»,
                    // «unsigned Foo *p». Голое «a * b» так не проходит:
                    // перед именем-типом должно стоять тип-слово.
                    j >= 2
                        && toks[j - 2].kind == TokKind::Ident
                        && is_type_word(toks[j - 2].text(text))
                } else {
                    false
                }
            });
        let prev_ok = j > 0 && {
            let p = toks[j - 1].text(text);
            match toks[j - 1].kind {
                // Идентификатор перед объявлением: тип («long x») или имя
                // typedef/тег («Point p», «struct Foo p») — но не
                // управляющее ключевое слово («return steps»).
                TokKind::Ident => !is_control_kw(p),
                TokKind::Other => is_type_word(p),
                _ => false,
            }
        };
        if prev_ok && star_ok && !decls.contains(&name.to_string()) && name != func_name {
            decls.push(name.to_string());
        }
    }
    decls
}

// ── Основная функция модуля ────────────────────────────────────────

/// Полиморфная обфускация функции `func` в исходнике `src`.
///
/// `seed` — зерно ГПСЧ: `None` → случайное зерно от системных часов
/// (новый вариант при каждом запуске), `Some(n)` → воспроизводимый
/// вариант (одинаковое n даёт побайтово одинаковый результат).
/// Возвращает новый текст файла и отчёт о сделанных заменах.
pub fn obfuscate(src: &str, func: &str, seed: Option<u64>) -> Result<ObfResult, String> {
    let seed = seed.unwrap_or_else(random_seed);
    let mut rng = Rng(seed);

    // Шаг 1: находим определение функции в исходнике.
    let span = csource::find_function(src, func)
        .ok_or_else(|| format!("функция «{}» не найдена в исходнике", func))?;
    let text = &src[span.start..span.end];
    let toks = tokenize(text);

    // Резерв имён: все идентификаторы функции — новые имена не должны
    // совпасть ни с одним из них, ни между собой.
    let mut used: HashSet<String> = toks
        .iter()
        .filter(|t| t.kind == TokKind::Ident)
        .map(|t| t.text(text).to_string())
        .collect();

    // Шаг 2: локальные переменные и параметры → случайные имена.
    let locals = collect_locals(text, &toks, func);
    let mut map: Vec<(String, String)> = Vec::new();
    for old in &locals {
        let new = poly_name(&mut rng, &mut used);
        map.push((old.clone(), new));
    }

    // Шаг 3: список замен байтовых диапазонов исходной функции.
    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    let mut rename_hits = 0usize;
    for t in &toks {
        if t.kind != TokKind::Ident {
            continue;
        }
        let name = t.text(text);
        if let Some((_, new)) = map.iter().find(|(o, _)| o == name) {
            edits.push((t.start, t.end, new.clone()));
            rename_hits += 1;
        }
    }

    // Шаг 3b: разложение литералов. Кандидат — чисто десятичный литерал
    // (0x1F, 1.5 и 10L не трогаем); с вероятностью 15 % литерал
    // пропускается, поэтому и состав замен меняется от запуска к запуску.
    let mut const_hits = 0usize;
    for t in &toks {
        if t.kind != TokKind::Number {
            continue;
        }
        let s = t.text(text);
        if !s.bytes().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let Ok(n) = s.parse::<u64>() else { continue };
        if !rng.chance(85) {
            continue; // этот литерал остался как есть — полиморфизм интенсивности
        }
        let depth = *rng.pick(&[1u32, 1, 1, 2, 2, 3]);
        let rep = lit_expr(&mut rng, n, depth);
        edits.push((t.start, t.end, rep));
        const_hits += 1;
    }

    // Применяем замены с конца, чтобы смещения не поехали.
    edits.sort_by_key(|&(s, _, _)| std::cmp::Reverse(s));
    let mut new_text = text.to_string();
    for (s, e, rep) in &edits {
        new_text.replace_range(s..e, rep);
    }

    // Шаг 4: вставки после «{» тела функции. Позицию ищем заново в
    // new_text: замены шага 3 (разложения литералов) меняют длины, поэтому
    // координаты исходных токенов больше не годятся. «{» после «)» — это
    // именно тело функции, а не initializer списка вроде «int a[] = {…}».
    let new_toks = tokenize(&new_text);
    let body_at = new_toks
        .iter()
        .enumerate()
        .find(|&(k, t)| {
            t.kind == TokKind::Other
                && t.text(&new_text) == "{"
                && k > 0
                && new_toks[k - 1].kind == TokKind::Other
                && new_toks[k - 1].text(&new_text) == ")"
        })
        .map(|(_, t)| t.end)
        .ok_or("в функции не найдено тело («{» после «)»)")?;

    // Мёртвые блоки (1–3) и безвредные блоки (0–2) — семейство и
    // константы каждого выбираются ГПСЧ; мусорные комментарии (0–2)
    // добавляют разброса внешнему виду. Порядок вставок перемешивается.
    let mut inserts: Vec<String> = Vec::new();
    let mut dead_blocks = 0usize;
    let mut opaque_blocks = 0usize;
    for _ in 0..rng.range(1, 3) {
        inserts.push(match rng.range(0, 1) {
            0 => {
                dead_blocks += 1;
                dead_block_volatile(&mut rng, &mut used)
            }
            _ => {
                dead_blocks += 1;
                dead_block_predicate(&mut rng, &mut used)
            }
        });
    }
    for _ in 0..rng.range(0, 2) {
        opaque_blocks += 1;
        inserts.push(opaque_block_always_true(&mut rng, &mut used));
    }
    let mut junk_comments = 0usize;
    for _ in 0..rng.range(0, 2) {
        junk_comments += 1;
        inserts.push(junk_comment(&mut rng));
    }
    // Фишер–Йетс: случайный порядок вставок.
    for i in (1..inserts.len()).rev() {
        let j = rng.range(0, i as u64) as usize;
        inserts.swap(i, j);
    }
    let mut at = body_at;
    for ins in &inserts {
        new_text.insert_str(at, ins);
        at += ins.len();
    }

    // Шаг 5: собираем новый файл целиком и перепроверяем разбор.
    let mut new_source = String::with_capacity(src.len());
    new_source.push_str(&src[..span.start]);
    new_source.push_str(&new_text);
    new_source.push_str(&src[span.end..]);
    let new_span = csource::find_function(&new_source, func)
        .ok_or("после обфускации функция не разбирается — откат")?;

    Ok(ObfResult {
        new_source,
        renames: map,
        rename_hits,
        const_hits,
        dead_blocks,
        opaque_blocks,
        junk_comments,
        seed,
        new_span,
    })
}
