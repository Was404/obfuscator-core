//! Обфускация одной функции в исходнике на C.
//!
//! Получив от инспектора имя функции (и её адрес/размер в ELF — они
//! нужны, чтобы убедиться, что речь об интересующей нас функции),
//! обфускатор находит её определение в исходнике (csource) и переписывает
//! тело эквивалентными преобразованиями:
//!
//!   1. переименование локальных переменных и параметров — имя в
//!      программе ничего не значит для машины, но мешает читать код;
//!   2. разложение литералов 0 и 1 на выражения «(1 - 1)», «(2 - 1)»;
//!   3. вставка мёртвого кода — блока под изменяемым флагом, значение
//!      которого всегда нуль: никогда не выполняется, но компилятор не
//!      может его выбросить, поэтому функция в ELF вырастает.
//!
//! Все преобразования сохраняют поведение программы. Токенизатор
//! пропускает строки, символьные литералы и комментарии, поэтому
//! содержимое «printf("%d", 0)» не искажается.

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
    /// Сколько литералов 0/1 разложено на выражения.
    pub const_hits: usize,
    /// Сколько вставлено мёртвых блоков.
    pub dead_blocks: usize,
    /// Где функция находится в новом файле.
    pub new_span: CSpan,
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
            // только отдельные литералы 0 и 1, а не цифры внутри чисел.
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

// ── Детерминированный «хеш» имени ──────────────────────────────────

/// FNV-1a, младшие 4 hex-цифры: имена обфускации получаются разными
/// для разных переменных, но одинаковыми при повторных запусках.
fn hash4(name: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in name.bytes() {
        h ^= byte as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{:04x}", (h & 0xffff) as u16)
}

// ── Основная функция модуля ────────────────────────────────────────

/// Обфускация функции `func` в исходнике `src`. Возвращает новый текст
/// файла и отчёт о сделанных заменах.
pub fn obfuscate(src: &str, func: &str) -> Result<ObfResult, String> {
    // Шаг 1: находим определение функции в исходнике.
    let span = csource::find_function(src, func)
        .ok_or_else(|| format!("функция «{}» не найдена в исходнике", func))?;
    let text = &src[span.start..span.end];
    let toks = tokenize(text);

    // Шаг 2: локальные переменные и параметры → новые имена.
    let locals = collect_locals(text, &toks, func);
    let mut map: Vec<(String, String)> = Vec::new();
    for (i, old) in locals.iter().enumerate() {
        let mut new = format!("obf_{}_{}", i, hash4(old));
        // Новое имя не должно совпадать ни с одним идентификатором функции.
        while toks.iter().any(|t| t.kind == TokKind::Ident && t.text(text) == new) {
            new.push('_');
        }
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
    let mut const_hits = 0usize;
    for t in &toks {
        if t.kind != TokKind::Number {
            continue;
        }
        // Отдельные литералы 0 и 1 превращаем в выражения.
        let rep = match t.text(text) {
            "0" => Some("(1 - 1)"),
            "1" => Some("(2 - 1)"),
            _ => None,
        };
        if let Some(rep) = rep {
            edits.push((t.start, t.end, rep.to_string()));
            const_hits += 1;
        }
    }

    // Применяем замены с конца, чтобы смещения не поехали.
    edits.sort_by_key(|&(s, _, _)| std::cmp::Reverse(s));
    let mut new_text = text.to_string();
    for (s, e, rep) in &edits {
        new_text.replace_range(s..e, rep);
    }

    // Шаг 4: мёртвый код — блок с изменяемым флагом, который всегда
    // равен нулю. volatile запрещает компилятору выбросить блок даже
    // на -O0, поэтому функция в ELF реально вырастает; выполняться
    // блок всё равно никогда не будет.
    let body_open = new_text.find('{').ok_or("в функции не найдена открывающая скобка")?;
    let h = hash4(func);
    let gate = format!("obf_gate_{}", h);
    let sink = format!("obf_sink_{}", h);
    let dead = format!(
        "\n    static volatile long {} = 0; if ({}) {{ static long {}; {} += (0x5A5A ^ 0x1234) - (0x4B4B ^ 0x0F0F); }} /* dead code: gate всегда 0 */",
        gate, gate, sink, sink
    );
    new_text.insert_str(body_open + 1, &dead);
    let dead_blocks = 1usize;

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
        new_span,
    })
}
