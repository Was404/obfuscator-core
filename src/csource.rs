//! Поиск определений функций в исходнике на C.
//!
//! Обфускатор получает от инспектора имя функции (как она называется
//! в ELF), но переписывает код в исходнике. Этот модуль связывает то
//! и другое: находит в тексте программы определение функции по имени
//! и возвращает диапазон байтов, который она занимает.
//!
//! Разбор сделан без крейта-парсера: сканер идёт по байтам, понимает
//! строки, символьные литералы и комментарии, считает вложенность
//! фигурных скобок и отбирает конструкции вида
//!
//!     тип имя(параметры) { ... }
//!
//! на верхнем уровне файла. Этого достаточно для обычных программ
//! (K&R-определения и макросы, разворачивающиеся в функции, не
//! поддерживаются — на такой случай find_function вернёт None).

/// Диапазон байтов [start, end) — определение функции целиком,
/// от начала сигнатуры до закрывающей скобки «}».
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CSpan {
    /// Смещение первого байта определения.
    pub start: usize,
    /// Смещение за последним байтом определения.
    pub end: usize,
}

/// Определение функции в исходнике.
#[derive(Debug, Clone)]
pub struct CFunctionDef {
    /// Имя функции.
    pub name: String,
    /// Диапазон байтов определения.
    pub span: CSpan,
}

/// Все определения функций верхнего уровня в файле.
pub fn list_functions(src: &str) -> Vec<CFunctionDef> {
    scan_definitions(src, None)
}

/// Поиск определения функции по имени.
pub fn find_function(src: &str, name: &str) -> Option<CSpan> {
    scan_definitions(src, Some(name)).into_iter().next().map(|f| f.span)
}

/// Номер строки (с 1), на которой начинается смещение offset.
pub fn line_of(src: &str, offset: usize) -> usize {
    src.as_bytes()[..offset.min(src.len())]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        + 1
}

/// Единый сканер для list_functions и find_function: когда фильтр задан,
/// возвращается только функция с этим именем (поиск быстрее).
fn scan_definitions(src: &str, only: Option<&str>) -> Vec<CFunctionDef> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut depth = 0i32; // глубина фигурных скобок: определения — на уровне 0

    while i < b.len() {
        match b[i] {
            // Строчный комментарий — до конца строки.
            b'/' if i + 1 < b.len() && b[i + 1] == b'/' => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            // Блочный комментарий — до «*/».
            b'/' if i + 1 < b.len() && b[i + 1] == b'*' => {
                i += 2;
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(b.len());
            }
            // Строка или символьный литерал — целиком пропускаем,
            // чтобы скобки и имена внутри не сбивали сканер.
            b'"' => i = skip_literal(b, i, b'"'),
            b'\'' => i = skip_literal(b, i, b'\''),
            b'{' => {
                depth += 1;
                i += 1;
            }
            b'}' => {
                depth -= 1;
                i += 1;
            }
            // Идентификатор на верхнем уровне — кандидат в имя функции.
            _ if depth == 0 && is_ident_start(b[i]) => {
                let s = i;
                while i < b.len() && is_ident_char(b[i]) {
                    i += 1;
                }
                let word = &src[s..i];
                if let Some(f) = only {
                    if word != f {
                        continue;
                    }
                }
                // Определение: за именем идут «(параметры)» и «{».
                // (После «)» стоит «;» у прототипа — такой случай отсеется.)
                let j = skip_ws_comments(b, i);
                if b.get(j) == Some(&b'(') {
                    if let Some(close) = match_bracket(b, j, b'(', b')') {
                        let k = skip_ws_comments(b, close + 1);
                        if b.get(k) == Some(&b'{') {
                            if let Some(end) = match_bracket(b, k, b'{', b'}') {
                                out.push(CFunctionDef {
                                    name: word.to_string(),
                                    span: CSpan { start: s, end: end + 1 },
                                });
                                // Тело перепрыгиваем целиком — внутри него
                                // других определений верхнего уровня нет.
                                i = end + 1;
                                continue;
                            }
                        }
                    }
                }
                // Не определение (например, спецификатор static/int) —
                // просто продолжаем со следующего токена.
            }
            _ => i += 1,
        }
    }
    out
}

/// Пропуск пробелов и комментариев; возвращает новую позицию.
pub fn skip_ws_comments(b: &[u8], mut i: usize) -> usize {
    loop {
        while i < b.len() && (b[i] as char).is_ascii_whitespace() {
            i += 1;
        }
        if i + 1 < b.len() && b[i] == b'/' && b[i + 1] == b'/' {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if i + 1 < b.len() && b[i] == b'/' && b[i + 1] == b'*' {
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(b.len());
            continue;
        }
        return i;
    }
}

/// Поиск парной скобки с учётом вложенности, строк и комментариев.
/// `i` указывает на открывающую скобку; возвращается позиция парной
/// закрывающей (или None, если файл оборван).
pub fn match_bracket(b: &[u8], i: usize, open: u8, close: u8) -> Option<usize> {
    let mut depth = 0i32;
    let mut j = i;
    while j < b.len() {
        let c = b[j];
        match c {
            b'/' if j + 1 < b.len() && b[j + 1] == b'/' => {
                while j < b.len() && b[j] != b'\n' {
                    j += 1;
                }
                continue;
            }
            b'/' if j + 1 < b.len() && b[j + 1] == b'*' => {
                j += 2;
                while j + 1 < b.len() && !(b[j] == b'*' && b[j + 1] == b'/') {
                    j += 1;
                }
                j = (j + 2).min(b.len());
                continue;
            }
            b'"' => {
                j = skip_literal(b, j, b'"');
                continue;
            }
            b'\'' => {
                j = skip_literal(b, j, b'\'');
                continue;
            }
            _ if c == open => depth += 1,
            _ if c == close => {
                depth -= 1;
                if depth == 0 {
                    return Some(j);
                }
            }
            _ => {}
        }
        j += 1;
    }
    None
}

/// Пропуск строкового или символьного литерала, начиная с кавычки в `i`.
/// Возвращает позицию ЗА закрывающей кавычкой.
fn skip_literal(b: &[u8], mut i: usize, quote: u8) -> usize {
    i += 1; // открывающая кавычка
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2, // экранированный символ — пропускаем вместе с «\»
            c if c == quote => return i + 1,
            _ => i += 1,
        }
    }
    i
}

/// Начало идентификатора: буква или «_».
pub fn is_ident_start(c: u8) -> bool {
    c == b'_' || c.is_ascii_alphabetic()
}

/// Продолжение идентификатора: буква, цифра или «_».
pub fn is_ident_char(c: u8) -> bool {
    c == b'_' || c.is_ascii_alphanumeric()
}
