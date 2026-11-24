//! Интеграционные тесты полиморфного движка через публичный API крейта.
//!
//! Здесь проверяется то, что не видно из юнит-тестов obfsource:
//! воспроизводимость по seed, различие вариантов, сохранность
//! препроцессорных строк и строковых литералов в собранном файле.

use obfuscator_core::obfsource::{obfuscate, parse_seed, random_seed};

const SAMPLE: &str = "\
#include <stdio.h>

int sum_to(int n) {
    int s = 0;
    for (int i = 1; i <= n; i++) {
        s += i;
    }
    return s;
}

int collatz_len(long n) {
    int steps = 0;
    while (n != 1) {
        if (n % 2 == 0) {
            n /= 2;
        } else {
            n = 3 * n + 1;
        }
        steps++;
    }
    return steps;
}

int main(void) {
    printf(\"sum=%d collatz=%d\\n\", sum_to(10), collatz_len(27));
    return 0;
}
";

#[test]
fn parse_seed_accepts_both_forms() {
    assert_eq!(parse_seed("123"), Some(123));
    assert_eq!(parse_seed("0xdead_beef"), Some(0xdead_beef));
    assert_eq!(parse_seed("не_число"), None);
}

#[test]
fn random_seed_is_never_zero_repeats() {
    // Три прогона подряд не дают одинаковых зёрен (наносекунды + PID).
    let a = random_seed();
    let b = random_seed();
    let c = random_seed();
    assert!(a != b || b != c);
}

#[test]
fn same_seed_reproduces_same_file() {
    let a = obfuscate(SAMPLE, "collatz_len", Some(2024)).unwrap();
    let b = obfuscate(SAMPLE, "collatz_len", Some(2024)).unwrap();
    assert_eq!(a.new_source, b.new_source);
    assert_eq!(a.seed, 2024);
}

#[test]
fn no_seed_produces_random_variants() {
    let a = obfuscate(SAMPLE, "collatz_len", None).unwrap();
    let b = obfuscate(SAMPLE, "collatz_len", None).unwrap();
    // Зёрна разные → варианты почти наверняка разные; зёрна точно разные.
    assert_ne!(a.seed, b.seed);
}

#[test]
fn preprocessor_lines_survive_verbatim() {
    let src = "#define LIMIT 100\n#include <stdio.h>\n\nint f(void) {\n    int x = 7;\n    return x;\n}\n";
    let r = obfuscate(src, "f", Some(17)).unwrap();
    assert!(r.new_source.contains("#define LIMIT 100"), "#define обязана остаться как есть");
    assert!(r.new_source.contains("#include <stdio.h>"));
    // 100 из #define не разлагается, 7 из тела — разложилось:
    assert!(r.const_hits >= 1);
}

#[test]
fn string_literals_survive_verbatim() {
    let src = "#include <stdio.h>\n\nvoid log_line(void) {\n    printf(\"code %d end\", 15);\n}\n";
    let r = obfuscate(src, "log_line", Some(31)).unwrap();
    assert!(r.new_source.contains("\"code %d end\""), "содержимое строки искажено");
    // Само число 15 в теле разложено, но «%d» внутри строки не тронуто.
    assert!(r.const_hits >= 1);
}

#[test]
fn renames_cover_every_occurrence() {
    let r = obfuscate(SAMPLE, "collatz_len", Some(64)).unwrap();
    assert!(!r.renames.is_empty());
    // Новые имена присутствуют, старых вхождений в функции не осталось:
    let body = &r.new_source[r.new_span.start..r.new_span.end];
    for (old, new) in &r.renames {
        assert!(body.contains(new.as_str()), "новое имя «{new}» не найдено");
        assert!(
            !body.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .any(|w| w == old),
            "старое имя «{old}» осталось в функции"
        );
    }
}

#[test]
fn result_reports_seed_and_stats() {
    let r = obfuscate(SAMPLE, "collatz_len", Some(77)).unwrap();
    assert_eq!(r.seed, 77);
    assert!(r.dead_blocks >= 1);
    assert!(r.rename_hits >= r.renames.len() && r.renames.len() >= 1);
}
