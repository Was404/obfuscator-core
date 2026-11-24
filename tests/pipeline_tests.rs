//! Стресс-тест эквивалентности: полиморфная обфускация не должна менять
//! поведение программы ни на одном зерне.
//!
//! Для каждого seed: обфусцируем collatz_len, компилируем оригинал и
//! вариант gcc -O0, запускаем оба бинарника и сравниваем stdout и код
//! возврата. 30 прогонов: 15 фиксированных зёрен + 15 случайных.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use obfuscator_core::obfsource::{obfuscate, random_seed};

const SAMPLE: &str = "\
#include <stdio.h>

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
    printf(\"collatz_len(27)=%d\\n\", collatz_len(27));
    return 0;
}
";

/// Есть ли gcc в системе (на машине без компилятора тест пропускается).
fn gcc_available() -> bool {
    Command::new("gcc")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// gcc -O0 -o dir/name dir/name.c
fn compile(dir: &PathBuf, name: &str) -> Result<(), String> {
    let out = Command::new("gcc")
        .args(["-O0", "-o"])
        .arg(dir.join(name))
        .arg(dir.join(format!("{name}.c")))
        .output()
        .map_err(|e| format!("gcc не запустился: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "gcc не собрал {name}: {}",
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

/// Запуск бинарника: (stdout, код возврата).
fn run(bin: &PathBuf) -> (String, i32) {
    let Output { stdout, status, .. } = Command::new(bin).output().expect("запуск бинарника");
    (
        String::from_utf8_lossy(&stdout).into_owned(),
        status.code().unwrap_or(-1),
    )
}

#[test]
fn stress_30_runs_equivalent() {
    if !gcc_available() {
        eprintln!("gcc недоступен — стресс-тест пропущен");
        return;
    }
    let base = std::env::temp_dir().join("obf_stress_tests");
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).expect("временный каталог");

    let mut checked = 0usize;
    let mut failures: Vec<String> = Vec::new();

    let seeds: Vec<u64> = (1..=15u64)
        .chain((0..15).map(|_| random_seed()))
        .collect();
    assert_eq!(seeds.len(), 30);

    for (i, seed) in seeds.iter().enumerate() {
        let dir = base.join(format!("run{i}"));
        fs::create_dir_all(&dir).expect("каталог прогона");

        fs::write(dir.join("orig.c"), SAMPLE).expect("запись orig.c");
        let r = match obfuscate(SAMPLE, "collatz_len", Some(*seed)) {
            Ok(r) => r,
            Err(e) => {
                failures.push(format!("seed={seed}: обфускация не удалась: {e}"));
                continue;
            }
        };
        fs::write(dir.join("obf.c"), &r.new_source).expect("запись obf.c");

        if let Err(e) = compile(&dir, "orig") {
            failures.push(format!("seed={seed}: {e}"));
            continue;
        }
        if let Err(e) = compile(&dir, "obf") {
            failures.push(format!("seed={seed}: обфусцированный вариант не собирается: {e}"));
            continue;
        }
        let (out_o, code_o) = run(&dir.join("orig"));
        let (out_b, code_b) = run(&dir.join("obf"));
        if out_o != out_b || code_o != code_b {
            failures.push(format!(
                "seed={seed}: поведение различается ({out_o:?}/{code_o} vs {out_b:?}/{code_b})"
            ));
            continue;
        }
        checked += 1;
        let _ = fs::remove_dir_all(&dir);
    }

    let _ = fs::remove_dir_all(&base);
    assert!(
        failures.is_empty(),
        "прогонов без сбоя: {} из 30\n{}",
        checked,
        failures.join("\n")
    );
    assert_eq!(checked, 30, "все 30 прогонов обязаны пройти");
}
