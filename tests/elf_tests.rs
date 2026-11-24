//! Тесты байтовой обфускации готовых ELF-файлов (obfelf + run_obf_elf).
//!
//! Гарантии, которые проверяем:
//!   1. обфусцированный ELF запускается и ведёт себя как оригинал;
//!   2. одинаковый seed → побайтово одинаковый результат, разные seed —
//!      разные файлы (полиморфизм);
//!   3. байты функций из карты кандидатов не меняются ни при каком seed;
//!   4. файл остаётся валидным ELF: инспектор разбирает вариант, секция
//!      junk-секции видна в таблице, число кандидатов не меняется.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use obfuscator_core::inspector::ElfInspector;
use obfuscator_core::obfelf;

const SAMPLE: &str = "\
#include <stdio.h>

static long fib(int n) {
    long a = 0, b = 1;
    for (int i = 0; i < n; i++) {
        long t = a + b;
        a = b;
        b = t;
    }
    return a;
}

int main(void) {
    printf(\"fib(20)=%ld\\n\", fib(20));
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

/// Собрать SAMPLE в tmp_dir/prog и вернуть путь к ELF.
fn build_sample(tmp_dir: &PathBuf) -> Result<PathBuf, String> {
    let dir = tmp_dir.join("elf_obf_tests");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let cfile = dir.join("prog.c");
    fs::write(&cfile, SAMPLE).map_err(|e| e.to_string())?;
    let elf = dir.join("prog");
    let out = Command::new("gcc")
        .args(["-O0", "-g0", "-o"])
        .arg(&elf)
        .arg(&cfile)
        .output()
        .map_err(|e| format!("gcc не запустился: {e}"))?;
    if out.status.success() {
        Ok(elf)
    } else {
        Err(format!(
            "gcc не собрал prog: {}",
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
fn obfelf_rejects_non_elf() {
    assert!(obfelf::obfuscate(vec![1, 2, 3, 4], &[], Some(1)).is_err());
    assert!(obfelf::obfuscate(Vec::new(), &[], Some(1)).is_err());
}

#[test]
fn elf_pipeline_equivalent_and_structurally_valid() {
    if !gcc_available() {
        eprintln!("gcc недоступен — ELF-тесты пропущены");
        return;
    }
    let base = std::env::temp_dir().join("obf_elf_pipeline");
    let _ = fs::remove_dir_all(&base);
    let elf_path = build_sample(&base).expect("сборка образца");
    let orig = fs::read(&elf_path).expect("чтение ELF");

    // Инспектор: карта функций.
    let insp = ElfInspector::parse(&elf_path.to_string_lossy(), &orig).expect("разбор ELF");
    let cands = insp.candidates();
    let sections_before = insp.section_count();

    // Обфускация и запись с правами оригинала.
    let result = obfelf::obfuscate(orig.clone(), &cands, Some(777)).expect("обфускация");
    let obf_path = elf_path.parent().unwrap().join("prog_obf");
    fs::write(&obf_path, &result.new_bytes).expect("запись варианта");
    #[cfg(unix)]
    fs::set_permissions(&obf_path, fs::metadata(&elf_path).unwrap().permissions())
        .expect("права");

    // Байты функций-кандидатов не изменились.
    for c in &cands {
        let a = c.file_offset as usize;
        let b = a + c.size as usize;
        assert_eq!(
            orig[a..b],
            result.new_bytes[a..b],
            "байты функции «{}» изменены",
            c.name
        );
    }

    // Файл остаётся валидным ELF: секций на одну больше (junk-секция),
    // кандидатов столько же, e_shnum в заголовке увеличился.
    let obf_bytes = fs::read(&obf_path).expect("чтение варианта");
    let insp2 = ElfInspector::parse(&obf_path.to_string_lossy(), &obf_bytes)
        .expect("вариант должен разбираться как ELF");
    assert_eq!(
        insp2.section_count(),
        sections_before + 1,
        "junk-секция должна появиться в таблице секций"
    );
    assert_eq!(insp2.candidates().len(), cands.len(), "карта функций не изменилась");
    assert!(result.junk_section.is_some(), "у собранного gcc файла junk-секция ожидаема");
    let shnum = u16::from_le_bytes([obf_bytes[60], obf_bytes[61]]) as usize;
    assert_eq!(shnum, sections_before + 1, "e_shnum должен вырасти на 1");

    // Поведение совпало.
    let (out_o, code_o) = run(&elf_path);
    let (out_b, code_b) = run(&obf_path);
    assert_eq!(code_o, 0, "оригинал должен отработать успешно");
    assert_eq!((out_o, code_o), (out_b, code_b), "поведение изменилось");

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn elf_obfuscate_is_polymorphic_and_reproducible() {
    if !gcc_available() {
        eprintln!("gcc недоступен — ELF-тесты пропущены");
        return;
    }
    let base = std::env::temp_dir().join("obf_elf_poly");
    let _ = fs::remove_dir_all(&base);
    let elf_path = build_sample(&base).expect("сборка образца");
    let orig = fs::read(&elf_path).expect("чтение ELF");
    let cands = ElfInspector::parse(&elf_path.to_string_lossy(), &orig)
        .expect("разбор ELF")
        .candidates();

    let a = obfelf::obfuscate(orig.clone(), &cands, Some(777)).unwrap();
    let b = obfelf::obfuscate(orig.clone(), &cands, Some(777)).unwrap();
    assert_eq!(a.new_bytes, b.new_bytes, "одинаковый seed — одинаковый файл");
    assert_eq!(a.seed, 777);

    let variants: Vec<Vec<u8>> = (1u64..=5)
        .map(|s| obfelf::obfuscate(orig.clone(), &cands, Some(s)).unwrap().new_bytes)
        .collect();
    for i in 0..variants.len() {
        for j in i + 1..variants.len() {
            assert_ne!(variants[i], variants[j], "разные seed — разные файлы");
        }
    }

    let _ = fs::remove_dir_all(&base);
}
