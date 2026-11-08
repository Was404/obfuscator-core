//! Полный сценарий «исходник на C → ELF → обфусцированный исходник →
//! работающая программа».
//!
//! Именно здесь видна вся связка:
//!   1. компилируем demo.c — для анализа нужен исполняемый ELF;
//!   2. инспектор читает ELF и находит функции-кандидаты (имя, адрес,
//!      размер, секция) — это и есть «где расположена функция»;
//!   3. обфускатор берёт выбранную функцию, находит её определение в
//!      исходнике и создаёт новый demo_obf.c с переписанным телом;
//!   4. компилируем demo_obf.c и запускаем обе версии — вывод обязан
//!      совпасть, это и есть проверка эквивалентности.

use std::io::Write as _;
use std::process::{Command, ExitCode};

use crate::csource;
use crate::inspector::{Candidate, ElfInspector};
use crate::obfsource;

/// Компиляция исходника на C: gcc -O0, чтобы каждая функция попала в
/// ELF отдельным символом известного размера (без инлайнинга).
fn compile(src: &str, out: &str) -> Result<(), String> {
    let res = Command::new("gcc")
        .args(["-O0", "-g0", "-o", out, src])
        .output()
        .map_err(|e| format!("не удалось запустить gcc: {}", e))?;
    if !res.status.success() {
        return Err(format!(
            "gcc не смог собрать «{}»:\n{}",
            src,
            String::from_utf8_lossy(&res.stderr)
        ));
    }
    Ok(())
}

/// Запуск собранной программы: возвращает (stdout, код возврата).
fn run_program(path: &str) -> Result<(String, i32), String> {
    let res = Command::new(path)
        .output()
        .map_err(|e| format!("не удалось запустить «{}»: {}", path, e))?;
    Ok((
        String::from_utf8_lossy(&res.stdout).into_owned(),
        res.status.code().unwrap_or(-1),
    ))
}

/// Таблица кандидатов для печати: имя @ адрес, размер, секция.
fn print_candidates(title: &str, cands: &[Candidate]) {
    println!("{}", title);
    for c in cands {
        println!(
            "  {:<20} @ 0x{:x}  {:>4} байт  секция {}",
            c.name, c.addr, c.size, c.section
        );
    }
}

/// Выбор функции: явное имя (-f) или автоматом — крупнейшая функция
/// помимо main/_start (её тело интереснее всего обфусцировать).
pub fn pick_candidate<'a>(
    cands: &'a [Candidate],
    want: Option<&str>,
) -> Result<&'a Candidate, String> {
    if let Some(w) = want {
        return cands
            .iter()
            .find(|c| c.name == w)
            .ok_or_else(|| format!("функция «{}» отсутствует среди кандидатов ELF", w));
    }
    let mut best: Option<&Candidate> = None;
    for c in cands {
        if c.name == "main" || c.name == "_start" {
            continue; // входные точки не трогаем — их и так видно
        }
        if best.map_or(true, |b| c.size > b.size) {
            best = Some(c);
        }
    }
    best.ok_or_else(|| "в ELF нет подходящих функций (нет STT_FUNC с размером)".to_string())
}

/// Главная команда: obfuscator-core -obf demo.c [-f имя]
pub fn run_obf(src_path: &str, want: Option<&str>) -> ExitCode {
    println!("=== obfuscator-core: обфускация {} ===", src_path);

    // ── Шаг 0. Проверяем исходник ──
    let src = match std::fs::read_to_string(src_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Не удалось прочитать «{}»: {}", src_path, e);
            return ExitCode::FAILURE;
        }
    };
    let build_dir = match std::path::Path::new(src_path).parent() {
        Some(p) => p.join(".obf-build"),
        None => std::path::PathBuf::from(".obf-build"),
    };
    let stem = std::path::Path::new(src_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("demo")
        .to_string();
    if let Err(e) = std::fs::create_dir_all(&build_dir) {
        eprintln!("Не удалось создать каталог {}: {}", build_dir.display(), e);
        return ExitCode::FAILURE;
    }
    let orig_elf = build_dir.join(&stem).to_string_lossy().into_owned();

    // ── Шаг 1. Компилируем оригинал: анализировать нужно ELF ──
    println!("\n[1/6] Компиляция оригинала: gcc -O0 -o {} {}", orig_elf, src_path);
    if let Err(e) = compile(src_path, &orig_elf) {
        eprintln!("{}", e);
        return ExitCode::FAILURE;
    }

    // ── Шаг 2. Инспектор: читаем ELF и находим функции ──
    let bytes = match std::fs::read(&orig_elf) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Не удалось прочитать «{}»: {}", orig_elf, e);
            return ExitCode::FAILURE;
        }
    };
    let insp = match ElfInspector::parse(&orig_elf, &bytes) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("«{}» не разобрать как ELF: {}", orig_elf, e);
            return ExitCode::FAILURE;
        }
    };
    let cands = insp.candidates();
    println!("\n[2/6] Инспектор нашёл в {} функции-кандидаты:", orig_elf);
    print_candidates("  (имя            @ адрес          размер   секция)", &cands);

    // ── Шаг 3. Выбор функции: из ELF и с проверкой по исходнику ──
    let chosen = match pick_candidate(&cands, want) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Ошибка выбора функции: {}", e);
            return ExitCode::FAILURE;
        }
    };
    let span = match csource::find_function(&src, &chosen.name) {
        Some(s) => s,
        None => {
            eprintln!(
                "Функция «{}» есть в ELF (0x{:x}, {} байт), но её определения нет в «{}».",
                chosen.name, chosen.addr, chosen.size, src_path
            );
            eprintln!("Определения в исходнике: {:?}", csource::list_functions(&src)
                .iter().map(|f| f.name.clone()).collect::<Vec<_>>());
            return ExitCode::FAILURE;
        }
    };
    println!(
        "\n[3/6] Выбрана функция «{}»: адрес 0x{:x}, {} байт, секция {}; \
         в исходнике — строка {}",
        chosen.name,
        chosen.addr,
        chosen.size,
        chosen.section,
        csource::line_of(&src, span.start)
    );

    // ── Шаг 4. Обфускатор: новый исходник с переписанной функцией ──
    let result = match obfsource::obfuscate(&src, &chosen.name) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Обфускация не удалась: {}", e);
            return ExitCode::FAILURE;
        }
    };
    let obf_path = format!("{}_obf.c", src_path.trim_end_matches(".c"));
    if let Err(e) = std::fs::write(&obf_path, &result.new_source) {
        eprintln!("Не удалось записать «{}»: {}", obf_path, e);
        return ExitCode::FAILURE;
    }
    println!("\n[4/6] Обфускатор создал «{}»:", obf_path);
    println!("  переименований переменных: {} (вхождений: {})", result.renames.len(), result.rename_hits);
    for (old, new) in &result.renames {
        println!("    {} → {}", old, new);
    }
    println!("  литералов разложено: {}", result.const_hits);
    println!("  мёртвых блоков вставлено: {}", result.dead_blocks);

    // ── Шаг 5. Компилируем и запускаем обе версии ──
    let obf_elf = build_dir.join(format!("{}_obf", stem)).to_string_lossy().into_owned();
    println!("\n[5/6] Компиляция обфусцированной версии: {} → {}", obf_path, obf_elf);
    if let Err(e) = compile(&obf_path, &obf_elf) {
        eprintln!("{}", e);
        return ExitCode::FAILURE;
    }
    let (out_o, code_o) = match run_program(&orig_elf) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}", e);
            return ExitCode::FAILURE;
        }
    };
    let (out_b, code_b) = match run_program(&obf_elf) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}", e);
            return ExitCode::FAILURE;
        }
    };
    println!("  оригинал     (код {}): {}", code_o, out_o.trim_end());
    println!("  обфусцирован (код {}): {}", code_b, out_b.trim_end());
    let same = out_o == out_b && code_o == code_b;

    // ── Шаг 6. ELF после обфускации: функция всё та же, но выросла ──
    println!("\n[6/6] Инспектор по обфусцированной версии:");
    if let Ok(nb) = std::fs::read(&obf_elf) {
        if let Ok(ni) = ElfInspector::parse(&obf_elf, &nb) {
            if let Some(c) = ni.candidates().into_iter().find(|c| c.name == chosen.name) {
                println!(
                    "  функция «{}»: было {} байт по адресу 0x{:x}, стало {} байт по адресу 0x{:x}",
                    c.name, chosen.size, chosen.addr, c.size, c.addr
                );
            }
        }
    }

    if same {
        println!("\nИтог: поведение совпало — обфускация эквивалентна. Файл с обфусцированным исходником: {}", obf_path);
        ExitCode::SUCCESS
    } else {
        eprintln!("\nИтог: вывод различается — обфускация испортила программу!");
        ExitCode::FAILURE
    }
}

/// Вспомогательная команда: obfuscator-core inspect demo.c —
/// полная печать ELF скомпилированной программы.
pub fn run_inspect(src_path: &str) -> ExitCode {
    let src = match std::fs::read_to_string(src_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Не удалось прочитать «{}»: {}", src_path, e);
            return ExitCode::FAILURE;
        }
    };
    let build_dir = std::path::Path::new(src_path)
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join(".obf-build");
    let stem = std::path::Path::new(src_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("demo")
        .to_string();
    if let Err(e) = std::fs::create_dir_all(&build_dir) {
        eprintln!("Не удалось создать каталог {}: {}", build_dir.display(), e);
        return ExitCode::FAILURE;
    }
    let elf = build_dir.join(&stem).to_string_lossy().into_owned();
    println!("Компиляция {} → {} (для инспектора нужен ELF)", src_path, elf);
    if let Err(e) = compile(src_path, &elf) {
        eprintln!("{}", e);
        return ExitCode::FAILURE;
    }
    let _ = src; // исходник нужен только для проверки существования
    let bytes = match std::fs::read(&elf) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Не удалось прочитать «{}»: {}", elf, e);
            return ExitCode::FAILURE;
        }
    };
    match ElfInspector::parse(&elf, &bytes) {
        Ok(insp) => {
            let stdout = std::io::stdout();
            let mut out = std::io::BufWriter::new(stdout.lock());
            match insp.report(&mut out, 0) {
                Ok(()) => {
                    let _ = out.flush();
                    let cands = insp.candidates();
                    print_candidates("\nКандидаты на обфускацию:", &cands);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("Ошибка при выводе отчёта: {}", e);
                    ExitCode::FAILURE
                }
            }
        }
        Err(e) => {
            eprintln!("«{}» не разобрать как ELF: {}", elf, e);
            ExitCode::FAILURE
        }
    }
}
