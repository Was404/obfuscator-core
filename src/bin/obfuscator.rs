//! Бинарник `obfuscator`: обфускатор исходника из состава obfuscator-core.
//!
//! Второй инструмент связки. Получает:
//!   1. исходник на C (например, demo.c);
//!   2. JSON инспектора с описанием функций ELF (имя, адрес, размер,
//!      секция, смещение в файле) — «где расположена функция».
//! Выбирает функцию (ключом -f или автоматически), находит её
//! определение в исходнике и создаёт новый файл с переписанным телом:
//! переименованные переменные, разложенные литералы, мёртвый код.
//!
//! Использование:
//!   obfuscator <файл.c> <кандидаты.json> [-o выход.c] [-f имя_функции]

use std::process::ExitCode;

use obfuscator_core::{csource, inspector, obfsource, pipeline};

fn print_usage() {
    eprintln!("Использование: obfuscator <файл.c> <кандидаты.json> [-o выход.c] [-f имя]");
    eprintln!("Подробнее: obfuscator --help");
}

fn print_help() {
    println!("Обфускатор исходника на C по данным инспектора ELF.");
    println!();
    println!("Использование:");
    println!("  obfuscator <файл.c> <кандидаты.json> [-o выход.c] [-f имя_функции]");
    println!();
    println!("Ключи:");
    println!("  -o, --out F   куда записать новый исходник (по умолчанию <файл>_obf.c)");
    println!("  -f, --func N  какую функцию обфусцировать (по умолчанию — крупнейшая");
    println!("                из кандидатов помимо main/_start, найденная в исходнике)");
    println!("  -h, --help    эта справка");
    println!();
    println!("JSON кандидатов создаёт elf-inspector: elf-inspector prog --json info.json");
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 && (args[1] == "-h" || args[1] == "--help") {
        print_help();
        return ExitCode::SUCCESS;
    }

    // ── Шаг 1. Аргументы: <файл.c> <json> [-o F] [-f N] ──
    let mut cfile: Option<String> = None;
    let mut jfile: Option<String> = None;
    let mut out: Option<String> = None;
    let mut func: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--out" => {
                i += 1;
                match args.get(i) {
                    Some(p) => out = Some(p.clone()),
                    None => {
                        eprintln!("Ошибка: после ключа «{}» нужно указать файл.", args[i - 1]);
                        return ExitCode::FAILURE;
                    }
                }
            }
            "-f" | "--func" => {
                i += 1;
                match args.get(i) {
                    Some(f) => func = Some(f.clone()),
                    None => {
                        eprintln!("Ошибка: после ключа «{}» нужно указать имя функции.", args[i - 1]);
                        return ExitCode::FAILURE;
                    }
                }
            }
            other => {
                if cfile.is_none() {
                    cfile = Some(other.to_string());
                } else if jfile.is_none() {
                    jfile = Some(other.to_string());
                } else {
                    eprintln!("Ошибка: лишний аргумент «{}».", other);
                    print_usage();
                    return ExitCode::FAILURE;
                }
            }
        }
        i += 1;
    }
    let (Some(cfile), Some(jfile)) = (cfile, jfile) else {
        print_usage();
        return ExitCode::FAILURE;
    };

    // ── Шаг 2. Читаем исходник и JSON инспектора ──
    let src = match std::fs::read_to_string(&cfile) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Не удалось прочитать «{}»: {}", cfile, e);
            return ExitCode::FAILURE;
        }
    };
    let jtext = match std::fs::read_to_string(&jfile) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Не удалось прочитать «{}»: {}", jfile, e);
            return ExitCode::FAILURE;
        }
    };
    let info = match inspector::parse_candidates(&jtext) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Ошибка разбора «{}»: {}", jfile, e);
            return ExitCode::FAILURE;
        }
    };

    // ── Шаг 3. Выбор функции: из ELF, с проверкой по исходнику ──
    let chosen = match pipeline::pick_candidate(&info.functions, func.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Ошибка выбора функции: {}", e);
            return ExitCode::FAILURE;
        }
    };
    let Some(span) = csource::find_function(&src, &chosen.name) else {
        eprintln!(
            "Функция «{}» есть в ELF «{}» (0x{:x}, {} байт), но не найдена в «{}».",
            chosen.name, info.file, chosen.addr, chosen.size, cfile
        );
        return ExitCode::FAILURE;
    };
    println!(
        "Функция «{}» из ELF {}: адрес 0x{:x}, {} байт, секция {}; в исходнике — строка {}",
        chosen.name,
        info.file,
        chosen.addr,
        chosen.size,
        chosen.section,
        csource::line_of(&src, span.start)
    );

    // ── Шаг 4. Обфускация и запись нового исходника ──
    let result = match obfsource::obfuscate(&src, &chosen.name) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Обфускация не удалась: {}", e);
            return ExitCode::FAILURE;
        }
    };
    let out_path = out.unwrap_or_else(|| format!("{}_obf.c", cfile.trim_end_matches(".c")));
    if let Err(e) = std::fs::write(&out_path, &result.new_source) {
        eprintln!("Не удалось записать «{}»: {}", out_path, e);
        return ExitCode::FAILURE;
    }
    println!(
        "Переименований: {} ({} вхождений), литералов разложено: {}, мёртвых блоков: {}",
        result.renames.len(),
        result.rename_hits,
        result.const_hits,
        result.dead_blocks
    );
    for (old, new) in &result.renames {
        println!("  {} → {}", old, new);
    }
    println!("Новый исходник записан: {}", out_path);
    ExitCode::SUCCESS
}
