//! Консольный интерфейс проекта obfuscator-core.
//!
//! Пользователь пишет:
//!   obfuscator-core -obf demo.c          — обфускация функции в C-файле
//!   obfuscator-core -obf /bin/ls         — байтовая обфускация готового ELF
//!   obfuscator-core -obf demo.c -f gcd   — та же, но функцию выбирает он сам
//!   obfuscator-core -obf demo.c -s 42    — воспроизводимый вариант обфускации
//!   obfuscator-core inspect demo.c       — полный отчёт инспектора (C → ELF)
//!   obfuscator-core inspect /bin/ls      — отчёт по готовому ELF
//!   obfuscator-core --help
//!
//! Тип входного файла определяется автоматически по ELF-магии (см.
//! inspector::is_elf). Разбор аргументов живёт здесь (библиотечный
//! модуль), а бинарники src/main.rs и src/bin/cli.rs — лишь тонкие
//! обёртки над cli::run.

use std::process::ExitCode;

use crate::inspector;
use crate::obfsource;
use crate::pipeline;

fn print_help() {
    println!("obfuscator-core — связка «инспектор ELF + обфускатор».");
    println!();
    println!("Тип входного файла определяется автоматически по ELF-магии:");
    println!("  C-исходник: demo.c компилируется, инспектор находит в ELF");
    println!("  функции (имя, адрес, размер, секция), обфускатор создаёт новый");
    println!("  исходник с переписанной функцией, компилирует его и запускает");
    println!("  обе версии — вывод обязан совпасть;");
    println!("  готовый ELF: инспектор читает файл как есть и передаёт");
    println!("  обфускатору карту функций, обфускатор заполняет code caves");
    println!("  (свободное место исполняемых секций), обезличивает .comment,");
    println!("  заполняет межсекционные гэпы, добавляет junk-секцию —");
    println!("  и сразу запускает обе версии");
    println!("  (например: obfuscator-core -obf /bin/ls).");
    println!();
    println!("Использование:");
    println!("  obfuscator-core -obf <файл.c | файл ELF> [-f имя_функции] [-s зерно]");
    println!("      полиморфно обфусцировать и запустить обе версии; без -f");
    println!("      функция выбирается автоматически (крупнейшая, помимо");
    println!("      main/_start у C-файла, у ELF — якорь отчёта); без -s зерно");
    println!("      берётся из системных часов, поэтому каждый запуск даёт НОВЫЙ");
    println!("      вариант кода с тем же поведением (полиморфизм);");
    println!("      одинаковый -s — одинаковый вариант (воспроизводимость)");
    println!("  obfuscator-core inspect <файл.c | файл ELF>");
    println!("      полный отчёт инспектора (C-файл сначала компилируется)");
    println!("  obfuscator-core --help");
    println!();
    println!("Артефакты: для C — <файл>_obf.c (обфусцированный исходник); для");
    println!("ELF — <имя>_obf в каталоге .obf-build/ рядом с файлом (или в");
    println!("текущем каталоге, если рядом записать нельзя).");
}

/// Точка входа всех «говорящих» бинарников проекта.
pub fn run(args: &[String]) -> ExitCode {
    // Шаг 1: без аргументов или --help — справка.
    if args.len() == 1 || args.iter().any(|a| a == "-h" || a == "--help") {
        print_help();
        return if args.len() == 1 { ExitCode::FAILURE } else { ExitCode::SUCCESS };
    }

    // Шаг 2: разбор команды.
    let mut cmd: Option<String> = None; // «-obf» или «inspect»
    let mut src: Option<String> = None; // путь к исходнику
    let mut func: Option<String> = None; // имя функции (-f)
    let mut seed: Option<u64> = None; // зерно ГПСЧ (-s)
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-obf" | "--obf" | "obf" => cmd = Some("-obf".into()),
            "inspect" => cmd = Some("inspect".into()),
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
            "-s" | "--seed" => {
                i += 1;
                match args.get(i).and_then(|s| obfsource::parse_seed(s)) {
                    Some(v) => seed = Some(v),
                    None => {
                        eprintln!(
                            "Ошибка: после ключа «{}» нужно указать зерно (десятичное или 0x…).",
                            args[i - 1]
                        );
                        return ExitCode::FAILURE;
                    }
                }
            }
            other => {
                if src.is_some() {
                    eprintln!("Ошибка: лишний аргумент «{}».", other);
                    return ExitCode::FAILURE;
                }
                src = Some(other.to_string());
            }
        }
        i += 1;
    }
    let Some(src) = src else {
        eprintln!("Ошибка: не указан файл (C-исходник или готовый ELF).");
        eprintln!("Использование: obfuscator-core -obf <файл> [-f имя] [-s зерно]");
        return ExitCode::FAILURE;
    };

    // Шаг 3: запуск сценария. Для -obf тип файла выбирает конвейер:
    // ELF-магия → байтовая обфускация, иначе — C-исходник.
    match cmd.as_deref() {
        Some("-obf") => {
            if inspector::is_elf(&src) {
                pipeline::run_obf_elf(&src, func.as_deref(), seed)
            } else {
                pipeline::run_obf(&src, func.as_deref(), seed)
            }
        }
        Some("inspect") => {
            if func.is_some() {
                eprintln!("Предупреждение: ключ -f при команде inspect игнорируется.");
            }
            pipeline::run_inspect(&src)
        }
        _ => {
            eprintln!("Ошибка: не указана команда (-obf или inspect).");
            eprintln!("Использование: obfuscator-core -obf <файл> [-f имя] [-s зерно]");
            ExitCode::FAILURE
        }
    }
}