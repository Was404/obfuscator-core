//! Консольный интерфейс проекта obfuscator-core.
//!
//! Пользователь пишет:
//!   obfuscator-core -obf demo.c          — полная обфускация с проверкой
//!   obfuscator-core -obf demo.c -f gcd   — та же, но функцию выбирает он сам
//!   obfuscator-core inspect demo.c       — полный отчёт инспектора по ELF
//!   obfuscator-core --help
//!
//! Разбор аргументов живёт здесь (библиотечный модуль), а бинарники
//! src/main.rs и src/bin/cli.rs — лишь тонкие обёртки над cli::run.

use std::process::ExitCode;

use crate::pipeline;

fn print_help() {
    println!("obfuscator-core — связка «инспектор ELF + обфускатор исходника».");
    println!();
    println!("Как это работает: demo.c компилируется, инспектор находит в ELF");
    println!("функции (имя, адрес, размер, секция), обфускатор создаёт новый");
    println!("исходник с переписанной функцией, компилирует его и запускает");
    println!("обе версии — вывод обязан совпасть.");
    println!();
    println!("Использование:");
    println!("  obfuscator-core -obf <файл.c> [-f имя_функции]");
    println!("      обфусцировать одну функцию и запустить обе версии;");
    println!("      без -f функция выбирается автоматически (крупнейшая");
    println!("      помимо main/_start)");
    println!("  obfuscator-core inspect <файл.c>");
    println!("      скомпилировать файл и показать полный отчёт инспектора");
    println!("  obfuscator-core --help");
    println!();
    println!("Артефакты: <файл>_obf.c (обфусцированный исходник) и каталог");
    println!(".obf-build/ рядом с исходником (ELF до и после).");
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
        eprintln!("Ошибка: не указан файл с исходником на C.");
        eprintln!("Использование: obfuscator-core -obf <файл.c> [-f имя]");
        return ExitCode::FAILURE;
    };

    // Шаг 3: запуск сценария.
    match cmd.as_deref() {
        Some("-obf") => pipeline::run_obf(&src, func.as_deref()),
        Some("inspect") => {
            if func.is_some() {
                eprintln!("Предупреждение: ключ -f при команде inspect игнорируется.");
            }
            pipeline::run_inspect(&src)
        }
        _ => {
            eprintln!("Ошибка: не указана команда (-obf или inspect).");
            eprintln!("Использование: obfuscator-core -obf <файл.c> [-f имя]");
            ExitCode::FAILURE
        }
    }
}
