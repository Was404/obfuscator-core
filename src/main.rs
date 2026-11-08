//! Точка входа проекта: бинарник `obfuscator-core`.
//!
//! Вся логика живёт в библиотечных модулях (lib.rs); main.rs лишь
//! передаёт аргументы командной строки в cli::run. Пример запуска:
//!
//!   obfuscator-core -obf demo.c

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    obfuscator_core::cli::run(&args)
}