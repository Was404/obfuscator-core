//! Бинарник `elf-inspector`: инспектор ELF из состава obfuscator-core.
//!
//! Это первый инструмент связки: читает исполняемый файл, печатает
//! его структуру и (по ключу --json) выгружает кандидатов на
//! обфускацию — функции с адресами, размерами и смещениями в файле.
//! Именно этот JSON получает обфускатор (bin/obfuscator.rs).
//!
//! Использование:
//!   elf-inspector <файл> [-n ЛИМИТ] [--json ОТЧЁТ.json]
//!   elf-inspector --help

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    obfuscator_core::inspector::run(&args)
}
