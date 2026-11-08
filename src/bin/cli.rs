//! Альтернативная точка входа: бинарник `cli`.
//!
//! Делает ровно то же, что и основной бинарник `obfuscator-core`
//! (src/main.rs): оба вызывают библиотечный obfuscator_core::cli::run.
//! Файл существует, чтобы запускать конвейер было удобно и короткой
//! командой: `cli -obf demo.c`.

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    obfuscator_core::cli::run(&args)
}
