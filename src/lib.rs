//! Библиотека проекта obfuscator-core.
//!
//! Модули:
//!   dicts     — расшифровка числовых констант формата ELF;
//!   inspector — разбор ELF (goblin), отчёт, кандидаты на обфускацию;
//!   csource   — поиск определений функций в исходнике на C;
//!   obfsource — переписывание одной функции эквивалентным кодом;
//!   pipeline  — полный сценарий «C-файл → ELF → новый C-файл → запуск»;
//!   cli       — разбор аргументов командной строки.
//!
//! Бинарники (все — тонкие обёртки над этой библиотекой):
//!   obfuscator-core (src/main.rs) — полный конвейер;
//!   bin/elf-inspector.rs — инспектор: отчёт по ELF + выгрузка JSON;
//!   bin/obfuscator.rs    — обфускатор: C-файл + JSON инспектора → новый C;
//!   bin/cli.rs           — альтернативная точка входа полного конвейера.

pub mod cli;
pub mod csource;
pub mod dicts;
pub mod inspector;
pub mod obfsource;
pub mod pipeline;
