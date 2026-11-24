//! Библиотека проекта obfuscator-core.
//!
//! Модули:
//!   dicts     — расшифровка числовых констант формата ELF;
//!   inspector — разбор ELF (goblin), отчёт, кандидаты на обфускацию;
//!   csource   — поиск определений функций в исходнике на C;
//!   obfsource — переписывание одной функции эквивалентным кодом;
//!   obfelf    — байтовая обфускация готового ELF (code caves, .comment,
//!               паддинг заголовков, межсекционные гэпы, junk-секция);
//!   pipeline  — сценарии «C-файл → ELF → новый C → запуск» и
//!               «готовый ELF → обфусцированный ELF → запуск»;
//!   cli       — разбор аргументов командной строки.
//!
//! Бинарники (все — тонкие обёртки над этой библиотекой):
//!   obfuscator-core (src/main.rs) — полный конвейер (C или ELF);
//!   bin/elf-inspector.rs — инспектор: отчёт по ELF + выгрузка JSON;
//!   bin/obfuscator.rs    — обфускатор: C-файл + JSON инспектора → новый C;
//!   bin/cli.rs           — альтернативная точка входа полного конвейера.

pub mod cli;
pub mod csource;
pub mod dicts;
pub mod inspector;
pub mod obfelf;
pub mod obfsource;
pub mod pipeline;
