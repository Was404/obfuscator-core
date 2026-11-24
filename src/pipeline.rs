//! Полные сценарии обфускации с проверкой эквивалентности запуском.
//!
//! Сценарий A — вход C-исходник (run_obf):
//!   1. компилируем demo.c — для анализа нужен исполняемый ELF;
//!   2. инспектор читает ELF и находит функции-кандидаты (имя, адрес,
//!      размер, секция) — это и есть «где расположена функция»;
//!   3. обфускатор берёт выбранную функцию, находит её определение в
//!      исходнике и создаёт новый demo_obf.c с переписанным телом;
//!   4. компилируем demo_obf.c и запускаем обе версии — вывод обязан
//!      совпасть, это и есть проверка эквивалентности.
//!
//! Сценарий B — вход готовый ELF (run_obf_elf), например /bin/ls:
//!   1. инспектор читает файл как есть и строит карту функций;
//!   2. байтовый обфускатор (obfelf) заполняет code caves, обезличивает
//!      .comment, перезаписывает паддинг заголовка, заполняет
//!      межсекционные гэпы и добавляет junk-секцию; байты функций из
//!      карты не трогаются;
//!   3. результат записывается в .obf-build/, обе версии запускаются —
//!      вывод обязан совпасть.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use crate::csource;
use crate::inspector::{self, Candidate, ElfInspector};
use crate::obfelf;
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

/// Каталог сборки: рядом с входным файлом (.obf-build/), а если тот
/// недоступен для записи (например, /bin для /bin/ls) — в текущем
/// каталоге.
fn ensure_build_dir(src_path: &str) -> (PathBuf, bool) {
    let primary = Path::new(src_path)
        .parent()
        .unwrap_or(Path::new("."))
        .join(".obf-build");
    if std::fs::create_dir_all(&primary).is_ok() {
        return (primary, true);
    }
    let fallback = PathBuf::from(".obf-build");
    if let Err(e) = std::fs::create_dir_all(&fallback) {
        eprintln!("Не удалось создать каталог {}: {}", fallback.display(), e);
    }
    (fallback, false)
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

/// Главная команда: obfuscator-core -obf demo.c [-f имя] [-s зерно]
///
/// `seed` — зерно ГПСЧ обфускации: None → случайное (новый вариант
/// при каждом запуске), Some(n) → воспроизводимый вариант.
pub fn run_obf(src_path: &str, want: Option<&str>, seed: Option<u64>) -> ExitCode {
    println!("=== obfuscator-core: полиморфная обфускация {} ===", src_path);

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
    let result = match obfsource::obfuscate(&src, &chosen.name, seed) {
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
    println!(
        "  зерно (seed): {} (0x{:016x}) — тот же seed даёт тот же файл, другой seed даёт другой вариант",
        result.seed, result.seed
    );
    println!("  переименований переменных: {} (вхождений: {})", result.renames.len(), result.rename_hits);
    for (old, new) in &result.renames {
        println!("    {} → {}", old, new);
    }
    println!("  литералов разложено: {}", result.const_hits);
    println!("  мёртвых блоков вставлено: {}", result.dead_blocks);
    println!("  безвредных блоков под истинным предикатом: {}", result.opaque_blocks);
    println!("  мусорных комментариев: {}", result.junk_comments);

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

/// Команда для готовых бинарников: obfuscator-core -obf /bin/ls [-f имя] [-s зерно]
///
/// Инспектор читает ELF как есть и передаёт обфускатору карту функций
/// (кандидаты); байтовый обфускатор обфусцирует всё вне функций и сразу
/// запускает обе версии — оригинал и вариант. `want` (-f) выбирает
/// функцию-якорь отчёта; `seed` — как в run_obf (None → новый вариант).
pub fn run_obf_elf(src_path: &str, want: Option<&str>, seed: Option<u64>) -> ExitCode {
    println!("=== obfuscator-core: байтовая обфускация ELF {} ===", src_path);

    // ── Шаг 1. Инспектор читает ELF и строит карту функций ──
    let bytes = match std::fs::read(src_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Не удалось прочитать «{}»: {}", src_path, e);
            return ExitCode::FAILURE;
        }
    };
    let insp = match ElfInspector::parse(src_path, &bytes) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("«{}» не разобрать как ELF: {}", src_path, e);
            return ExitCode::FAILURE;
        }
    };
    let cands = insp.candidates();
    let orig_sections = insp.section_count();
    let orig_size = bytes.len();
    println!("\n[1/6] Инспектор нашёл в {} функции-кандидаты: {}", src_path,
             if cands.is_empty() { "список пуст (stripped-файл без символов)".to_string() }
             else { format!("{} шт.", cands.len()) });
    print_candidates("  (имя            @ адрес          размер   секция)", &cands);

    // ── Шаг 2. Функция-якорь: самые крупные байты кода остаются нетронутыми ──
    let anchor = match want {
        Some(w) => match cands.iter().find(|c| c.name == w) {
            Some(c) => Some(c.clone()),
            None => {
                eprintln!("Ошибка выбора функции: функция «{}» отсутствует среди кандидатов ELF", w);
                return ExitCode::FAILURE;
            }
        },
        None => cands.iter().max_by_key(|c| c.size).cloned(),
    };
    match &anchor {
        Some(a) => println!(
            "\n[2/6] Якорь — функция «{}» (0x{:x}, {} байт, секция {}); \
             байты всех функций-кандидатов не трогаются",
            a.name, a.addr, a.size, a.section
        ),
        None => println!(
            "\n[2/6] Кандидатов-функций нет — обфусцируются только служебные \
             области файла (паддинг, .comment, гэпы)"
        ),
    }

    // ── Шаг 3. Байтовый обфускатор: инспектор передал карту, обфусцируем ──
    let result = match obfelf::obfuscate(bytes, &cands, seed) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Обфускация не удалась: {}", e);
            return ExitCode::FAILURE;
        }
    };
    println!("\n[3/6] Обфускатор переписал байты:");
    println!(
        "  зерно (seed): {} (0x{:016x}) — тот же seed даёт тот же файл, другой seed даёт другой вариант",
        result.seed, result.seed
    );
    println!(
        "  code caves заполнено: {} ({} байт) — свободное место исполняемых секций",
        result.caves, result.cave_bytes
    );
    if result.comment_bytes > 0 {
        println!("  .comment обезличен: {} байт", result.comment_bytes);
    }
    println!("  межсекционных гэпов заполнено: {} байт", result.gap_bytes);
    match &result.junk_section {
        Some((off, sz)) => println!("  добавлена junk-секция: {} байт по смещению 0x{:x}", sz, off),
        None => println!("  junk-секция не добавлена (нестандартная раскладка файла)"),
    }

    // ── Шаг 4. Записываем вариант с правами оригинала ──
    let (build_dir, _fell_back) = ensure_build_dir(src_path);
    let stem = Path::new(src_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("prog")
        .to_string();
    let obf_path = build_dir.join(format!("{}_obf", stem));
    if let Err(e) = std::fs::write(&obf_path, &result.new_bytes) {
        eprintln!("Не удалось записать «{}»: {}", obf_path.display(), e);
        return ExitCode::FAILURE;
    }
    #[cfg(unix)]
    if let Ok(md) = std::fs::metadata(src_path) {
        let _ = std::fs::set_permissions(&obf_path, md.permissions());
    }
    println!("\n[4/6] Обфусцированный ELF записан: {}", obf_path.display());

    // ── Шаг 5. Запускаем обе версии — вывод обязан совпасть ──
    let (out_o, code_o) = match run_program(src_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}", e);
            return ExitCode::FAILURE;
        }
    };
    let (out_b, code_b) = match run_program(&obf_path.to_string_lossy()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}", e);
            return ExitCode::FAILURE;
        }
    };
    println!("  оригинал     (код {}): {}", code_o, out_o.trim_end());
    println!("  обфусцирован (код {}): {}", code_b, out_b.trim_end());
    let same = out_o == out_b && code_o == code_b;

    // ── Шаг 6. Инспектор по обфусцированной версии ──
    println!("\n[6/6] Инспектор по обфусцированной версии:");
    match std::fs::read(&obf_path) {
        Ok(nb) => match ElfInspector::parse(&obf_path.to_string_lossy(), &nb) {
            Ok(ni) => {
                println!(
                    "  секций: было {}, стало {} (+1 junk-секция); кандидатов: было {}, осталось {}; размер файла: {} → {} байт",
                    orig_sections,
                    ni.section_count(),
                    cands.len(),
                    ni.candidates().len(),
                    orig_size,
                    result.new_bytes.len()
                );
            }
            Err(e) => eprintln!("  инспектор не разобрал вариант: {} (но программа запустилась)", e),
        },
        Err(e) => eprintln!("  не удалось перечитать вариант: {}", e),
    }

    if same {
        println!(
            "\nИтог: поведение совпало — обфускация эквивалентна. Обфусцированный ELF: {}",
            obf_path.display()
        );
        ExitCode::SUCCESS
    } else {
        eprintln!("\nИтог: вывод различается — обфускация испортила программу!");
        ExitCode::FAILURE
    }
}

/// Вспомогательная команда: obfuscator-core inspect <файл>.
///
/// Вход — C-исходник (компилируем и показываем ELF) либо готовый ELF
/// (читаем как есть, без компиляции): obfuscator-core inspect /bin/ls.
pub fn run_inspect(src_path: &str) -> ExitCode {
    // ── Вход ELF: отчёт сразу, компиляция не нужна ──
    if inspector::is_elf(src_path) {
        let bytes = match std::fs::read(src_path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("Не удалось прочитать «{}»: {}", src_path, e);
                return ExitCode::FAILURE;
            }
        };
        return match ElfInspector::parse(src_path, &bytes) {
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
                eprintln!("«{}» не разобрать как ELF: {}", src_path, e);
                ExitCode::FAILURE
            }
        };
    }

    // ── Вход C-исходник: компилируем, затем тот же отчёт ──
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
