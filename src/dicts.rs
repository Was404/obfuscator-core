//! Таблицы имён: расшифровка числовых констант формата ELF.
//!
//! Все значения взяты из спецификации System V ABI (ELF) и её
//! дополнений GNU/Linux. Инспектор пользуется этими функциями,
//! чтобы вместо «p_type = 0x6474e551» печатать «GNU_STACK».

/// Сегмент PT_INTERP — в нём лежит путь к динамическому загрузчику.
pub const PT_INTERP: u32 = 3;
/// Символ-функция (поле типа внутри st_info).
#[allow(dead_code)] // используется точкой расширения function_symbols
pub const STT_FUNC: u8 = 2;
/// Запись .dynamic «имя требуемой библиотеки».
pub const DT_NEEDED: u64 = 1;
/// Запись .dynamic «собственное имя библиотеки» (SONAME).
pub const DT_SONAME: u64 = 14;
/// Запись .dynamic «путь поиска библиотек» (устаревшая).
pub const DT_RPATH: u64 = 15;
/// Запись .dynamic «путь поиска библиотек» (современная).
pub const DT_RUNPATH: u64 = 29;
/// Запись .dynamic «набор флагов» (DF_*).
pub const DT_FLAGS: u64 = 30;
/// Запись .dynamic «набор флагов» (DF_1_*).
pub const DT_FLAGS_1: u64 = 0x6fff_fffb;
/// Запись .dynamic «тип перемещений для PLT».
pub const DT_PLTREL: u64 = 20;

/// Класс файла — байт e_ident[4] (EI_CLASS).
pub fn class_to_str(c: u8) -> String {
    match c {
        1 => "ELF32 (32 бита)".into(),
        2 => "ELF64 (64 бита)".into(),
        _ => format!("неизвестный ({})", c),
    }
}

/// Порядок байт — байт e_ident[5] (EI_DATA).
pub fn data_to_str(d: u8) -> String {
    match d {
        1 => "младший (little-endian)".into(),
        2 => "старший (big-endian)".into(),
        _ => format!("неизвестный ({})", d),
    }
}

/// Операционная система и ABI — байт e_ident[7] (EI_OSABI).
pub fn osabi_to_str(o: u8) -> String {
    match o {
        0 => "UNIX — System V".into(),
        1 => "HP-UX".into(),
        2 => "NetBSD".into(),
        3 => "GNU/Linux".into(),
        6 => "Solaris".into(),
        9 => "FreeBSD".into(),
        _ => format!("неизвестный ({})", o),
    }
}

/// Тип файла — поле e_type.
pub fn etype_to_str(t: u16) -> String {
    match t {
        0 => "NONE — нет типа".into(),
        1 => "REL — перемещаемый объект (.o)".into(),
        2 => "EXEC — обычный исполняемый файл".into(),
        3 => "DYN — разделяемый объект (PIE или .so)".into(),
        4 => "CORE — дамп памяти процесса".into(),
        _ => format!("неизвестный ({})", t),
    }
}

/// Архитектура — поле e_machine (наиболее распространённые значения).
pub fn machine_to_str(m: u16) -> String {
    match m {
        0 => "NONE — нет".into(),
        2 => "SPARC".into(),
        3 => "i386 (Intel 80386)".into(),
        4 => "Motorola 68000".into(),
        8 => "MIPS".into(),
        20 => "PowerPC".into(),
        21 => "PowerPC64".into(),
        22 => "IBM S/390".into(),
        40 => "ARM".into(),
        42 => "SuperH".into(),
        43 => "SPARCv9".into(),
        50 => "IA-64 (Itanium)".into(),
        62 => "X86-64 (AMD / Intel 64)".into(),
        183 => "AArch64 (ARM64)".into(),
        243 => "RISC-V".into(),
        258 => "LoongArch".into(),
        _ => format!("неизвестная ({})", m),
    }
}

/// Тип сегмента — поле p_type программного заголовка.
pub fn pt_type_to_str(t: u32) -> String {
    match t {
        0 => "NULL".into(),
        1 => "LOAD".into(),
        2 => "DYNAMIC".into(),
        3 => "INTERP".into(),
        4 => "NOTE".into(),
        5 => "SHLIB".into(),
        6 => "PHDR".into(),
        7 => "TLS".into(),
        // 0x6474e550..0x6474e553 — расширения GNU (магия "GNU\0").
        0x6474_e550 => "GNU_EH_FRAME".into(),
        0x6474_e551 => "GNU_STACK".into(),
        0x6474_e552 => "GNU_RELRO".into(),
        0x6474_e553 => "GNU_PROPERTY".into(),
        _ => format!("НЕИЗВ_0x{:x}", t),
    }
}

/// Флаги сегмента — поле p_flags, строка вида «R-E» (чтение/запись/исполнение).
pub fn ph_flags_to_str(f: u32) -> String {
    let r = if f & 0x4 != 0 { 'R' } else { '-' };
    let w = if f & 0x2 != 0 { 'W' } else { '-' };
    let x = if f & 0x1 != 0 { 'E' } else { '-' };
    format!("{}{}{}", r, w, x)
}

/// Тип секции — поле sh_type.
pub fn sht_to_str(t: u32) -> String {
    match t {
        0 => "NULL".into(),
        1 => "PROGBITS".into(),
        2 => "SYMTAB".into(),
        3 => "STRTAB".into(),
        4 => "RELA".into(),
        5 => "HASH".into(),
        6 => "DYNAMIC".into(),
        7 => "NOTE".into(),
        8 => "NOBITS".into(),
        9 => "REL".into(),
        10 => "SHLIB".into(),
        11 => "DYNSYM".into(),
        14 => "INIT_ARRAY".into(),
        15 => "FINI_ARRAY".into(),
        16 => "PREINIT_ARRAY".into(),
        17 => "GROUP".into(),
        18 => "SYMTAB_SHNDX".into(),
        0x6fff_fff5 => "GNU_ATTRIBUTES".into(),
        0x6fff_fff6 => "GNU_HASH".into(),
        0x6fff_fff7 => "GNU_LIBLIST".into(),
        0x6fff_fffd => "GNU_VERDEF".into(),
        0x6fff_fffe => "GNU_VERNEED".into(),
        0x6fff_ffff => "GNU_VERSYM".into(),
        _ => format!("НЕИЗВ_0x{:x}", t),
    }
}

/// Флаги секции — поле sh_flags, список вида «ALLOC|EXEC».
pub fn sh_flags_to_str(f: u64) -> String {
    let mut names: Vec<&str> = Vec::new();
    let flags: [(u64, &str); 11] = [
        (0x1, "WRITE"),          // данные сегмента изменяемые
        (0x2, "ALLOC"),          // секция занимает память в процессе
        (0x4, "EXEC"),           // машинный код
        (0x10, "MERGE"),         // допускает слияние одинаковых элементов
        (0x20, "STRINGS"),       // содержит строки с NUL-терминаторами
        (0x40, "INFO_LINK"),     // поле sh_info хранит индекс секции
        (0x80, "LINK_ORDER"),    // порядок секций задаёт sh_link
        (0x100, "OS_NONCONFORM"),// нестандартная обработка ОС
        (0x200, "GROUP"),        // член группы секций
        (0x400, "TLS"),          // локальная память потоков
        (0x800, "COMPRESSED"),   // сжатые данные
    ];
    for (bit, name) in flags {
        if f & bit != 0 {
            names.push(name);
        }
    }
    if names.is_empty() { "-".into() } else { names.join("|") }
}

/// Тип связи символа — старшие 4 бита поля st_info (ST_BIND).
pub fn st_bind_to_str(b: u8) -> String {
    match b {
        0 => "LOCAL".into(),
        1 => "GLOBAL".into(),
        2 => "WEAK".into(),
        10 => "GNU_UNIQUE".into(),
        _ => format!("{}?", b),
    }
}

/// Тип символа — младшие 4 бита поля st_info (ST_TYPE).
pub fn st_type_to_str(t: u8) -> String {
    match t {
        0 => "NOTYPE".into(),
        1 => "OBJECT".into(),
        2 => "FUNC".into(),
        3 => "SECTION".into(),
        4 => "FILE".into(),
        5 => "COMMON".into(),
        6 => "TLS".into(),
        10 => "GNU_IFUNC".into(),
        _ => format!("{}?", t),
    }
}

/// Видимость символа — младшие 2 бита поля st_other (STV_*).
pub fn st_vis_to_str(v: u8) -> String {
    match v {
        0 => "DEFAULT".into(),
        1 => "INTERNAL".into(),
        2 => "HIDDEN".into(),
        3 => "PROTECTED".into(),
        _ => format!("{}?", v),
    }
}

/// Метка записи .dynamic — поле d_tag (часто используемые значения).
pub fn dt_tag_to_str(t: u64) -> String {
    match t {
        0 => "DT_NULL".into(),
        1 => "DT_NEEDED".into(),
        2 => "DT_PLTRELSZ".into(),
        3 => "DT_PLTGOT".into(),
        4 => "DT_HASH".into(),
        5 => "DT_STRTAB".into(),
        6 => "DT_SYMTAB".into(),
        7 => "DT_RELA".into(),
        8 => "DT_RELASZ".into(),
        9 => "DT_RELAENT".into(),
        10 => "DT_STRSZ".into(),
        11 => "DT_SYMENT".into(),
        12 => "DT_INIT".into(),
        13 => "DT_FINI".into(),
        14 => "DT_SONAME".into(),
        15 => "DT_RPATH".into(),
        16 => "DT_SYMBOLIC".into(),
        17 => "DT_REL".into(),
        18 => "DT_RELSZ".into(),
        19 => "DT_RELENT".into(),
        20 => "DT_PLTREL".into(),
        21 => "DT_DEBUG".into(),
        22 => "DT_TEXTREL".into(),
        23 => "DT_JMPREL".into(),
        24 => "DT_BIND_NOW".into(),
        25 => "DT_INIT_ARRAY".into(),
        26 => "DT_FINI_ARRAY".into(),
        27 => "DT_INIT_ARRAYSZ".into(),
        28 => "DT_FINI_ARRAYSZ".into(),
        29 => "DT_RUNPATH".into(),
        30 => "DT_FLAGS".into(),
        32 => "DT_PREINIT_ARRAY".into(),
        33 => "DT_PREINIT_ARRAYSZ".into(),
        0x6fff_fef5 => "DT_GNU_HASH".into(),
        0x6fff_fff0 => "DT_VERSYM".into(),
        0x6fff_fffc => "DT_VERDEF".into(),
        0x6fff_fffd => "DT_VERDEFNUM".into(),
        0x6fff_fffe => "DT_VERNEED".into(),
        0x6fff_ffff => "DT_VERNEEDNUM".into(),
        0x6fff_fff9 => "DT_RELACOUNT".into(),
        0x6fff_fffa => "DT_RELCOUNT".into(),
        0x6fff_fffb => "DT_FLAGS_1".into(),
        _ => format!("0x{:x}", t),
    }
}

/// Расшифровка набора флагов DT_FLAGS (DF_*).
pub fn dt_flags_to_str(f: u64) -> String {
    let mut names: Vec<&str> = Vec::new();
    let flags: [(u64, &str); 5] = [
        (0x1, "ORIGIN"),    // $ORIGIN разрешён в RUNPATH
        (0x2, "SYMBOLIC"),  // свои символы приоритетнее глобальных
        (0x4, "TEXTREL"),   // перемещения в кодовой (read-only) части
        (0x8, "BIND_NOW"),  // связывание всех символов при загрузке
        (0x10, "STATIC_TLS"),// используется статический TLS
    ];
    for (bit, name) in flags {
        if f & bit != 0 {
            names.push(name);
        }
    }
    names.join("|")
}

/// Расшифровка набора флагов DT_FLAGS_1 (DF_1_*).
pub fn dt_flags1_to_str(f: u64) -> String {
    let mut names: Vec<&str> = Vec::new();
    let flags: [(u64, &str); 8] = [
        (0x1, "NOW"),        // немедленное связывание
        (0x8, "NODELETE"),   // библиотеку нельзя выгрузить
        (0x10, "LOADFLTR"),  // загружать фильтры при старте
        (0x20, "INITFIRST"), // инициализировать первой
        (0x40, "NOOPEN"),    // нельзя загрузить через dlopen
        (0x80, "ORIGIN"),    // $ORIGIN разрешён
        (0x800, "NODEFLIB"), // пути поиска по умолчанию не используются
        (0x0800_0000, "PIE"),// позиционно-независимый исполняемый файл
    ];
    for (bit, name) in flags {
        if f & bit != 0 {
            names.push(name);
        }
    }
    names.join("|")
}
