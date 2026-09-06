use goblin::pe::PE;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, env, fs, path::Path};

const MAPPING_DATA: &str = include_str!("../mappings/evidence.toml");
const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Deserialize)]
struct EvidenceTable {
    schema_version: u32,
    mapping_version: String,
    mapping: Vec<Evidence>,
}

#[derive(Debug, Deserialize)]
struct Evidence {
    dll: String,
    #[serde(default)]
    dll_aliases: Vec<String>,
    symbol: String,
    area: String,
    wording: String,
}

#[derive(Default)]
struct VersionInfo {
    product_name: Option<String>,
    product_version: Option<String>,
    company_name: Option<String>,
}

fn main() {
    let Some(path) = env::args_os().nth(1) else {
        eprintln!("Please provide a path to one Windows PE binary.");
        return;
    };
    if env::args_os().nth(2).is_some() {
        eprintln!("Please provide exactly one path to a Windows PE binary.");
        return;
    }

    let path = Path::new(&path);
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("Pet Passport could not read '{}': {error}", path.display());
            return;
        }
    };
    let pe = match PE::parse(&bytes) {
        Ok(pe) => pe,
        Err(_) => {
            eprintln!("'{}' is not a Windows PE file.", path.display());
            return;
        }
    };
    let table: EvidenceTable = match toml::from_str::<EvidenceTable>(MAPPING_DATA) {
        Ok(table) if table.schema_version == 1 => table,
        Ok(_) => {
            eprintln!("The bundled evidence mapping has an unsupported schema version.");
            return;
        }
        Err(error) => {
            eprintln!("The bundled evidence mapping could not be read: {error}");
            return;
        }
    };

    render_report(path, &bytes, &pe, &table);
}

fn render_report(path: &Path, bytes: &[u8], pe: &PE<'_>, table: &EvidenceTable) {
    let digest = Sha256::digest(bytes);
    let version = version_info(bytes, pe);

    println!("Self-reported identity (unverified)");
    println!(
        "This report was produced by Pet Passport {TOOL_VERSION} for '{}'.",
        path.display()
    );
    println!(
        "The examined file is {} bytes and has SHA-256 {}.",
        bytes.len(),
        hex(&digest)
    );
    println!("The following fields are claims read from the PE VERSIONINFO resource; they are not independently verified.");
    match version.product_name {
        Some(value) => println!("The resource self-reports product name: {value}."),
        None => println!("No self-reported product name was found in a VERSIONINFO resource."),
    }
    match version.product_version {
        Some(value) => println!("The resource self-reports product version: {value}."),
        None => println!("No self-reported product version was found in a VERSIONINFO resource."),
    }
    match version.company_name {
        Some(value) => println!("The resource self-reports company: {value}."),
        None => println!("No self-reported company was found in a VERSIONINFO resource."),
    }

    println!("\nObserved imports");
    println!("These are names found in the binary's import table. The wording comes from evidence mapping {} (schema {}).", table.mapping_version, table.schema_version);
    if pe.imports.is_empty() {
        println!("No imported function names were available in the import table.");
    } else {
        let mut imports: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for import in &pe.imports {
            imports
                .entry(import.dll.to_string())
                .or_default()
                .push(import.name.to_string());
        }
        for (dll, mut symbols) in imports {
            symbols.sort_unstable();
            symbols.dedup();
            println!("{dll} supplies {}.", symbols.join(", "));
            for symbol in symbols {
                if let Some(evidence) = table.mapping.iter().find(|item| {
                    (item.dll.eq_ignore_ascii_case(&dll)
                        || item
                            .dll_aliases
                            .iter()
                            .any(|alias| alias.eq_ignore_ascii_case(&dll)))
                        && item.symbol.eq_ignore_ascii_case(&symbol)
                }) {
                    println!("  In the {} area: {}", evidence.area, evidence.wording);
                } else {
                    println!(
                        "  No published plain-language mapping currently covers {dll}!{symbol}."
                    );
                }
            }
        }
    }

    println!("\nBlind spots");
    let names: Vec<String> = pe
        .imports
        .iter()
        .map(|item| item.name.to_string())
        .collect();
    let has_load_library = names
        .iter()
        .any(|name| name.to_ascii_lowercase().starts_with("loadlibrary"));
    let has_get_proc = names
        .iter()
        .any(|name| matches_name(name, "GetProcAddress"));
    if has_load_library && has_get_proc {
        println!("Both LoadLibrary and GetProcAddress are imported. This is evidence that DLLs and symbols may be resolved while the program runs, so this static import picture is partial.");
    } else {
        println!("This import table does not show both LoadLibrary and GetProcAddress together. That does not rule out runtime symbol resolution by another route.");
    }
    if names.len() <= 3 {
        println!("Only {} imported function name(s) were recovered. An unusually small import table can result when code is packed, generated, or resolves symbols at runtime.", names.len());
    } else {
        println!("{} imported function name(s) were recovered; import names still do not expose symbols resolved after startup.", names.len());
    }
    let high_entropy = high_entropy_sections(bytes, pe);
    if high_entropy.is_empty() {
        println!("No section with entropy at or above 7.2 bits per byte was found. This is not evidence that the file is unpacked.");
    } else {
        println!("Section(s) {} have entropy at or above 7.2 bits per byte, which can occur with compressed or packed data and makes static inspection less complete.", high_entropy.join(", "));
    }
    let unusual = unusual_sections(pe);
    if unusual.is_empty() {
        println!("No section names outside this tool's small conventional-name set were observed; names alone cannot establish how code is stored.");
    } else {
        println!("Section name(s) {} are outside this tool's small conventional-name set. Names are only a cue for further examination, not a conclusion.", unusual.join(", "));
    }
    let callbacks = tls_callbacks(bytes, pe);
    if callbacks == 0 {
        println!("No TLS callback addresses were recovered. TLS callbacks can run before a program's usual entry point when present.");
    } else {
        println!("{callbacks} TLS callback address(es) were recovered. Such callbacks can run before a program's usual entry point.");
    }

    println!("\nWhat this tool cannot see");
    println!("This is a static reading of one file. It cannot see code produced after launch, decrypted or downloaded content, direct system calls, user-triggered paths, or what the program actually does on a particular machine. Dynamic and behavioral analysis tools, such as a sandbox, system-call monitor, network capture, or debugger, can observe kinds of runtime behavior that this report cannot.");
}

fn matches_name(name: &str, stem: &str) -> bool {
    name.eq_ignore_ascii_case(stem)
        || name.eq_ignore_ascii_case(&format!("{stem}A"))
        || name.eq_ignore_ascii_case(&format!("{stem}W"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn section_name(section: &goblin::pe::section_table::SectionTable) -> String {
    let raw = section.name().unwrap_or("");
    raw.trim_end_matches('\0').to_string()
}

fn high_entropy_sections(bytes: &[u8], pe: &PE<'_>) -> Vec<String> {
    pe.sections
        .iter()
        .filter_map(|section| {
            let start = section.pointer_to_raw_data as usize;
            let end = start.checked_add(section.size_of_raw_data as usize)?;
            let data = bytes.get(start..end)?;
            (entropy(data) >= 7.2).then(|| section_name(section))
        })
        .collect()
}

fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for byte in data {
        counts[*byte as usize] += 1;
    }
    let length = data.len() as f64;
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

fn unusual_sections(pe: &PE<'_>) -> Vec<String> {
    const CONVENTIONAL: &[&str] = &[
        ".text", ".rdata", ".data", ".rsrc", ".reloc", ".pdata", ".idata", ".edata", ".tls",
        ".debug", ".bss", ".CRT", ".00cfg", ".gfids",
    ];
    pe.sections
        .iter()
        .map(section_name)
        .filter(|name| {
            !CONVENTIONAL
                .iter()
                .any(|known| name.eq_ignore_ascii_case(known))
        })
        .collect()
}

fn rva_to_offset(pe: &PE<'_>, rva: u32) -> Option<usize> {
    pe.sections.iter().find_map(|section| {
        let start = section.virtual_address;
        let extent = section.virtual_size.max(section.size_of_raw_data);
        (rva >= start && rva < start.checked_add(extent)?)
            .then(|| (section.pointer_to_raw_data + rva - start) as usize)
    })
}

fn tls_callbacks(bytes: &[u8], pe: &PE<'_>) -> usize {
    let Some(optional) = pe.header.optional_header else {
        return 0;
    };
    let directory = optional
        .data_directories
        .get_tls_table()
        .copied()
        .unwrap_or_default();
    if directory.virtual_address == 0 || directory.size == 0 {
        return 0;
    }
    let Some(offset) = rva_to_offset(pe, directory.virtual_address) else {
        return 0;
    };
    let is_64 = pe.is_64;
    let address_offset = if is_64 { 24 } else { 12 };
    let pointer_size = if is_64 { 8 } else { 4 };
    let callback_va = if is_64 {
        read_u64(bytes, offset + address_offset).unwrap_or(0)
    } else {
        read_u32(bytes, offset + address_offset).unwrap_or(0) as u64
    };
    if callback_va == 0 {
        return 0;
    }
    let image_base = if is_64 {
        optional.windows_fields.image_base
    } else {
        optional.windows_fields.image_base
    };
    let Some(callback_rva) = callback_va.checked_sub(image_base) else {
        return 0;
    };
    let Some(callback_offset) = rva_to_offset(pe, callback_rva as u32) else {
        return 0;
    };
    (0..128)
        .take_while(|index| {
            let offset = callback_offset + index * pointer_size;
            if is_64 {
                read_u64(bytes, offset).unwrap_or(0) != 0
            } else {
                read_u32(bytes, offset).unwrap_or(0) != 0
            }
        })
        .count()
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn version_info(bytes: &[u8], pe: &PE<'_>) -> VersionInfo {
    let Some(optional) = pe.header.optional_header else {
        return VersionInfo::default();
    };
    let directory = optional
        .data_directories
        .get_resource_table()
        .copied()
        .unwrap_or_default();
    if directory.virtual_address == 0 {
        return VersionInfo::default();
    }
    let Some(base) = rva_to_offset(pe, directory.virtual_address) else {
        return VersionInfo::default();
    };
    let Some(data_entry) = find_version_resource(bytes, base, 0, 0) else {
        return VersionInfo::default();
    };
    let Some(data_rva) = read_u32(bytes, data_entry) else {
        return VersionInfo::default();
    };
    let Some(size) = read_u32(bytes, data_entry + 4) else {
        return VersionInfo::default();
    };
    let Some(offset) = rva_to_offset(pe, data_rva) else {
        return VersionInfo::default();
    };
    let Some(data) = bytes.get(offset..offset.saturating_add(size as usize)) else {
        return VersionInfo::default();
    };
    parse_version_resource(data)
}

fn find_version_resource(
    bytes: &[u8],
    base: usize,
    relative: usize,
    depth: usize,
) -> Option<usize> {
    if depth > 3 {
        return None;
    }
    let directory = base.checked_add(relative)?;
    let count =
        read_u16(bytes, directory + 12)? as usize + read_u16(bytes, directory + 14)? as usize;
    for index in 0..count {
        let entry = directory + 16 + index * 8;
        let name = read_u32(bytes, entry)?;
        let target = read_u32(bytes, entry + 4)?;
        if depth == 0 && name != 16 {
            continue;
        }
        if target & 0x8000_0000 != 0 {
            if let Some(found) =
                find_version_resource(bytes, base, (target & 0x7fff_ffff) as usize, depth + 1)
            {
                return Some(found);
            }
        } else if depth > 0 {
            return base.checked_add(target as usize);
        }
    }
    None
}

fn parse_version_resource(data: &[u8]) -> VersionInfo {
    if read_utf16z(data, 6).as_deref() != Some("VS_VERSION_INFO") {
        return VersionInfo::default();
    }
    let root_length = read_u16(data, 0).unwrap_or(0) as usize;
    if root_length == 0 || root_length > data.len() {
        return VersionInfo::default();
    }
    let key_end = utf16z_end(data, 6).unwrap_or(root_length);
    let value_length = read_u16(data, 2).unwrap_or(0) as usize;
    let mut cursor = align4(key_end.saturating_add(value_length));
    let mut result = VersionInfo::default();
    while cursor + 6 <= root_length {
        let length = read_u16(data, cursor).unwrap_or(0) as usize;
        if length == 0 || cursor + length > root_length {
            break;
        }
        let key = read_utf16z(data, cursor + 6).unwrap_or_default();
        if key == "StringFileInfo" {
            parse_string_file_info(&data[cursor..cursor + length], &mut result);
        }
        cursor += align4(length);
    }
    result
}

fn parse_string_file_info(data: &[u8], result: &mut VersionInfo) {
    let Some(total) = read_u16(data, 0).map(|value| value as usize) else {
        return;
    };
    let Some(key_end) = utf16z_end(data, 6) else {
        return;
    };
    let mut table = align4(key_end);
    while table + 6 <= total && table < data.len() {
        let length = read_u16(data, table).unwrap_or(0) as usize;
        if length == 0 || table + length > total || table + length > data.len() {
            break;
        }
        parse_string_table(&data[table..table + length], result);
        table += align4(length);
    }
}

fn parse_string_table(data: &[u8], result: &mut VersionInfo) {
    let Some(total) = read_u16(data, 0).map(|value| value as usize) else {
        return;
    };
    let Some(key_end) = utf16z_end(data, 6) else {
        return;
    };
    let mut item = align4(key_end);
    while item + 6 <= total && item < data.len() {
        let length = read_u16(data, item).unwrap_or(0) as usize;
        if length == 0 || item + length > total || item + length > data.len() {
            break;
        }
        let value_length = read_u16(data, item + 2).unwrap_or(0) as usize;
        let key = read_utf16z(data, item + 6).unwrap_or_default();
        let Some(value_start) = utf16z_end(data, item + 6).map(align4) else {
            break;
        };
        let value = read_utf16(data, value_start, value_length).unwrap_or_default();
        match key.as_str() {
            "ProductName" => result.product_name = nonempty(value),
            "ProductVersion" => result.product_version = nonempty(value),
            "CompanyName" => result.company_name = nonempty(value),
            _ => {}
        }
        item += align4(length);
    }
}

fn nonempty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}
fn align4(value: usize) -> usize {
    (value + 3) & !3
}
fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}
fn utf16z_end(data: &[u8], offset: usize) -> Option<usize> {
    let mut cursor = offset;
    loop {
        if read_u16(data, cursor)? == 0 {
            return Some(cursor + 2);
        }
        cursor += 2;
    }
}
fn read_utf16z(data: &[u8], offset: usize) -> Option<String> {
    read_utf16(data, offset, (utf16z_end(data, offset)? - offset) / 2 - 1)
}
fn read_utf16(data: &[u8], offset: usize, units: usize) -> Option<String> {
    let end = offset.checked_add(units.checked_mul(2)?)?;
    let words: Vec<u16> = data
        .get(offset..end)?
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    Some(
        String::from_utf16_lossy(&words)
            .trim_end_matches('\0')
            .to_string(),
    )
}
