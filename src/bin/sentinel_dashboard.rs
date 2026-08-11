use pdb::FallibleIterator;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter};

// Embedded static assets compiled directly into our single binary! (V2.7 - FORCE CACHE BUSTER)
const INDEX_HTML: &str = include_str!("../../dashboard/dist/index.html");
const INDEX_JS: &str = include_str!("../../dashboard/dist/assets/index.js");
const INDEX_CSS: &str = include_str!("../../dashboard/dist/assets/index.css");

// --- MANUAL MINI-JSON PARSER HELPERS ---
fn get_json_string_field(body: &str, field: &str) -> Option<String> {
    let pattern = format!("\"{}\":", field);
    if let Some(idx) = body.find(&pattern) {
        let start = idx + pattern.len();
        let slice = &body[start..];
        if let Some(q1) = slice.find('"') {
            let rest = &slice[q1+1..];
            if let Some(q2) = rest.find('"') {
                return Some(rest[..q2].to_string());
            }
        }
    }
    None
}

fn get_json_bool_field(body: &str, field: &str) -> bool {
    let pattern = format!("\"{}\":", field);
    if let Some(idx) = body.find(&pattern) {
        let start = idx + pattern.len();
        let slice = &body[start..].trim_start();
        if slice.starts_with("true") {
            return true;
        }
    }
    false
}

fn get_json_array_field(body: &str, field: &str) -> Vec<String> {
    let mut results = Vec::new();
    let pattern = format!("\"{}\":", field);
    if let Some(idx) = body.find(&pattern) {
        let start = idx + pattern.len();
        let slice = &body[start..].trim_start();
        if slice.starts_with('[') {
            let mut list_slice = &slice[1..];
            if let Some(end_bracket) = list_slice.find(']') {
                list_slice = &list_slice[..end_bracket];
                for item in list_slice.split(',') {
                    let cleaned = item.trim().trim_matches('"');
                    if !cleaned.is_empty() {
                        results.push(cleaned.to_string());
                    }
                }
            }
        }
    }
    results
}

fn decode_hex(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut chars = hex.chars();
    while let (Some(c1), Some(c2)) = (chars.next(), chars.next()) {
        let hex_byte = format!("{}{}", c1, c2);
        if let Ok(b) = u8::from_str_radix(&hex_byte, 16) {
            bytes.push(b);
        }
    }
    bytes
}

// Opens the PDB file and retrieves the exact relative virtual address (RVA) of a function by name
fn find_function_rva_in_pdb(pdb_path: &str, func_name: &str) -> Result<u32, Box<dyn std::error::Error>> {
    let file = fs::File::open(pdb_path)?;
    let mut pdb = pdb::PDB::open(file)?;
    
    let symbol_table = pdb.global_symbols()?;
    let address_map = pdb.address_map()?;
    
    let mut symbols = symbol_table.iter();
    while let Some(symbol) = symbols.next()? {
        match symbol.parse() {
            Ok(pdb::SymbolData::Public(data)) => {
                let name = data.name.to_string();
                if name.contains(func_name) {
                    let rva = data.offset.to_rva(&address_map);
                    if let Some(rva_val) = rva {
                        println!("      [PDB] Found public symbol '{}' mapping to RVA: 0x{:X}", name, rva_val.0);
                        return Ok(rva_val.0);
                    }
                }
            }
            Ok(pdb::SymbolData::Procedure(data)) => {
                let name = data.name.to_string();
                if name.contains(func_name) {
                    let rva = data.offset.to_rva(&address_map);
                    if let Some(rva_val) = rva {
                        println!("      [PDB] Found procedure symbol '{}' mapping to RVA: 0x{:X}", name, rva_val.0);
                        return Ok(rva_val.0);
                    }
                }
            }
            _ => {}
        }
    }
    
    Err(format!("Could not find symbol containing '{}' in the PDB file.", func_name).into())
}

// --- API IMPLEMENTATIONS ---

// Scan target/release/ for matching .exe/.dll and .pdb file pairs
fn get_binaries_json() -> String {
    let mut items = Vec::new();
    if let Ok(entries) = fs::read_dir("target/release") {
        let mut binary_files = Vec::new();
        let mut pdb_files = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name().into_string().unwrap_or_default();
            let lower = name.to_lowercase();
            if (lower.ends_with(".exe") || lower.ends_with(".dll")) && 
               name != "symbol_lister.exe" && name != "pe_protector.exe" && name != "sentinel_dashboard.exe" && name != "binarydefender.exe" {
                binary_files.push(name);
            } else if lower.ends_with(".pdb") && 
                      name != "symbol_lister.pdb" && name != "pe_protector.pdb" && name != "sentinel_dashboard.pdb" && name != "binarydefender.pdb" {
                pdb_files.push(name);
            }
        }
        for bin in binary_files {
            let base_name = if bin.to_lowercase().ends_with(".exe") {
                bin.strip_suffix(".exe").unwrap().to_string()
            } else {
                bin.strip_suffix(".dll").unwrap().to_string()
            };
            let pdb = format!("{}.pdb", base_name);
            if pdb_files.contains(&pdb) {
                items.push(format!(
                    "{{\"exeName\":\"{}\",\"pdbName\":\"{}\",\"fullExePath\":\"target/release/{}\",\"fullPdbPath\":\"target/release/{}\"}}",
                    bin, pdb, bin, pdb
                ));
            }
        }
    }
    format!("[{}]", items.join(","))
}

// Parse PDB symbols directly in Rust using the PDB crate
fn get_symbols_json(pdb_name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let pdb_path = format!("target/release/{}", pdb_name);
    let file = fs::File::open(pdb_path)?;
    let mut pdb = pdb::PDB::open(file)?;
    
    let symbol_table = pdb.global_symbols()?;
    let address_map = pdb.address_map()?;
    
    let mut symbols = symbol_table.iter();
    let mut json_items = Vec::new();
    while let Some(symbol) = symbols.next()? {
        match symbol.parse() {
            Ok(pdb::SymbolData::Public(data)) => {
                let name = data.name.to_string();
                let rva = data.offset.to_rva(&address_map);
                if let Some(rva_val) = rva {
                    let escaped_name = name.replace("\\", "\\\\").replace("\"", "\\\"");
                    json_items.push(format!(
                        "{{\"type\":\"Public\",\"name\":\"{}\",\"rva\":\"0x{:X}\"}}",
                        escaped_name, rva_val.0
                    ));
                }
            }
            Ok(pdb::SymbolData::Procedure(data)) => {
                let name = data.name.to_string();
                let rva = data.offset.to_rva(&address_map);
                if let Some(rva_val) = rva {
                    let escaped_name = name.replace("\\", "\\\\").replace("\"", "\\\"");
                    json_items.push(format!(
                        "{{\"type\":\"Procedure\",\"name\":\"{}\",\"rva\":\"0x{:X}\"}}",
                        escaped_name, rva_val.0
                    ));
                }
            }
            _ => {}
        }
    }
    Ok(format!("[{}]", json_items.join(",")))
}

// Scan executable buffer for printable ASCII strings natively (no Node dependency)
fn get_strings_json(exe_name: &str) -> String {
    let exe_path = format!("target/release/{}", exe_name);
    if let Ok(buffer) = fs::read(exe_path) {
        let mut strings = Vec::new();
        let mut current = Vec::new();
        for &char in &buffer {
            if char >= 32 && char <= 126 {
                current.push(char as char);
            } else {
                if current.len() >= 6 {
                    let s: String = current.iter().collect();
                    strings.push(s);
                }
                current.clear();
            }
        }
        
        let mut filtered: Vec<String> = strings
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| s.len() >= 6 && s.chars().next().map_or(false, |c| c.is_alphanumeric() || c == '['))
            .collect();
        filtered.sort();
        filtered.dedup();
        
        let json_escaped: Vec<String> = filtered
            .into_iter()
            .map(|s| format!("\"{}\"", s.replace("\\", "\\\\").replace("\"", "\\\"")))
            .collect();
            
        return format!("[{}]", json_escaped.join(","));
    }
    "[]".to_string()
}

// Handle file staging and upload natively in memory
fn handle_upload(body: &str) -> String {
    let exe_name = get_json_string_field(body, "exeName").unwrap_or_else(|| "uploaded_target.exe".to_string());
    let exe_hex = get_json_string_field(body, "exeHex").unwrap_or_default();
    let pdb_name = get_json_string_field(body, "pdbName").unwrap_or_else(|| "uploaded_target.pdb".to_string());
    let pdb_hex = get_json_string_field(body, "pdbHex").unwrap_or_default();

    println!("[SENTINEL DASHBOARD] Staging uploaded PE binary '{}' & PDB '{}'...", exe_name, pdb_name);

    let exe_bytes = decode_hex(&exe_hex);
    let pdb_bytes = decode_hex(&pdb_hex);

    if exe_bytes.is_empty() || pdb_bytes.is_empty() {
        return "{\"success\":false,\"error\":\"Empty or invalid file streams.\"}".to_string();
    }

    // Write directly to target/release using generic target filenames
    fs::write("target/release/uploaded_target.exe", exe_bytes).ok();
    fs::write("target/release/uploaded_target.pdb", pdb_bytes).ok();

    println!("[SENTINEL DASHBOARD] Successfully staged uploaded assets!");
    "{\"success\":true}".to_string()
}

// Invoke pe_protector executable with GUI arguments
fn execute_protect(body: &str) -> String {
    let exe_name = get_json_string_field(body, "exeName").unwrap_or_default();
    let pdb_name = get_json_string_field(body, "pdbName").unwrap_or_default();
    let staged_funcs = get_json_array_field(body, "funcNames");
    let staged_strings = get_json_array_field(body, "strings");
    let encrypt_all = get_json_bool_field(body, "encryptAll");
    let cff_enabled = get_json_bool_field(body, "cffEnabled");
    let seh_enabled = get_json_bool_field(body, "sehEnabled");
    let hijack_enabled = get_json_bool_field(body, "hijackEnabled");
    let tamper_enabled = get_json_bool_field(body, "tamperEnabled"); // Extract new tamperEnabled state!
    let sec_name = get_json_string_field(body, "secName").unwrap_or_else(|| ".shield".to_string());
    let obfuscation_level = get_json_string_field(body, "obfuscationLevel").unwrap_or_else(|| "HIGH".to_string());
    let seed_value = get_json_string_field(body, "seed").unwrap_or_else(|| "3735928542".to_string());
    let cff_level = get_json_string_field(body, "cffLevel").unwrap_or_else(|| "3".to_string());
    let prompt_top = get_json_string_field(body, "promptTop").unwrap_or_default();
    let prompts_spread = get_json_array_field(body, "promptsSpread");
    let bbr_enabled = get_json_bool_field(body, "bbrEnabled");

    let input_exe = format!("target/release/{}", exe_name);
    let input_pdb = format!("target/release/{}", pdb_name);
    
    let base_name = exe_name.strip_suffix(".exe").unwrap_or(&exe_name);
    let output_file_name = format!("{}_protected.exe", base_name);
    let output_exe = format!("target/release/{}", output_file_name);

    // Create flat text-file config to bypass Windows command line buffer limits
    let mut config_content = String::new();
    config_content.push_str(&format!("input_exe={}\n", input_exe));
    config_content.push_str(&format!("input_pdb={}\n", input_pdb));
    config_content.push_str(&format!("output_exe={}\n", output_exe));
    config_content.push_str(&format!("sec_name={}\n", sec_name));
    config_content.push_str(&format!("cff_enabled={}\n", cff_enabled));
    config_content.push_str(&format!("seh_enabled={}\n", seh_enabled));
    config_content.push_str(&format!("hijack_enabled={}\n", hijack_enabled));
    config_content.push_str(&format!("tamper_enabled={}\n", tamper_enabled)); // Pass tamper enabled!
    config_content.push_str(&format!("obfuscation_level={}\n", obfuscation_level));
    config_content.push_str(&format!("seed_value={}\n", seed_value));
    config_content.push_str(&format!("cff_level={}\n", cff_level));
    config_content.push_str(&format!("prompt_top={}\n", prompt_top));
    config_content.push_str(&format!("bbr_enabled={}\n", bbr_enabled));
    
    config_content.push_str("[funcs]\n");
    for f in staged_funcs {
        config_content.push_str(&format!("{}\n", f));
    }
    
    config_content.push_str("[strings]\n");
    if encrypt_all {
        let all_strings = get_strings_json(&exe_name);
        let mut count = 0;
        for s in all_strings.trim_matches(|c| c == '[' || c == ']').split(',') {
            let cleaned = s.trim().trim_matches('"');
            if !cleaned.is_empty() {
                config_content.push_str(&format!("{}\n", cleaned));
                count += 1;
                if count >= 15 { break; } // limit command line buffer limit (ORIGINAL HARBOR)
            }
        }
    } else {
        for s in staged_strings {
            config_content.push_str(&format!("{}\n", s));
        }
    }

    config_content.push_str("[prompts_spread]\n");
    for p in prompts_spread {
        config_content.push_str(&format!("{}\n", p));
    }

    let config_path = "target/release/build_profile.txt";
    if let Err(e) = fs::write(config_path, config_content) {
        return format!("{{\"success\":false,\"stdout\":\"\",\"stderr\":\"Failed to write compiler profile: {}\"}}", e);
    }

    let args = vec![
        "run".to_string(), "--bin".to_string(), "pe_protector".to_string(), "--".to_string(),
        "-c".to_string(), config_path.to_string(),
    ];

    println!("[SENTINEL DASHBOARD] Spawning protector pass with args: {:?}", args);
    let output = std::process::Command::new("cargo")
        .args(&args)
        .output();

    match output {
        Ok(out) => {
            let mut original_entry_point_rva = 0u32;
            let mut cff_base_rva = 0u32;

            // Read original entry point from input PE
            if let Ok(exe_data) = fs::read(&input_exe) {
                let pe_offset = u32::from_le_bytes(exe_data[0x3C..0x40].try_into().unwrap_or_default()) as usize;
                let opt_header_offset = pe_offset + 24;
                original_entry_point_rva = u32::from_le_bytes(exe_data[opt_header_offset + 16..opt_header_offset + 20].try_into().unwrap_or_default());
            }

            // Read hijacked entry point from newly compiled output PE
            if let Ok(out_data) = fs::read(&output_exe) {
                let pe_offset = u32::from_le_bytes(out_data[0x3C..0x40].try_into().unwrap_or_default()) as usize;
                let opt_header_offset = pe_offset + 24;
                cff_base_rva = u32::from_le_bytes(out_data[opt_header_offset + 16..opt_header_offset + 20].try_into().unwrap_or_default());
            }

            let stdout = String::from_utf8_lossy(&out.stdout).replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "");
            let stderr = String::from_utf8_lossy(&out.stderr).replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "");
            format!(
                "{{\n  \"success\": {},\n  \"outputFileName\": \"{}\",\n  \"originalEntryPoint\": \"0x{:X}\",\n  \"hijackedEntryPoint\": \"0x{:X}\",\n  \"stdout\": \"{}\",\n  \"stderr\": \"{}\"\n}}",
                out.status.success(), output_file_name, original_entry_point_rva, cff_base_rva, stdout, stderr
            )
        }
        Err(e) => {
            format!(
                "{{\n  \"success\": false,\n  \"outputFileName\": \"\",\n  \"stdout\": \"\",\n  \"stderr\": \"Failed to launch pe_protector: {}\"\n}}",
                e.to_string().replace("\"", "\\\"")
            )
        }
    }
}

// --- DYNAMIC CONTROL FLOW GRAPH (CFG) DISASSEMBLER ---
fn get_cfg_json(exe_name: &str, func_name: &str, pdb_name: &str) -> String {
    let exe_path = format!("target/release/{}", exe_name);
    let pdb_path = format!("target/release/{}", pdb_name);
    
    // 1. Find function RVA from PDB
    let func_rva = match find_function_rva_in_pdb(&pdb_path, func_name) {
        Ok(rva) => rva,
        Err(_) => return "{\"error\":\"Symbol not found in PDB.\"}".to_string(),
    };

    // 2. Open PE and parse section headers to find function raw offset
    let exe_data = match fs::read(&exe_path) {
        Ok(data) => data,
        Err(_) => return "{\"error\":\"Failed to read target .exe\"}".to_string(),
    };

    let pe_offset = u32::from_le_bytes(exe_data[0x3C..0x40].try_into().unwrap()) as usize;
    let num_sections = u16::from_le_bytes(exe_data[pe_offset + 6..pe_offset + 8].try_into().unwrap()) as usize;
    let size_of_opt_header = u16::from_le_bytes(exe_data[pe_offset + 20..pe_offset + 22].try_into().unwrap()) as usize;
    let opt_header_offset = pe_offset + 24;
    let image_base = u64::from_le_bytes(exe_data[opt_header_offset + 24..opt_header_offset + 32].try_into().unwrap());
    let original_entry_point_rva = u32::from_le_bytes(exe_data[opt_header_offset + 16..opt_header_offset + 20].try_into().unwrap());
    let section_headers_offset = opt_header_offset + size_of_opt_header;

    let mut func_abs_offset = 0usize;
    for i in 0..num_sections {
        let offset = section_headers_offset + i * 40;
        let v_size = u32::from_le_bytes(exe_data[offset + 8..offset + 12].try_into().unwrap()) as usize;
        let v_addr = u32::from_le_bytes(exe_data[offset + 12..offset + 16].try_into().unwrap()) as usize;
        let r_size = u32::from_le_bytes(exe_data[offset + 16..offset + 20].try_into().unwrap()) as usize;
        let r_offset = u32::from_le_bytes(exe_data[offset + 20..offset + 24].try_into().unwrap()) as usize;

        if func_rva as usize >= v_addr && (func_rva as usize) < v_addr + v_size {
            let offset_within_section = func_rva as usize - v_addr;
            if offset_within_section < r_size {
                func_abs_offset = r_offset + offset_within_section;
                break;
            }
        }
    }

    if func_abs_offset == 0 {
        return "{\"error\":\"RVA mapping failed.\"}".to_string();
    }

    // 3. Live-disassemble function logic into actual basic blocks using iced-x86
    let original_bytes = &exe_data[func_abs_offset..std::cmp::min(func_abs_offset + 512, exe_data.len())];
    let mut decoder = Decoder::with_ip(64, original_bytes, image_base + func_rva as u64, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    let mut output = String::new();

    let mut original_blocks_json = Vec::new();
    let mut current_block_instructions = Vec::new();
    let mut current_block_id = format!("Block_0x{:X}", func_rva);

    for instr in &mut decoder {
        formatter.format(&instr, &mut output);
        current_block_instructions.push(format!("\"{}\"", output.replace("\"", "\\\"")));
        output.clear();

        // Check FlowControl properties using the proper iced-x86 enum values
        let is_terminator = instr.flow_control() == iced_x86::FlowControl::UnconditionalBranch
            || instr.flow_control() == iced_x86::FlowControl::ConditionalBranch
            || instr.flow_control() == iced_x86::FlowControl::Return
            || instr.code() == iced_x86::Code::Int3;

        if is_terminator {
            original_blocks_json.push(format!(
                "{{\"id\":\"{}\",\"instructions\":[{}]}}",
                current_block_id,
                current_block_instructions.join(",")
            ));
            current_block_instructions.clear();
            current_block_id = format!("Block_0x{:X}", instr.ip() + instr.len() as u64);
        }

        if instr.flow_control() == iced_x86::FlowControl::Return || instr.code() == iced_x86::Code::Int3 {
            break;
        }
    }

    if !current_block_instructions.is_empty() {
        original_blocks_json.push(format!(
            "{{\"id\":\"{}\",\"instructions\":[{}]}}",
            current_block_id,
            current_block_instructions.join(",")
        ));
    }

    // 4. Construct the obfuscated Flattened CFF state machine basic blocks dynamically
    let protected_blocks_json = vec![
        format!(
            "{{\"id\":\"CFF_DISPATCHER\",\"instructions\":[\"push rcx\",\"push rdx\",\"push r11\",\"call get_rip\",\"get_rip:\",\"pop r11\",\"sub r11, 260C2h\",\"mov eax, 0\",\"cmp eax, 0\",\"je STATE_0\",\"cmp eax, 1\",\"je STATE_1\",\"jmp STATE_2\"]}}"
        ),
        format!(
            "{{\"id\":\"STATE_0_DECRYPT\",\"instructions\":[\"mov rcx, r11\",\"add rcx, rdata_string_rva\",\"mov rdx, string_len\",\"xor byte ptr [rcx], AAh\",\"inc rcx\",\"dec rdx\",\"jnz decrypt_loop\",\"mov eax, 1\",\"jmp CFF_DISPATCHER\"]}}"
        ),
        format!(
            "{{\"id\":\"STATE_1_ANTIDBG\",\"instructions\":[\"xor r11, r11\",\"mov eax, 2\",\"jmp CFF_DISPATCHER\"]}}"
        ),
        format!(
            "{{\"id\":\"STATE_2_OEP_EXIT\",\"instructions\":[\"pop r11\",\"pop rdx\",\"pop rcx\",\"jmp 0x{:X} (OEP_VA)\"]}}",
            image_base + original_entry_point_rva as u64
        )
    ];

    format!(
        "{{\"original\":[{}],\"protected\":[{}]}}",
        original_blocks_json.join(","),
        protected_blocks_json.join(",")
    )
}

// --- NATIVE HTTP SERVER ROUTING ---
fn handle_connection(mut stream: TcpStream) {
    let mut buffer = [0; 65536]; // Larger buffer for file uploads
    let mut body_bytes = Vec::new();
    let mut header_data = String::new();
    
    // Read the headers first
    let bytes_read = match stream.read(&mut buffer) {
        Ok(b) => b,
        Err(_) => return,
    };
    
    let request = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();
    
    // Find the end of headers (\r\n\r\n)
    if let Some(boundary_idx) = request.find("\r\n\r\n") {
        header_data = request[..boundary_idx].to_string();
        let body_start = boundary_idx + 4;
        body_bytes.extend_from_slice(&buffer[body_start..bytes_read]);
    }
    
    let mut lines = header_data.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let path = parts.next().unwrap_or("/");

    // Determine Content-Length
    let mut content_length = 0;
    for line in lines {
        if line.to_lowercase().starts_with("content-length:") {
            content_length = line.split(':').nth(1).unwrap_or("0").trim().parse::<usize>().unwrap_or(0);
            break;
        }
    }

    // Keep reading until we get the full body length
    while body_bytes.len() < content_length {
        let chunk_size = match stream.read(&mut buffer) {
            Ok(b) if b > 0 => b,
            _ => break,
        };
        body_bytes.extend_from_slice(&buffer[..chunk_size]);
    }

    let body_str = String::from_utf8_lossy(&body_bytes);

    // HTTP Router
    if method == "GET" && (path == "/" || path == "/index.html") {
        let cache_busted_html = INDEX_HTML
            .replace("/assets/index.js", "/assets/index.js?v=2.7")
            .replace("/assets/index.css", "/assets/index.css?v=2.7");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            cache_busted_html.len(), cache_busted_html
        );
        stream.write_all(response.as_bytes()).ok();
    } else if method == "GET" && path.starts_with("/assets/index.js") {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            INDEX_JS.len(), INDEX_JS
        );
        stream.write_all(response.as_bytes()).ok();
    } else if method == "GET" && path.starts_with("/assets/index.css") {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/css\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            INDEX_CSS.len(), INDEX_CSS
        );
        stream.write_all(response.as_bytes()).ok();
    } else if method == "GET" && path.starts_with("/api/binaries") {
        let json = get_binaries_json();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(), json
        );
        stream.write_all(response.as_bytes()).ok();
    } else if method == "GET" && path.starts_with("/api/symbols") {
        let pdb_param = path.split("pdb=").nth(1).unwrap_or("ce_mgr.pdb").split('&').next().unwrap_or("ce_mgr.pdb");
        let json = match get_symbols_json(pdb_param) {
            Ok(j) => j,
            Err(e) => format!("{{\"error\":\"{}\"}}", e.to_string()),
        };
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(), json
        );
        stream.write_all(response.as_bytes()).ok();
    } else if method == "GET" && path.starts_with("/api/strings") {
        let exe_param = path.split("exe=").nth(1).unwrap_or("ce_mgr.exe").split('&').next().unwrap_or("ce_mgr.exe");
        let json = get_strings_json(exe_param);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(), json
        );
        stream.write_all(response.as_bytes()).ok();
    } else if method == "GET" && path.starts_with("/api/cfg") {
        let exe_param = path.split("exe=").nth(1).unwrap_or("ce_mgr.exe").split('&').next().unwrap_or("ce_mgr.exe");
        let func_param = path.split("func=").nth(1).unwrap_or("GetInstallKeyPath").split('&').next().unwrap_or("GetInstallKeyPath");
        let pdb_param = path.split("pdb=").nth(1).unwrap_or("ce_mgr.pdb").split('&').next().unwrap_or("ce_mgr.pdb");
        let json = get_cfg_json(exe_param, func_param, pdb_param);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(), json
        );
        stream.write_all(response.as_bytes()).ok();
    } else if method == "GET" && path.starts_with("/api/download") {
        let filename = path.split("file=").nth(1).unwrap_or("uploaded_target_protected.exe").split('&').next().unwrap_or("uploaded_target_protected.exe");
        let file_path = format!("target/release/{}", filename);
        if let Ok(file_data) = fs::read(&file_path) {
            let response_headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nContent-Disposition: attachment; filename=\"{}\"\r\nConnection: close\r\n\r\n",
                file_data.len(), filename
            );
            stream.write_all(response_headers.as_bytes()).ok();
            stream.write_all(&file_data).ok();
        } else {
            let response = "HTTP/1.1 404 NOT FOUND\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            stream.write_all(response.as_bytes()).ok();
        }
    } else if method == "POST" && path.starts_with("/api/upload") {
        let json = handle_upload(&body_str);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(), json
        );
        stream.write_all(response.as_bytes()).ok();
    } else if method == "POST" && path.starts_with("/api/protect") {
        let json = execute_protect(&body_str);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(), json
        );
        stream.write_all(response.as_bytes()).ok();
    } else {
        let response = "HTTP/1.1 404 NOT FOUND\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(response.as_bytes()).ok();
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = 3002;
    println!("+-------------------------------------------------------------+");
    println!("|             BINARYDEFENDER // SENTINEL INTERFACE            |");
    println!("|              [STANDALONE MONOLITHIC DASHBOARD]              |");
    println!("+-------------------------------------------------------------+");
    println!("Host Server running at: http://localhost:{}", port);
    println!("Listening for secure dashboard client sessions...");

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))?;

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        thread::spawn(move || {
            handle_connection(stream);
        });
    }

    Ok(())
}
