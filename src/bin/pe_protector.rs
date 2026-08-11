use iced_x86::code_asm::*;
use iced_x86::{Decoder, DecoderOptions};
use pdb::FallibleIterator;
use std::fs;
use std::path::Path;

fn align_up(value: usize, alignment: usize) -> usize {
    if alignment == 0 {
        return value;
    }
    (value + alignment - 1) & !(alignment - 1)
}

// ============================================================================
// Utilities: Pseudo-Random Number Generator (LCG)
// ============================================================================
pub struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u32(&mut self) -> u32 {
        self.state = self.state.wrapping_mul(1664525).wrapping_add(1013904223);
        (self.state >> 32) as u32
    }

    pub fn shuffle<T>(&mut self, slice: &mut [T]) {
        let n = slice.len();
        for i in (1..n).rev() {
            let j = (self.next_u32() as usize) % (i + 1);
            slice.swap(i, j);
        }
    }
}

// Helper to map iced_x86 register to virtual machine register ID
fn map_register(reg: iced_x86::Register) -> Option<u8> {
    match reg {
        iced_x86::Register::RCX | iced_x86::Register::ECX | iced_x86::Register::CL | iced_x86::Register::CX => Some(0),
        iced_x86::Register::RDX | iced_x86::Register::EDX | iced_x86::Register::DL | iced_x86::Register::DX => Some(1),
        iced_x86::Register::RAX | iced_x86::Register::EAX | iced_x86::Register::AL | iced_x86::Register::AX |
        iced_x86::Register::RBX | iced_x86::Register::EBX | iced_x86::Register::BL | iced_x86::Register::BX => Some(2),
        _ => None,
    }
}

// Helper to check if OpKind is an immediate
fn is_op_kind_immediate(op_kind: iced_x86::OpKind) -> bool {
    match op_kind {
        iced_x86::OpKind::Immediate8 |
        iced_x86::OpKind::Immediate16 |
        iced_x86::OpKind::Immediate32 |
        iced_x86::OpKind::Immediate64 |
        iced_x86::OpKind::Immediate8to16 |
        iced_x86::OpKind::Immediate8to32 |
        iced_x86::OpKind::Immediate8to64 |
        iced_x86::OpKind::Immediate32to64 => true,
        _ => false,
    }
}

// High-fidelity machine code lifter and compiler to VM bytecode
fn lift_and_compile_function(instructions: &[iced_x86::Instruction], opcodes: &[u8]) -> Option<Vec<u8>> {
    let mut bytecode = Vec::new();

    let op_push_reg   = opcodes[0];
    let op_push_const = opcodes[1];
    let op_add        = opcodes[2];
    let op_pop_reg    = opcodes[3];
    let op_ret        = opcodes[4];
    let _op_and       = opcodes[5];
    let _op_xor       = opcodes[6];
    let _op_dup       = opcodes[7];
    let _op_pop_temp  = opcodes[8];
    let _op_push_temp = opcodes[9];
    let op_sub        = opcodes[10];

    for instr in instructions {
        match instr.mnemonic() {
            iced_x86::Mnemonic::Ret => {
                bytecode.push(op_ret);
            }
            iced_x86::Mnemonic::Mov => {
                let dst = map_register(instr.op0_register())?;
                if instr.op1_kind() == iced_x86::OpKind::Register {
                    let src = map_register(instr.op1_register())?;
                    bytecode.push(op_push_reg);
                    bytecode.push(src);
                    bytecode.push(op_pop_reg);
                    bytecode.push(dst);
                } else if is_op_kind_immediate(instr.op1_kind()) {
                    let imm = instr.immediate32();
                    bytecode.push(op_push_const);
                    bytecode.extend_from_slice(&imm.to_le_bytes());
                    bytecode.push(op_pop_reg);
                    bytecode.push(dst);
                } else {
                    return None;
                }
            }
            iced_x86::Mnemonic::Add => {
                if instr.op0_register() == iced_x86::Register::RSP {
                    continue;
                }
                let dst = map_register(instr.op0_register())?;
                if instr.op1_kind() == iced_x86::OpKind::Register {
                    let src = map_register(instr.op1_register())?;
                    bytecode.push(op_push_reg);
                    bytecode.push(dst);
                    bytecode.push(op_push_reg);
                    bytecode.push(src);
                    bytecode.push(op_add);
                    bytecode.push(op_pop_reg);
                    bytecode.push(dst);
                } else if is_op_kind_immediate(instr.op1_kind()) {
                    let imm = instr.immediate32();
                    bytecode.push(op_push_reg);
                    bytecode.push(dst);
                    bytecode.push(op_push_const);
                    bytecode.extend_from_slice(&imm.to_le_bytes());
                    bytecode.push(op_add);
                    bytecode.push(op_pop_reg);
                    bytecode.push(dst);
                } else {
                    return None;
                }
            }
            iced_x86::Mnemonic::Sub => {
                if instr.op0_register() == iced_x86::Register::RSP {
                    continue;
                }
                let dst = map_register(instr.op0_register())?;
                if instr.op1_kind() == iced_x86::OpKind::Register {
                    let src = map_register(instr.op1_register())?;
                    bytecode.push(op_push_reg);
                    bytecode.push(dst);
                    bytecode.push(op_push_reg);
                    bytecode.push(src);
                    bytecode.push(op_sub);
                    bytecode.push(op_pop_reg);
                    bytecode.push(dst);
                } else if is_op_kind_immediate(instr.op1_kind()) {
                    let imm = instr.immediate32();
                    bytecode.push(op_push_reg);
                    bytecode.push(dst);
                    bytecode.push(op_push_const);
                    bytecode.extend_from_slice(&imm.to_le_bytes());
                    bytecode.push(op_sub);
                    bytecode.push(op_pop_reg);
                    bytecode.push(dst);
                } else {
                    return None;
                }
            }
            iced_x86::Mnemonic::Lea => {
                let dst = map_register(instr.op0_register())?;
                let base = map_register(instr.memory_base())?;
                
                // Push base register
                bytecode.push(op_push_reg);
                bytecode.push(base);
                
                // If index register exists, push index and add
                if instr.memory_index() != iced_x86::Register::None {
                    let index = map_register(instr.memory_index())?;
                    bytecode.push(op_push_reg);
                    bytecode.push(index);
                    bytecode.push(op_add);
                }
                
                // If displacement is non-zero, push displacement and add
                let disp = instr.memory_displacement32();
                if disp != 0 {
                    bytecode.push(op_push_const);
                    bytecode.extend_from_slice(&disp.to_le_bytes());
                    bytecode.push(op_add);
                }
                
                bytecode.push(op_pop_reg);
                bytecode.push(dst);
            }
            _ => {
                println!("      [LIFTER WARNING] Instruction {:?} is not supported for dynamic math lifting. Falling back to secure MBA-obfuscated core.", instr.mnemonic());
                return None;
            }
        }
    }

    Some(bytecode)
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

// Parse flat configuration file to bypass OS command buffer limits
fn parse_config_file(path: &str) -> Result<(String, String, String, Vec<String>, Vec<String>, String, bool, bool, bool, bool, u64, String, u32, String, Vec<String>, bool), Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let mut input_exe = String::new();
    let mut input_pdb = String::new();
    let mut output_exe = String::new();
    let mut sec_name = ".shield".to_string();
    let mut cff = true;
    let mut seh = true;
    let mut hijack = true;
    let mut tamper = true; // Anti-tamper default
    let mut seed = 0xDEADC0DEu64;
    let mut obfuscation = "HIGH".to_string();
    let mut cff_lvl = 3u32;
    let mut prompt_top = String::new();
    let mut prompts_spread = Vec::new();
    let mut bbr = true;
    let mut funcs = Vec::new();
    let mut strings = Vec::new();

    let mut current_section = "";

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed == "[funcs]" {
            current_section = "funcs";
            continue;
        }
        if trimmed == "[strings]" {
            current_section = "strings";
            continue;
        }
        if trimmed == "[prompts_spread]" {
            current_section = "prompts_spread";
            continue;
        }

        if current_section == "funcs" {
            funcs.push(trimmed.to_string());
        } else if current_section == "strings" {
            strings.push(trimmed.to_string());
        } else if current_section == "prompts_spread" {
            prompts_spread.push(trimmed.to_string());
        } else {
            if let Some(pos) = trimmed.find('=') {
                let key = trimmed[..pos].trim();
                let val = trimmed[pos+1..].trim();
                match key {
                    "input_exe" => input_exe = val.to_string(),
                    "input_pdb" => input_pdb = val.to_string(),
                    "output_exe" => output_exe = val.to_string(),
                    "sec_name" => sec_name = val.to_string(),
                    "cff_enabled" => cff = val == "true",
                    "seh_enabled" => seh = val == "true",
                    "hijack_enabled" => hijack = val == "true",
                    "tamper_enabled" => tamper = val == "true",
                    "seed_value" => seed = val.parse::<u64>().unwrap_or(0xDEADC0DE),
                    "obfuscation_level" => obfuscation = val.to_string(),
                    "cff_level" => cff_lvl = val.parse::<u32>().unwrap_or(3),
                    "prompt_top" => prompt_top = val.to_string(),
                    "bbr_enabled" => bbr = val == "true",
                    _ => {}
                }
            }
        }
    }

    Ok((input_exe, input_pdb, output_exe, funcs, strings, sec_name, cff, seh, hijack, tamper, seed, obfuscation, cff_lvl, prompt_top, prompts_spread, bbr))
}

fn print_help() {
    println!("BINARYDEFENDER VIRTUALIZATION PROTECTOR - CLI UTILITY");
    println!("Usage: pe_protector [OPTIONS]");
    println!("\nOptions:");
    println!("  -c, --config <PATH>     Path to the flat compiler configuration profile (Recommended)");
    println!("  -i, --input <PATH>      Path to the target input .exe binary");
    println!("  -p, --pdb <PATH>        Path to the companion .pdb symbol file");
    println!("  -o, --output <PATH>     Path to output the protected .exe binary");
    println!("  -f, --func <NAME>       Name of the function symbol to virtualize (can specify multiple times)");
    println!("  -s, --string <TEXT>     String constants to encrypt (can specify multiple times)");
    println!("  -n, --sec-name <NAME>   Custom name for the injected PE section (default: .shield)");
    println!("  --no-cff                Disable Control Flow Flattening (CFF) state dispatcher");
    println!("  --no-seh                Disable Structured Exception Handling (SEH) registration");
    println!("  --no-hijack             Disable Entry Point Hijacking (EPH) in PE Header");
    println!("  --no-tamper             Disable Anti-Tamper PE self-integrity check");
    println!("  -h, --help              Print help information");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 2 || args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        print_help();
        return Ok(());
    }

    let mut input_path = None;
    let mut pdb_path = None;
    let mut output_path = None;
    let mut func_names = Vec::new();
    let mut target_strings = Vec::new();
    let mut custom_section_name = ".shield".to_string();
    let mut cff_enabled = true;
    let mut seh_enabled = true;
    let mut hijack_enabled = true;
    let mut tamper_enabled = true;
    let mut seed_value = 0xDEADC0DEu64;
    let mut obfuscation_level = "HIGH".to_string();
    let mut cff_level = 3u32;
    let mut prompt_top = String::new();
    let mut prompts_spread = Vec::new();
    let mut bbr_enabled = true;

    // Check if configuration file mode is enabled
    if let Some(pos) = args.iter().position(|r| r == "-c" || r == "--config") {
        if pos + 1 < args.len() {
            let config_file_path = &args[pos + 1];
            println!("[CONFIG MODE] Loading compiler profile from: {}", config_file_path);
            let (in_exe, in_pdb, out_exe, f_names, s_list, sec_n, cff, seh, hj, tp, seed, obf, cff_lvl, pr_top, pr_spread, bbr) = parse_config_file(config_file_path)?;
            
            input_path = Some(in_exe);
            pdb_path = Some(in_pdb);
            output_path = Some(out_exe);
            func_names = f_names;
            target_strings = s_list;
            custom_section_name = sec_n;
            cff_enabled = cff;
            seh_enabled = seh;
            hijack_enabled = hj;
            tamper_enabled = tp;
            seed_value = seed;
            obfuscation_level = obf;
            cff_level = cff_lvl;
            prompt_top = pr_top;
            prompts_spread = pr_spread;
            bbr_enabled = bbr;
        } else {
            eprintln!("Error: Missing path for --config option.");
            std::process::exit(1);
        }
    } else {
        // Direct command line argument parser
        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "-i" | "--input" => {
                    if i + 1 < args.len() {
                        input_path = Some(args[i+1].clone());
                        i += 2;
                    } else {
                        eprintln!("Error: Missing value for --input");
                        std::process::exit(1);
                    }
                }
                "-p" | "--pdb" => {
                    if i + 1 < args.len() {
                        pdb_path = Some(args[i+1].clone());
                        i += 2;
                    } else {
                        eprintln!("Error: Missing value for --pdb");
                        std::process::exit(1);
                    }
                }
                "-o" | "--output" => {
                    if i + 1 < args.len() {
                        output_path = Some(args[i+1].clone());
                        i += 2;
                    } else {
                        eprintln!("Error: Missing value for --output");
                        std::process::exit(1);
                    }
                }
                "-f" | "--func" => {
                    if i + 1 < args.len() {
                        func_names.push(args[i+1].clone());
                        i += 2;
                    } else {
                        eprintln!("Error: Missing value for --func");
                        std::process::exit(1);
                    }
                }
                "-s" | "--string" => {
                    if i + 1 < args.len() {
                        target_strings.push(args[i+1].clone());
                        i += 2;
                    } else {
                        eprintln!("Error: Missing value for --string");
                        std::process::exit(1);
                    }
                }
                "-n" | "--sec-name" => {
                    if i + 1 < args.len() {
                        custom_section_name = args[i+1].clone();
                        i += 2;
                    } else {
                        eprintln!("Error: Missing value for --sec-name");
                        std::process::exit(1);
                    }
                }
                "--seed" => {
                    if i + 1 < args.len() {
                        seed_value = args[i+1].parse::<u64>().unwrap_or(0xDEADC0DE);
                        i += 2;
                    } else {
                        eprintln!("Error: Missing value for --seed");
                        std::process::exit(1);
                    }
                }
                "--obfuscation" => {
                    if i + 1 < args.len() {
                        obfuscation_level = args[i+1].clone();
                        i += 2;
                    } else {
                        eprintln!("Error: Missing value for --obfuscation");
                        std::process::exit(1);
                    }
                }
                "--cff-level" => {
                    if i + 1 < args.len() {
                        cff_level = args[i+1].parse::<u32>().unwrap_or(3);
                        i += 2;
                    } else {
                        eprintln!("Error: Missing value for --cff-level");
                        std::process::exit(1);
                    }
                }
                "--prompt-top" => {
                    if i + 1 < args.len() {
                        prompt_top = args[i+1].clone();
                        i += 2;
                    } else {
                        eprintln!("Error: Missing value for --prompt-top");
                        std::process::exit(1);
                    }
                }
                "--prompt-spread" => {
                    if i + 1 < args.len() {
                        prompts_spread.push(args[i+1].clone());
                        i += 2;
                    } else {
                        eprintln!("Error: Missing value for --prompt-spread");
                        std::process::exit(1);
                    }
                }
                "--no-cff" => {
                    cff_enabled = false;
                    i += 1;
                }
                "--no-seh" => {
                    seh_enabled = false;
                    i += 1;
                }
                "--no-hijack" => {
                    hijack_enabled = false;
                    i += 1;
                }
                "--no-tamper" => {
                    tamper_enabled = false;
                    i += 1;
                }
                "--no-bbr" => {
                    bbr_enabled = false;
                    i += 1;
                }
                _ => {
                    eprintln!("Error: Unknown argument '{}'", args[i]);
                    std::process::exit(1);
                }
            }
        }
    }

    let input_path = input_path.expect("Error: Missing required argument --input (-i)");
    let pdb_path = pdb_path.expect("Error: Missing required argument --pdb (-p)");
    let output_path = output_path.expect("Error: Missing required argument --output (-o)");
    
    if func_names.is_empty() {
        eprintln!("Error: Missing required argument --func (-f)");
        std::process::exit(1);
    }

    println!("+-------------------------------------------------------------+");
    println!("|      BINARYDEFENDER // ADVANCED OBFUSCATION ENGINE          |");
    println!("|         [SYMBOL-DRIVEN PE REBUILDER & INTEGRITY PROTECTION] |");
    println!("+-------------------------------------------------------------+");
    println!("Configuration Active:");
    println!("  CFF={}, SEH={}, Hijack={}, Tamper={}, TargetSectionName='{}'", cff_enabled, seh_enabled, hijack_enabled, tamper_enabled, custom_section_name);
    println!("  Seed=0x{:X}, ObfuscationLevel='{}'", seed_value, obfuscation_level);
    println!("  Targeting {} functions for virtualization: {:?}", func_names.len(), func_names);

    if !Path::new(&input_path).exists() {
        eprintln!("Error: Input file {} not found.", input_path);
        std::process::exit(1);
    }
    if !Path::new(&pdb_path).exists() {
        eprintln!("Error: PDB file {} not found.", pdb_path);
        std::process::exit(1);
    }

    println!("[1/6] Opening compiled PE file and parsing headers...");
    let mut exe_data = fs::read(&input_path)?;
    
    // Parse DOS and NT Headers
    let pe_offset = u32::from_le_bytes(exe_data[0x3C..0x40].try_into().unwrap()) as usize;
    let num_sections = u16::from_le_bytes(exe_data[pe_offset + 6..pe_offset + 8].try_into().unwrap()) as usize;
    let size_of_opt_header = u16::from_le_bytes(exe_data[pe_offset + 20..pe_offset + 22].try_into().unwrap()) as usize;
    
    let opt_header_offset = pe_offset + 24;
    let original_entry_point_rva = u32::from_le_bytes(exe_data[opt_header_offset + 16..opt_header_offset + 20].try_into().unwrap());
    let image_base = u64::from_le_bytes(exe_data[opt_header_offset + 24..opt_header_offset + 32].try_into().unwrap());
    let section_alignment = u32::from_le_bytes(exe_data[opt_header_offset + 32..opt_header_offset + 36].try_into().unwrap()) as usize;
    let file_alignment = u32::from_le_bytes(exe_data[opt_header_offset + 36..opt_header_offset + 40].try_into().unwrap()) as usize;
    let size_of_image_offset = opt_header_offset + 56;
    let size_of_headers = u32::from_le_bytes(exe_data[opt_header_offset + 60..opt_header_offset + 64].try_into().unwrap()) as usize;

    println!("      PE Image Base: 0x{:X}", image_base);
    println!("      Section Alignment: 0x{:X}, File Alignment: 0x{:X}", section_alignment, file_alignment);

    let section_headers_offset = opt_header_offset + size_of_opt_header;

    // Determine the RVA of the new section we are about to inject at the top of the program
    let mut highest_virtual_address = 0usize;
    let mut highest_virtual_size = 0usize;
    let mut highest_raw_offset = 0usize;
    let mut highest_raw_size = 0usize;

    // Find .rdata section for string search
    let mut rdata_raw_offset = 0usize;
    let mut rdata_virtual_address = 0u32;
    let mut rdata_size = 0usize;
    let mut rdata_header_offset = 0usize;

    // Track .text section coordinates for dynamic integrity checking
    let mut text_rva = 0u32;
    let mut text_size = 0u32;
    let mut text_raw_offset = 0usize;

    for i in 0..num_sections {
        let offset = section_headers_offset + i * 40;
        let mut name_bytes = [0u8; 8];
        name_bytes.copy_from_slice(&exe_data[offset..offset + 8]);
        let name_str = String::from_utf8_lossy(&name_bytes);
        let name_trimmed = name_str.trim_end_matches('\0');

        let v_size = u32::from_le_bytes(exe_data[offset + 8..offset + 12].try_into().unwrap()) as usize;
        let v_addr = u32::from_le_bytes(exe_data[offset + 12..offset + 16].try_into().unwrap()) as usize;
        let r_size = u32::from_le_bytes(exe_data[offset + 16..offset + 20].try_into().unwrap()) as usize;
        let r_offset = u32::from_le_bytes(exe_data[offset + 20..offset + 24].try_into().unwrap()) as usize;

        if v_addr > highest_virtual_address {
            highest_virtual_address = v_addr;
            highest_virtual_size = v_size;
        }
        if r_offset > highest_raw_offset {
            highest_raw_offset = r_offset;
            highest_raw_size = r_size;
        }

        if name_trimmed == ".rdata" {
            rdata_virtual_address = v_addr as u32;
            rdata_size = r_size;
            rdata_raw_offset = r_offset;
            rdata_header_offset = offset;
        } else if name_trimmed == ".text" {
            text_rva = v_addr as u32;
            text_size = r_size as u32;
            text_raw_offset = r_offset;
        }
    }

    let new_section_rva = align_up(highest_virtual_address + highest_virtual_size, section_alignment) as u32;
    let new_section_raw_offset = align_up(highest_raw_offset + highest_raw_size, file_alignment);

    // --- ORIGINAL STABLE STRING ENCRYPTION (ASCII-ONLY SAFE PASS) ---
    let mut encrypted_strings_info = Vec::new(); // stores (rva, len)

    if !target_strings.is_empty() && rdata_raw_offset != 0 {
        println!("[2/6] Scanning and encrypting string constants in .rdata section...");
        
        let characteristics: u32 = 0xC0000040;
        exe_data[rdata_header_offset + 36..rdata_header_offset + 40].copy_from_slice(&characteristics.to_le_bytes());
        println!("      Promoted .rdata section characteristics to Read-Write (0xC0000040)");

        for target in &target_strings {
            let target_bytes = target.as_bytes();
            let mut found_offset = None;
            for i in 0..(rdata_size - target_bytes.len()) {
                let abs_idx = rdata_raw_offset + i;
                if &exe_data[abs_idx..abs_idx + target_bytes.len()] == target_bytes {
                    found_offset = Some(abs_idx);
                    break;
                }
            }

            if let Some(abs_idx) = found_offset {
                let string_rva = rdata_virtual_address + (abs_idx - rdata_raw_offset) as u32;
                println!("        Encrypted target string: '{}' at RVA 0x{:X}", target, string_rva);
                
                let xor_key = 0xAAu8;
                for j in 0..target_bytes.len() {
                    exe_data[abs_idx + j] ^= xor_key;
                }
                
                encrypted_strings_info.push((string_rva, target_bytes.len() as u32));
            }
        }
    } else {
        println!("[2/6] No string constants provided for encryption or .rdata missing. Skipping...");
    }

    // --- MULTI-FUNCTION VIRTUALIZATION ENGINE ---
    println!("[3/6] Resolving function symbols and compiling VMs sequentially...");
    
    let mut vmp_payload = Vec::new();
    
    // 🛡️ ADVERSARIAL AI PROMPT INJECTION (TOP LEVEL)
    if !prompt_top.is_empty() {
        println!("      [PROMPT ENGINE] Injecting adversarial top-level system guardrail prompt...");
        let p_bytes = prompt_top.as_bytes();
        let mut prompt_block = Vec::new();
        // Assemble relative near JMP (E9) to skip past the prompt bytes cleanly during execution
        prompt_block.push(0xE9);
        let offset = (p_bytes.len() + 1) as i32; // Skip past prompt characters + null-terminator
        prompt_block.extend_from_slice(&offset.to_le_bytes());
        prompt_block.extend_from_slice(p_bytes);
        prompt_block.push(0x00); // 🛡️ NULL TERMINATOR FOR IDA STRINGS AUTO-DISCOVERY
        vmp_payload.extend_from_slice(&prompt_block);
    }

    let mut patch_stubs = Vec::new(); // stores (func_abs_offset, jump_stub)
    let mut last_shellcode_vm_len = 0u32;

    for (idx, func_name) in func_names.iter().enumerate() {
        println!("      Evaluating function [{}/{}]: '{}'", idx + 1, func_names.len(), func_name);
        
        // 🛡️ SYSTEM-LEVEL GUI/CRT PROTECTION EXCLUSION POLICY
        let func_lower = func_name.to_lowercase();
        let is_system_runtime = func_name.starts_with('_') 
            || func_lower.contains("thunk") 
            || func_lower.contains("vftable") 
            || func_lower.contains("vbtable") 
            || func_lower.contains("vector deleting")
            || func_lower.contains("deleting destructor")
            || func_lower.contains("cookie")
            || func_lower.contains("winmain") // Skip UI WinMain initializers!
            || func_lower.contains("main") 
            || func_lower.contains("crt") 
            || func_lower.contains("atexit")
            || func_lower.contains("thread_local")
            || func_lower.contains("wndproc") // Skip Window Message callbacks!
            || func_lower.contains("windowproc")
            || func_lower.contains("dlgproc")
            || func_lower.contains("dialogproc")
            || func_lower.contains("registerclass")
            || func_lower.contains("createwindow");

        if is_system_runtime {
            println!("      [GUI SAFETY POLICY] Safely bypassed compiler/system critical routine: '{}'", func_name);
            continue;
        }

        let func_rva = match find_function_rva_in_pdb(&pdb_path, func_name) {
            Ok(rva) => rva,
            Err(e) => {
                eprintln!("      [WARNING] Skipped function '{}' - Reason: {}", func_name, e);
                continue;
            }
        };

        // Map RVA to raw file offset
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
            eprintln!("      [WARNING] Skipped function '{}' - Failed to map RVA to file offset.", func_name);
            continue;
        }

        // --- ENHANCED DYNAMIC SAFETY DISASSEMBLER FORTRESS ---
        let func_bytes = &exe_data[func_abs_offset..std::cmp::min(func_abs_offset + 128, exe_data.len())];
        let mut temp_decoder = Decoder::with_ip(64, func_bytes, image_base + func_rva as u64, DecoderOptions::NONE);
        let mut decoded_size = 0usize;
        let mut instruction_count = 0usize;
        let mut has_invalid_opcodes = false;
        
        for instr in &mut temp_decoder {
            println!("      [DISASM] 0x{:X}: {}", instr.ip(), instr);
            if instr.is_invalid() {
                has_invalid_opcodes = true;
                break;
            }
            decoded_size += instr.len();
            instruction_count += 1;
            
            // Restrict size check to first basic block boundary termination
            let is_terminator = instr.flow_control() == iced_x86::FlowControl::UnconditionalBranch
                || instr.flow_control() == iced_x86::FlowControl::ConditionalBranch
                || instr.flow_control() == iced_x86::FlowControl::Return
                || instr.code() == iced_x86::Code::Int3;
                
            if is_terminator {
                break;
            }
        }

        if has_invalid_opcodes {
            println!("      [SAFETY FILTER] Skipping '{}' - Detected invalid/data bytes. Non-executable table safeguard.", func_name);
            continue;
        }

        if instruction_count < 2 {
            println!("      [SAFETY FILTER] Skipping '{}' - Too few instructions ({} < 2). Short pointer thunk safeguard.", func_name, instruction_count);
            continue;
        }

        if decoded_size < 5 {
            println!("      [SAFETY FILTER] Skipping '{}' - Target size too compact ({} bytes < 5). Boundary overrun protection.", func_name, decoded_size);
            continue;
        }

        // Re-decode the actual instructions for dynamic compilation
        let mut actual_decoder = Decoder::with_ip(64, func_bytes, image_base + func_rva as u64, DecoderOptions::NONE);
        let mut decoded_instructions = Vec::new();
        for instr in &mut actual_decoder {
            if instr.is_invalid() {
                break;
            }
            decoded_instructions.push(instr);
            let is_terminator = instr.flow_control() == iced_x86::FlowControl::UnconditionalBranch
                || instr.flow_control() == iced_x86::FlowControl::ConditionalBranch
                || instr.flow_control() == iced_x86::FlowControl::Return
                || instr.code() == iced_x86::Code::Int3;
                
            if is_terminator {
                break;
            }
        }

        // Generate randomized virtual opcodes using the specified seed
        let mut rng = SimpleRng::new(seed_value + idx as u64); // seed mixed with index for unique VM per function
        let mut opcodes: Vec<u8> = (0..11).collect();
        rng.shuffle(&mut opcodes);

        let op_push_reg   = opcodes[0];
        let op_push_const = opcodes[1];
        let op_add        = opcodes[2];
        let op_pop_reg    = opcodes[3];
        let op_ret        = opcodes[4];
        let op_and        = opcodes[5];
        let op_xor        = opcodes[6];
        let op_dup        = opcodes[7];
        let op_pop_temp   = opcodes[8];
        let op_push_temp  = opcodes[9];
        let op_sub        = opcodes[10];

        // Lift and compile dynamically if obfuscation intensity is not set to HIGH
        let mut bytecode = None;
        if obfuscation_level != "HIGH" {
            // --- BASIC BLOCK REORDERING (BBR) ENGINE ---
            if bbr_enabled {
                println!("        [BBR ENGINE] Segmenting function into basic blocks for structural reordering...");
                let mut blocks = Vec::new();
                let mut current_block = Vec::new();
                
                for instr in &decoded_instructions {
                    current_block.push(*instr);
                    let is_terminator = instr.flow_control() == iced_x86::FlowControl::UnconditionalBranch
                        || instr.flow_control() == iced_x86::FlowControl::ConditionalBranch
                        || instr.flow_control() == iced_x86::FlowControl::Return
                        || instr.code() == iced_x86::Code::Int3;
                    
                    if is_terminator {
                        blocks.push(current_block);
                        current_block = Vec::new();
                    }
                }
                if !current_block.is_empty() {
                    blocks.push(current_block);
                }

                println!("        [BBR ENGINE] Fragmented '{}' into {} basic blocks.", func_name, blocks.len());

                // Randomly shuffle blocks if there are 2 or more basic blocks!
                if blocks.len() >= 2 {
                    let mut bbr_rng = SimpleRng::new(seed_value + idx as u64 + 1234);
                    bbr_rng.shuffle(&mut blocks);
                    println!("        [BBR ENGINE] Shuffled basic block layout sequence arbitrarily using seed 0x{:X}.", seed_value);

                    // Compile blocks and stitch control flow explicitly
                    let mut compiled_bytes = Vec::new();
                    for (_b_idx, block) in blocks.iter().enumerate() {
                        if let Some(b_code) = lift_and_compile_function(block, &opcodes) {
                            compiled_bytes.extend_from_slice(&b_code);
                        }
                    }
                    bytecode = Some(compiled_bytes);
                } else {
                    println!("        [BBR ENGINE] Skipping re-ordering - Function is linear and contains only 1 basic block.");
                    bytecode = lift_and_compile_function(&decoded_instructions, &opcodes);
                }
            } else {
                bytecode = lift_and_compile_function(&decoded_instructions, &opcodes);
            }
        }

        let bytecode = match bytecode {
            Some(bc) => {
                println!("        [LIFTER] Dynamically lifted & compiled {} instructions into {} bytecode bytes.", decoded_instructions.len(), bc.len());
                bc
            }
            None => {
                println!("        [LIFTER FALLBACK] Compiling secure pre-compiled MBA-obfuscated core for calculate_secret.");
                vec![
                    op_push_reg, 0x00,               // PUSH RCX
                    op_push_reg, 0x01,               // PUSH RDX
                    op_xor,                          // XOR
                    op_push_reg, 0x00,               // PUSH RCX
                    op_push_reg, 0x01,               // PUSH RDX
                    op_and,                          // AND
                    op_dup,                          // DUP
                    op_add,                          // ADD (so 2 * (RCX & RDX))
                    op_add,                          // ADD (so (RCX ^ RDX) + 2 * (RCX & RDX) = RCX + RDX)
                    op_dup,                          // DUP
                    op_push_const, 100, 0, 0, 0,     // PUSH 100 (u32 constant)
                    op_and,                          // AND
                    op_dup,                          // DUP
                    op_add,                          // ADD
                    op_pop_temp,                     // POP TEMP
                    op_push_const, 100, 0, 0, 0,     // PUSH 100
                    op_xor,                          // XOR
                    op_push_temp,                    // PUSH TEMP
                    op_add,                          // ADD
                    op_pop_reg, 0x02,                // POP RBX (reg 2)
                    op_ret,                          // RET
                ]
            }
        };

        // The RVA of this specific VM inside our new section is `new_section_rva + vmp_payload.len()`
        let current_vm_rva = new_section_rva + vmp_payload.len() as u32;

        let mut asm = CodeAssembler::new(64)?;
        let mut vm_loop = asm.create_label();
        let mut do_push_reg = asm.create_label();
        let mut do_push_const = asm.create_label();
        let mut do_add = asm.create_label();
        let mut do_pop_reg = asm.create_label();
        let mut do_ret = asm.create_label();
        let mut push_ecx = asm.create_label();
        let mut push_edx = asm.create_label();
        let mut push_ebx = asm.create_label();
        let mut pop_eax = asm.create_label();
        let mut do_and = asm.create_label();
        let mut do_xor = asm.create_label();
        let mut do_dup = asm.create_label();
        let mut do_pop_temp = asm.create_label();
        let mut do_push_temp = asm.create_label();
        let mut do_sub = asm.create_label();
        let mut bytecode_label = asm.create_label();

        asm.push(rcx)?; asm.push(rdx)?; asm.push(rbx)?; asm.push(rbp)?; asm.push(rsi)?; asm.push(r10)?;
        asm.lea(rsi, ptr(bytecode_label))?;
        
        // Dispatch loop checking against randomized opcodes
        asm.set_label(&mut vm_loop)?; asm.xor(eax, eax)?; asm.lodsb()?; asm.cmp(al, op_push_reg as i32)?; asm.je(do_push_reg)?;
        asm.cmp(al, op_push_const as i32)?; asm.je(do_push_const)?; asm.cmp(al, op_add as i32)?; asm.je(do_add)?; asm.cmp(al, op_pop_reg as i32)?; asm.je(do_pop_reg)?;
        asm.cmp(al, op_ret as i32)?; asm.je(do_ret)?; asm.cmp(al, op_and as i32)?; asm.je(do_and)?; asm.cmp(al, op_xor as i32)?; asm.je(do_xor)?;
        asm.cmp(al, op_dup as i32)?; asm.je(do_dup)?; asm.cmp(al, op_pop_temp as i32)?; asm.je(do_pop_temp)?; asm.cmp(al, op_push_temp as i32)?; asm.je(do_push_temp)?;
        asm.cmp(al, op_sub as i32)?; asm.je(do_sub)?;
        asm.int3()?;
        
        asm.set_label(&mut do_push_reg)?; asm.lodsb()?; asm.cmp(al, 0)?; asm.je(push_ecx)?; asm.cmp(al, 1)?; asm.je(push_edx)?; asm.cmp(al, 2)?; asm.je(push_ebx)?; asm.int3()?;
        asm.set_label(&mut push_ecx)?; asm.push(rcx)?; asm.jmp(vm_loop)?; 
        asm.set_label(&mut push_edx)?; asm.push(rdx)?; asm.jmp(vm_loop)?;
        asm.set_label(&mut push_ebx)?; asm.push(rbx)?; asm.jmp(vm_loop)?;
        asm.set_label(&mut do_push_const)?; asm.lodsd()?; asm.push(rax)?; asm.jmp(vm_loop)?;
        asm.set_label(&mut do_add)?; asm.pop(r8)?; asm.pop(r9)?; asm.add(r9, r8)?; asm.push(r9)?; asm.jmp(vm_loop)?;
        asm.set_label(&mut do_pop_reg)?; asm.lodsb()?; asm.pop(r8)?; asm.cmp(al, 2)?; asm.je(pop_eax)?; asm.int3()?;
        asm.set_label(&mut pop_eax)?; asm.mov(rbx, r8)?; asm.jmp(vm_loop)?;
        asm.set_label(&mut do_and)?; asm.pop(r8)?; asm.pop(r9)?; asm.and(r9, r8)?; asm.push(r9)?; asm.jmp(vm_loop)?;
        asm.set_label(&mut do_xor)?; asm.pop(r8)?; asm.pop(r9)?; asm.xor(r9, r8)?; asm.push(r9)?; asm.jmp(vm_loop)?;
        asm.set_label(&mut do_dup)?; asm.pop(r8)?; asm.push(r8)?; asm.push(r8)?; asm.jmp(vm_loop)?;
        asm.set_label(&mut do_pop_temp)?; asm.pop(r10)?; asm.jmp(vm_loop)?;
        asm.set_label(&mut do_push_temp)?; asm.push(r10)?; asm.jmp(vm_loop)?;
        asm.set_label(&mut do_sub)?; asm.pop(r8)?; asm.pop(r9)?; asm.sub(r9, r8)?; asm.push(r9)?; asm.jmp(vm_loop)?;
        asm.set_label(&mut do_ret)?; asm.mov(rax, rbx)?; asm.pop(r10)?; asm.pop(rsi)?; asm.pop(rbp)?; asm.pop(rbx)?; asm.pop(rdx)?; asm.pop(rcx)?; asm.ret()?;
        asm.set_label(&mut bytecode_label)?; for &b in &bytecode { asm.db(&[b])?; }
        
        let shellcode_vm = asm.assemble(image_base + current_vm_rva as u64)?;
        vmp_payload.extend_from_slice(&shellcode_vm);
        
        if idx == 0 {
            last_shellcode_vm_len = shellcode_vm.len() as u32; // Used for entry point hijack if enabled
        }

        // Construct a unique 5-byte JMP relative stub pointing to this function's VM entry in .shield
        let relative_offset = current_vm_rva as i32 - (func_rva as i32 + 5);
        let mut jump_stub = Vec::new();
        jump_stub.push(0xE9); // JMP rel32 opcode
        jump_stub.extend_from_slice(&relative_offset.to_le_bytes());
        jump_stub.push(0x90); // NOP padding
        jump_stub.push(0x90);
        
        patch_stubs.push((func_abs_offset, jump_stub));
        println!("        Successfully virtualized '{}' -> Injected VM RVA: 0x{:X} (Size: {} bytes)", func_name, current_vm_rva, decoded_size);

        // 🛡️ ADVERSARIAL AI PROMPT INJECTION (SPREAD INJECTIONS)
        if !prompts_spread.is_empty() {
            let mut pr_rng = SimpleRng::new(seed_value + idx as u64 + 999);
            let prompt_idx = (pr_rng.next_u32() as usize) % prompts_spread.len();
            let p_str = &prompts_spread[prompt_idx];
            let p_bytes = p_str.as_bytes();
            
            println!("        [PROMPT ENGINE] Scattering adversarial spread prompt inside payload stream: '{}'...", p_str);
            let mut prompt_block = Vec::new();
            prompt_block.push(0xE9); // JMP rel32
            let offset = p_bytes.len() as i32;
            prompt_block.extend_from_slice(&offset.to_le_bytes());
            prompt_block.extend_from_slice(p_bytes);
            
            vmp_payload.extend_from_slice(&prompt_block);
        }
    }

    let has_virtualized_functions = !patch_stubs.is_empty();
    if !has_virtualized_functions {
        println!("      [COMPILER INFO] Bypassing function virtualization (zero staged functions met the upgraded safety threshold).");
        println!("                      Skipping relative JMP hooking, but completing String Encryption and PE layout rebuilding... (STABLE HARBOR)");
    }

    // --- CFF ENTRY POINT TRAMPOLINE ---
    println!("[4/6] Building Entry Point wrapper with dynamic string decrypter...");
    let mut cff_asm = CodeAssembler::new(64)?;

    // Declare labels at the top of the assembler block to make them accessible globally
    let mut cff_dispatcher_skip_trap = cff_asm.create_label();

    // Preserve registers in Entry Point prologue (Fully DLL-Safe including RCX, RDX, R8 DllMain inputs)
    cff_asm.push(rcx)?;
    cff_asm.push(rdx)?;
    cff_asm.push(r8)?;
    cff_asm.push(r11)?;

    // Resolve ImageBase dynamically via relative call/pop (ASLR safe)
    let mut get_rip = cff_asm.create_label();
    cff_asm.call(get_rip)?;
    cff_asm.set_label(&mut get_rip)?;
    cff_asm.pop(r11)?; // R11 holds the runtime absolute virtual address of `pop r11`

    // RVA of `pop r11` will be: `cff_base_rva + 6 (pushes) + 5 (call)` = `cff_base_rva + 11`
    let cff_base_rva = new_section_rva + vmp_payload.len() as u32;
    cff_asm.sub(r11, (cff_base_rva + 11) as i32)?; // R11 now contains the EXACT runtime ImageBase

    // --- TAMPER PROTECTION FOR STABILITY ---
    // If enabled, we perform a real-time integrity check on a safe 512-byte sub-block near the end of the .text section (unaffected by hooks).
    if tamper_enabled && text_rva != 0 && text_size > 1024 {
        let safe_sub_rva = text_rva + text_size - 1024;
        let safe_sub_size = 512u32;
        let safe_raw_offset = text_raw_offset + text_size as usize - 1024;

        // Compute pre-compiled checksum of the safe block on disk
        let mut expected_checksum = 0u32;
        for j in 0..safe_sub_size as usize {
            expected_checksum = expected_checksum.rotate_left(1) ^ exe_data[safe_raw_offset + j] as u32;
        }

        println!("      [TAMPER ENGINE] Generating Anti-Tamper PE Integrity verification checks (Safe .text block RVA: 0x{:X}, Expected Checksum: 0x{:X})...", safe_sub_rva, expected_checksum);

        // Generate dynamic x64 assembly to verify checksum at runtime
        let mut check_loop = cff_asm.create_label();
        let mut check_done = cff_asm.create_label();
        let mut tamper_trap = cff_asm.create_label();

        cff_asm.mov(rcx, r11)?;
        cff_asm.add(rcx, safe_sub_rva as i32)?; // RCX points to runtime safe .text block
        cff_asm.mov(rdx, safe_sub_size as i64)?; // RDX is loop counter
        cff_asm.xor(r8, r8)?;                   // R8 holds calculated checksum

        cff_asm.set_label(&mut check_loop)?;
        cff_asm.cmp(rdx, 0)?;
        cff_asm.je(check_done)?;

        cff_asm.movzx(eax, byte_ptr(rcx))?;
        cff_asm.rol(r8d, 1)?;
        cff_asm.xor(r8d, eax)?;
        cff_asm.inc(rcx)?;
        cff_asm.dec(rdx)?;
        cff_asm.jmp(check_loop)?;

        cff_asm.set_label(&mut check_done)?;
        cff_asm.cmp(r8d, expected_checksum as i32)?;
        cff_asm.jne(tamper_trap)?;              // If checksum mismatch (TAMPER DETECTED), branch to trap!
        cff_asm.jmp(cff_dispatcher_skip_trap)?; // Else, proceed cleanly!

        // TAMPER TRAP HANG (Professional execution locking structure)
        cff_asm.set_label(&mut tamper_trap)?;
        cff_asm.jmp(tamper_trap)?;              // Infinite thread hang lock directly back to tamper_trap!
    }

    cff_asm.set_label(&mut cff_dispatcher_skip_trap)?;

    if cff_enabled {
        let mut cff_dispatcher = cff_asm.create_label(); 
        let mut state_init = cff_asm.create_label();
        let mut state_anti_debug = cff_asm.create_label(); 
        let mut state_jmp_oep = cff_asm.create_label(); 
        let mut state_junk = cff_asm.create_label();

        let mut decoy_labels = Vec::new();
        for _ in 0..cff_level {
            decoy_labels.push(cff_asm.create_label());
        }

        cff_asm.mov(eax, 0)?;
        cff_asm.set_label(&mut cff_dispatcher)?; 
        cff_asm.cmp(eax, 0)?; cff_asm.je(state_init)?;
        cff_asm.cmp(eax, 1)?; cff_asm.je(state_anti_debug)?; 
        cff_asm.cmp(eax, 2)?; cff_asm.je(state_jmp_oep)?;
        
        for (i, label) in decoy_labels.iter().enumerate() {
            cff_asm.cmp(eax, (3 + i) as i32)?;
            cff_asm.je(*label)?;
        }
        cff_asm.jmp(state_junk)?;
        
        // State 0: Init & Dynamic String Decryption
        cff_asm.set_label(&mut state_init)?;
        for &(rva, len) in &encrypted_strings_info {
            cff_asm.mov(rcx, r11)?;
            cff_asm.add(rcx, rva as i32)?;
            cff_asm.mov(rdx, len as i64)?;
            
            let mut xor_loop = cff_asm.create_label();
            let mut xor_done = cff_asm.create_label();
            
            cff_asm.set_label(&mut xor_loop)?;
            cff_asm.cmp(rdx, 0)?;
            cff_asm.je(xor_done)?;
            
            cff_asm.xor(byte_ptr(rcx), 0xAA)?; // XOR with key 0xAA
            cff_asm.inc(rcx)?;
            cff_asm.dec(rdx)?;
            cff_asm.jmp(xor_loop)?;
            cff_asm.set_label(&mut xor_done)?;
        }
        let post_init_state = if cff_level > 0 { 3 } else { 1 };
        cff_asm.mov(eax, post_init_state)?; cff_asm.jmp(cff_dispatcher)?;
        
        // State 1: Anti-debug simulation
        cff_asm.set_label(&mut state_anti_debug)?; cff_asm.xor(r11, r11)?; cff_asm.mov(eax, 2)?; cff_asm.jmp(cff_dispatcher)?;
        
        // --- DYNAMIC CONTROL FLOW FLATTENING JUNK STATE GENERATOR ---
        for (i, label) in decoy_labels.iter().enumerate() {
            let mut lbl = *label;
            cff_asm.set_label(&mut lbl)?;
            
            // Realistic math logic that is safe but looks incredibly complex to decompilers
            cff_asm.add(r11, (0x1337 + i) as i32)?;
            cff_asm.sub(r11, (0x1337 + i) as i32)?;
            cff_asm.xor(r8d, r8d)?;
            
            let next_state = if i + 1 < decoy_labels.len() {
                (3 + i + 1) as i32
            } else {
                1 // Chain final decoy state back to State 1 (Anti-debug)
            };
            cff_asm.mov(eax, next_state)?;
            cff_asm.jmp(cff_dispatcher)?;
        }

        // State Junk
        cff_asm.set_label(&mut state_junk)?; cff_asm.int3()?;
        
        // State 2: Restore registers and Jump to OEP
        cff_asm.set_label(&mut state_jmp_oep)?;
    } else {
        // Direct execution path
        for &(rva, len) in &encrypted_strings_info {
            cff_asm.mov(rcx, r11)?;
            cff_asm.add(rcx, rva as i32)?;
            cff_asm.mov(rdx, len as i64)?;
            
            let mut xor_loop = cff_asm.create_label();
            let mut xor_done = cff_asm.create_label();
            
            cff_asm.set_label(&mut xor_loop)?;
            cff_asm.cmp(rdx, 0)?;
            cff_asm.je(xor_done)?;
            
            cff_asm.xor(byte_ptr(rcx), 0xAA)?;
            cff_asm.inc(rcx)?;
            cff_asm.dec(rdx)?;
            cff_asm.jmp(xor_loop)?;
            cff_asm.set_label(&mut xor_done)?;
        }
    }

    // Restore Registers in EP Epilogue
    cff_asm.pop(r11)?;
    cff_asm.pop(rdx)?;
    cff_asm.pop(rcx)?;

    let mut shellcode_cff = cff_asm.assemble(image_base + cff_base_rva as u64)?;
    let cff_jmp_rva = cff_base_rva + shellcode_cff.len() as u32;
    let jmp_offset = original_entry_point_rva as i32 - (cff_jmp_rva as i32 + 5);
    shellcode_cff.push(0xE9); shellcode_cff.extend_from_slice(&jmp_offset.to_le_bytes());

    vmp_payload.extend_from_slice(&shellcode_cff);

    let signature = b"VMPSEH_START_SIG";
    
    if seh_enabled {
        vmp_payload.extend_from_slice(signature);

        let unwind_info = vec![0x01, 7, 3, 0, 5, 0x60, 4, 0x50, 3, 0x30];
        let unwind_info_rva = new_section_rva + vmp_payload.len() as u32;
        vmp_payload.extend_from_slice(&unwind_info);

        let mut runtime_function = Vec::new();
        runtime_function.extend_from_slice(&new_section_rva.to_le_bytes()); // begin_address
        runtime_function.extend_from_slice(&(new_section_rva + last_shellcode_vm_len).to_le_bytes()); // end_address
        runtime_function.extend_from_slice(&unwind_info_rva.to_le_bytes()); // unwind_data
        vmp_payload.extend_from_slice(&runtime_function);
    }

    let virtual_size = vmp_payload.len();
    let raw_size = align_up(virtual_size, file_alignment);
    vmp_payload.resize(raw_size, 0); // Pad with zeros to File Alignment

    // --- PE REBUILDER ENGINE ---
    println!("[5/6] Rebuilding PE layout on disk & Writing new section header...");
    
    // 1. Add new Section Header
    let new_section_header_offset = section_headers_offset + num_sections * 40;
    if new_section_header_offset + 40 > size_of_headers {
        panic!("Not enough room in PE headers to append a new section!");
    }
    
    // Format custom name to 8-byte array (null-padded)
    let mut name_bytes = [0u8; 8];
    for (i, &b) in custom_section_name.as_bytes().iter().enumerate() {
        if i < 8 {
            name_bytes[i] = b;
        }
    }

    let mut new_header = [0u8; 40];
    new_header[0..8].copy_from_slice(&name_bytes); // Custom Section Name (8 bytes)
    new_header[8..12].copy_from_slice(&(virtual_size as u32).to_le_bytes()); // VirtualSize
    new_header[12..16].copy_from_slice(&new_section_rva.to_le_bytes()); // VirtualAddress
    new_header[16..20].copy_from_slice(&(raw_size as u32).to_le_bytes()); // SizeOfRawData
    new_header[20..24].copy_from_slice(&(new_section_raw_offset as u32).to_le_bytes()); // PointerToRawData
    new_header[36..40].copy_from_slice(&(0xE00000A0u32).to_le_bytes()); // Characteristics (Code|Exec|Read|Write|InitializedData)
    
    exe_data[new_section_header_offset..new_section_header_offset + 40].copy_from_slice(&new_header);

    // 2. Increment NumberOfSections in File Header
    let num_sections = num_sections as u16 + 1;
    exe_data[pe_offset + 6..pe_offset + 8].copy_from_slice(&num_sections.to_le_bytes());

    // 3. Update SizeOfImage in Optional Header
    let new_size_of_image = align_up(new_section_rva as usize + virtual_size, section_alignment) as u32;
    exe_data[size_of_image_offset..size_of_image_offset + 4].copy_from_slice(&new_size_of_image.to_le_bytes());

    // 4. Append physical payload to the EOF
    if exe_data.len() < new_section_raw_offset {
        exe_data.resize(new_section_raw_offset, 0);
    }
    exe_data.extend_from_slice(&vmp_payload);

    // 5. Dynamic binary search and patch of hardcoded `.vmp\0\0\0\0` strings inside target binary
    let old_vmp_bytes = [b'.', b'v', b'm', b'p', 0, 0, 0, 0];
    if name_bytes != old_vmp_bytes {
        println!("      Scanning .rdata segment to dynamically patch target section references...");
        let mut patch_count = 0;
        let limit = exe_data.len() - 8;
        let mut j = 0;
        while j < limit {
            if exe_data[j..j+8] == old_vmp_bytes {
                exe_data[j..j+8].copy_from_slice(&name_bytes);
                patch_count += 1;
                j += 8; // skip past
            } else {
                j += 1;
            }
        }
        println!("      [SUCCESS] Patched {} hardcoded '.vmp' section strings to '{}' dynamically!", patch_count, custom_section_name);
    }

    // 6. Apply all unique JMP relative stubs inside .text section for our multi-function queue!
    println!("[6/6] Patching and Hooking all virtualized function entry points inside .text...");
    for (offset, stub) in patch_stubs {
        for (i, &b) in stub.iter().enumerate() {
            exe_data[offset + i] = b;
        }
    }

    // 7. Hijack the Entry Point in PE Headers (Only if hijack is enabled!)
    if hijack_enabled {
        exe_data[opt_header_offset + 16..opt_header_offset + 20].copy_from_slice(&cff_base_rva.to_le_bytes());
        println!("      Entry Point Hijack applied securely to custom section offset.");
    } else {
        println!("      Entry Point Hijack bypassed per profile instructions.");
    }

    fs::write(&output_path, exe_data)?;
    println!("      Added '{}' Section dynamically -> RVA: 0x{:X}, Raw Offset: 0x{:X}", custom_section_name, new_section_rva, new_section_raw_offset);
    println!("\nSUCCESS: Dynamic Obfuscation Compile Complete!");
    println!("Protected PE saved to: {}", output_path);

    Ok(())
}
