use std::env;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RuntimeFunction {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_data: u32,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleA(lpModuleName: *const u8) -> *mut std::ffi::c_void;
    fn RtlAddFunctionTable(
        FunctionTable: *const RuntimeFunction,
        EntryCount: u32,
        BaseAddress: u64,
    ) -> u8;
}

// Statically define the .vmp section in the compiled binary so the PE headers
// are automatically generated with correct size, offsets, and alignment.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".vmp")]
pub static mut VMP_SECTION: [u8; 4096] = [0; 4096];

#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn calculate_secret(a: u32, b: u32) -> u32 {
    let mut x = a;
    x += b;
    x += 100;
    x
}

// Dynamically walks our own loaded PE headers to find and register the injected .vmp SEH tables
fn register_vmp_seh() {
    println!("[SEH Setup] Scanning loaded PE image for injected exception tables...");
    
    // Statically declare the target section name as an 8-byte continuous constant
    // This allows the pe_protector to safely overwrite it on disk with any custom name!
    let target_section_name = ".vmp\0\0\0\0";
    let target_bytes = target_section_name.as_bytes();

    unsafe {
        let base_addr = GetModuleHandleA(std::ptr::null()) as u64;
        if base_addr == 0 {
            println!("[SEH Setup] Failed to get module base address.");
            return;
        }

        // Parse DOS Header (MZ)
        let dos_header = base_addr as *const u8;
        if *dos_header != b'M' || *dos_header.add(1) != b'Z' {
            return;
        }

        // Parse NT Headers (PE signature offset is at 0x3C)
        let pe_offset = *(dos_header.add(0x3C) as *const u32) as usize;
        let nt_headers = dos_header.add(pe_offset);
        
        let signature = *(nt_headers as *const u32);
        if signature != 0x00004550 { // "PE\0\0"
            return;
        }

        // File Header is at nt_headers + 4
        let num_sections = *(nt_headers.add(4 + 2) as *const u16);
        let size_of_opt_header = *(nt_headers.add(4 + 16) as *const u16) as usize;

        // Section Headers are located immediately after Optional Header
        let section_headers_start = nt_headers.add(24 + size_of_opt_header);

        for i in 0..num_sections {
            let section_ptr = section_headers_start.add(i as usize * 40);
            
            // Read 8-byte section name
            let mut name_bytes = [0u8; 8];
            std::ptr::copy_nonoverlapping(section_ptr, name_bytes.as_mut_ptr(), 8);

            // Compare section name with our dynamic target bytes (supporting custom names!)
            if name_bytes == target_bytes {
                let virtual_address = *(section_ptr.add(12) as *const u32);
                let virtual_size = *(section_ptr.add(8) as *const u32);
                println!("      Found target section! RVA: 0x{:X}, Virtual Size: 0x{:X}", virtual_address, virtual_size);

                // Scan the section memory for our unique SEH signature: "VMPSEH_START_SIG"
                let section_start_ptr = (base_addr + virtual_address as u64) as *const u8;
                let signature_bytes = b"VMPSEH_START_SIG";
                
                for offset in 0..(virtual_size as usize - signature_bytes.len() - 12) {
                    let candidate_ptr = section_start_ptr.add(offset);
                    let mut matched = true;
                    for j in 0..signature_bytes.len() {
                        if *candidate_ptr.add(j) != signature_bytes[j] {
                            matched = false;
                            break;
                        }
                    }

                    if matched {
                        let table_ptr = candidate_ptr.add(signature_bytes.len()) as *const RuntimeFunction;
                        println!("      Found injected exception table signature inside target section!");
                        println!("      Registering Dynamic RUNTIME_FUNCTION at: {:?}", table_ptr);
                        
                        let result = RtlAddFunctionTable(table_ptr, 1, base_addr);
                        if result != 0 {
                            println!("      [SUCCESS] Injected exception tables registered successfully with Windows!");
                        } else {
                            println!("      [FAILED] RtlAddFunctionTable returned error.");
                        }
                        return;
                    }
                }
            }
        }
        println!("[SEH Setup] No matching section or exception table signature found. Executing normally.");
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let val_a = if args.len() > 1 { args[1].parse().unwrap_or(10) } else { 10 };
    let val_b = if args.len() > 2 { args[2].parse().unwrap_or(20) } else { 20 };
    
    // Attempt dynamic SEH registration if the custom section exists (injected by protector)
    register_vmp_seh();

    println!("[Dummy Target] Executing MSVC x64 binary...");
    let result = calculate_secret(val_a, val_b);
    println!("[Dummy Target] Result of secret calculation: {}", result);
}
