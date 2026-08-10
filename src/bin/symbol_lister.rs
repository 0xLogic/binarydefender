use pdb::FallibleIterator;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let as_json = args.contains(&"--json".to_string());
    
    // Parse PDB path from args, or fallback to ce_mgr.pdb in local directory
    let mut pdb_path = "ce_mgr.pdb".to_string();
    for arg in args.iter().skip(1) {
        if arg != "--json" {
            pdb_path = arg.clone();
            break;
        }
    }
    
    let file = fs::File::open(&pdb_path)?;
    let mut pdb = pdb::PDB::open(file)?;
    
    let symbol_table = pdb.global_symbols()?;
    let address_map = pdb.address_map()?;
    
    let mut symbols = symbol_table.iter();
    
    if as_json {
        let mut json_items = Vec::new();
        while let Some(symbol) = symbols.next()? {
            match symbol.parse() {
                Ok(pdb::SymbolData::Public(data)) => {
                    let name = data.name.to_string();
                    let rva = data.offset.to_rva(&address_map);
                    if let Some(rva_val) = rva {
                        let escaped_name = name.replace("\"", "\\\"");
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
                        let escaped_name = name.replace("\"", "\\\"");
                        json_items.push(format!(
                            "{{\"type\":\"Procedure\",\"name\":\"{}\",\"rva\":\"0x{:X}\"}}",
                            escaped_name, rva_val.0
                        ));
                    }
                }
                _ => {}
            }
        }
        println!("[{}]", json_items.join(","));
    } else {
        println!("+-------------------------------------------------------------+");
        println!("|                   PDB SYMBOL LISTER TOOL                    |");
        println!("+-------------------------------------------------------------+");
        println!("Opening PDB: {}", pdb_path);
        println!("Listing first 100 public or procedure symbols found in PDB...");
        let mut count = 0;
        while let Some(symbol) = symbols.next()? {
            match symbol.parse() {
                Ok(pdb::SymbolData::Public(data)) => {
                    let name = data.name.to_string();
                    let rva = data.offset.to_rva(&address_map);
                    if let Some(rva_val) = rva {
                        println!("  [Public] Name: {:<40} | RVA: 0x{:X}", name, rva_val.0);
                        count += 1;
                    }
                }
                Ok(pdb::SymbolData::Procedure(data)) => {
                    let name = data.name.to_string();
                    let rva = data.offset.to_rva(&address_map);
                    if let Some(rva_val) = rva {
                        println!("  [Procedure] Name: {:<37} | RVA: 0x{:X}", name, rva_val.0);
                        count += 1;
                    }
                }
                _ => {}
            }
            if count >= 100 {
                break;
            }
        }
        println!("+-------------------------------------------------------------+");
    }

    Ok(())
}
