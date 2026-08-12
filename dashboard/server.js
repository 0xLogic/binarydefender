import express from 'express';
import cors from 'cors';
import { exec, execFile } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const app = express();
const PORT = 3001;

app.use(cors());
app.use(express.json());

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Helper to determine the target release folder dynamically
let targetReleaseDir = path.resolve(__dirname, '../target/release');
let projectRootDir = path.resolve(__dirname, '..');

// Fallback auto-detection if target/release is missing
if (!fs.existsSync(targetReleaseDir)) {
    // Check if the current workspace root has it or fallback to the local folder
    if (fs.existsSync(path.resolve(__dirname, '.'))) {
        targetReleaseDir = path.resolve(__dirname, '.');
    }
}

// Accept command line argument to set directory: --dir <path> or -d <path>
const args = process.argv.slice(2);
for (let i = 0; i < args.length; i++) {
    if (args[i] === '--dir' || args[i] === '-d') {
        if (args[i + 1]) {
            targetReleaseDir = path.resolve(args[i + 1]);
        } else {
            console.error('Error: --dir or -d requires a directory path.');
            process.exit(1);
        }
    }
}

console.log(`[SENTINEL DASHBOARD] Using target binary directory: ${targetReleaseDir}`);

// Helper to extract printable ASCII strings from any binary file
function extractPrintableStrings(filePath, minLength = 6) {
    try {
        const buffer = fs.readFileSync(filePath);
        const strings = [];
        let current = [];
        
        for (let i = 0; i < buffer.length; i++) {
            const char = buffer[i];
            // Printable ASCII characters are from 32 (space) to 126 (~)
            if (char >= 32 && char <= 126) {
                current.push(String.fromCharCode(char));
            } else {
                if (current.length >= minLength) {
                    strings.push(current.join(''));
                }
                current = [];
            }
        }
        
        // Filter out obvious garbage and return unique strings
        const filtered = strings
            .map(s => s.trim())
            .filter(s => s.length >= minLength && /^[a-zA-Z0-9_\[]/.test(s));
            
        return [...new Set(filtered)];
    } catch (err) {
        console.error("Error reading binary for strings:", err);
        return [];
    }
}

// 1. GET: Available protected binaries and PDBs
app.get('/api/binaries', (req, res) => {
    try {
        const files = fs.readdirSync(targetReleaseDir);
        const binaries = files
            .filter(f => f.endsWith('.exe'))
            .map(exe => {
                const name = path.basename(exe, '.exe');
                const hasPdb = files.includes(`${name}.pdb`);
                return {
                    exeName: exe,
                    pdbName: hasPdb ? `${name}.pdb` : null,
                    fullExePath: path.join(targetReleaseDir, exe),
                    fullPdbPath: hasPdb ? path.join(targetReleaseDir, `${name}.pdb`) : null,
                };
            })
            .filter(item => item.pdbName !== null); // only return files with a companion PDB

        res.json(binaries);
    } catch (err) {
        res.status(500).json({ error: "Failed to scan target/release directory." });
    }
});

// 2. GET: List PDB symbols using our symbol lister Rust tool
app.get('/api/symbols', (req, res) => {
    const symbolListerPath = path.join(targetReleaseDir, 'symbol_lister.exe');
    const pdbName = req.query.pdb || 'ce_mgr.pdb';
    const absolutePdbPath = path.join(targetReleaseDir, pdbName);
    
    // Execute the compiled Rust symbol_lister with the target PDB and --json
    execFile(symbolListerPath, [absolutePdbPath, '--json'], { cwd: targetReleaseDir, maxBuffer: 10 * 1024 * 1024 }, (error, stdout, stderr) => {
        if (error) {
            console.error("Exec error:", error);
            return res.status(500).json({ error: "Failed to parse symbols using symbol_lister.", details: stderr });
        }
        try {
            // Locate the start of the JSON block (symbol_lister prints "[{...}]")
            const startIdx = stdout.indexOf('[');
            const endIdx = stdout.lastIndexOf(']') + 1;
            if (startIdx === -1 || endIdx === 0) {
                return res.status(500).json({ error: "No JSON output found from symbol_lister." });
            }
            const jsonStr = stdout.substring(startIdx, endIdx);
            const symbols = JSON.parse(jsonStr);
            res.json(symbols);
        } catch (err) {
            res.status(500).json({ error: "Failed to parse symbols JSON.", details: err.message });
        }
    });
});

// 3. GET: List printable strings from the selected executable
app.get('/api/strings', (req, res) => {
    const exeName = req.query.exe || 'ce_mgr.exe';
    const exePath = path.join(targetReleaseDir, exeName);
    
    if (!fs.existsSync(exePath)) {
        return res.status(404).json({ error: `Binary ${exeName} not found.` });
    }
    
    const strings = extractPrintableStrings(exePath);
    res.json(strings);
});

// 4. POST: Execute pe_protector on chosen symbol and strings
app.post('/api/protect', (req, res) => {
    const { exeName, pdbName, funcName, strings, encryptAll, cffEnabled, sehEnabled, hijackEnabled } = req.body;
    
    if (!exeName || !pdbName || !funcName) {
        return res.status(400).json({ error: "Missing required parameters: exeName, pdbName, funcName" });
    }
    
    const inputExe = path.join(targetReleaseDir, exeName);
    const inputPdb = path.join(targetReleaseDir, pdbName);
    const outputExe = path.join(targetReleaseDir, `${path.basename(exeName, '.exe')}_protected.exe`);
    
    // Build pe_protector CLI command arguments
    let cmd = `cargo run --bin pe_protector -- -i "${inputExe}" -p "${inputPdb}" -o "${outputExe}" -f "${funcName}"`;
    
    if (cffEnabled === false) cmd += " --no-cff";
    if (sehEnabled === false) cmd += " --no-seh";
    if (hijackEnabled === false) cmd += " --no-hijack";
    
    if (encryptAll) {
        // Mocking ALL strings by passing a broad set or telling the server to fetch them
        const allStrings = extractPrintableStrings(inputExe).slice(0, 15); // limit to 15 for safety/performance
        for (const s of allStrings) {
            cmd += ` -s "${s.replace(/"/g, '\\"')}"`;
        }
    } else if (strings && Array.isArray(strings)) {
        for (const s of strings) {
            cmd += ` -s "${s.replace(/"/g, '\\"')}"`;
        }
    }
    
    console.log("Executing protect command:", cmd);
    
    exec(cmd, { cwd: projectRootDir }, (error, stdout, stderr) => {
        res.json({
            success: !error,
            stdout,
            stderr,
            outputPath: outputExe
        });
    });
});

app.listen(PORT, () => {
    console.log(`[BinaryDefender Express API] Running on http://localhost:${PORT}`);
});
