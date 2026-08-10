import React, { useState, useEffect } from 'react';

export default function App() {
  const [binaries, setBinaries] = useState([]);
  const [selectedBinary, setSelectedBinary] = useState(null);
  
  // Repositories (Fetched from backend)
  const [symbols, setSymbols] = useState([]);
  const [strings, setStrings] = useState([]);
  
  // Selected Queues (Staged by user via '+')
  const [stagedSymbols, setStagedSymbols] = useState([]);
  const [stagedStrings, setStagedStrings] = useState([]);
  
  // UI Customization State
  const [theme, setTheme] = useState(() => localStorage.getItem('sentinel_theme') || 'DARK');
  const [activeTab, setActiveTab] = useState('WORKSPACE'); // 'WORKSPACE', 'CFG_VISUALIZER', 'ASSEMBLY_VIEW'
  
  // Help Modal Toggle State
  const [isHelpOpen, setIsHelpOpen] = useState(false);

  // IDA Pro Workspace Column 1 Tabs
  const [idaRepositoryTab, setIdaRepositoryTab] = useState('FUNCTIONS'); // 'FUNCTIONS' or 'STRINGS'

  // Selected Function for Active CFG Rendering
  const [cfgActiveFunc, setCfgActiveFunc] = useState('');

  // Protection Options (Column 3 Toggles)
  const [cffEnabled, setCffEnabled] = useState(true);
  const [sehEnabled, setSehEnabled] = useState(true);
  const [hijackEnabled, setHijackEnabled] = useState(true);
  const [tamperEnabled, setTamperEnabled] = useState(true); // Expose dynamic tamper toggle!
  const [obfuscationLevel, setObfuscationLevel] = useState('HIGH'); // 'LOW', 'MEDIUM', 'HIGH'
  const [encryptMode, setEncryptMode] = useState('SPECIFIC'); // Default to SPECIFIC (Manual Queue) for 100% stability!
  const [secName, setSecName] = useState('.shield'); // Default section name to .shield!
  
  // Dynamic Entry Point RVAs
  const [originalEntryPoint, setOriginalEntryPoint] = useState('0x17900');
  const [hijackedEntryPoint, setHijackedEntryPoint] = useState('0x260B9');

  // Live CFG Disassembly States
  const [cfgOriginalBlocks, setCfgOriginalBlocks] = useState([]);
  const [cfgProtectedBlocks, setCfgProtectedBlocks] = useState([]);
  const [cfgError, setCfgError] = useState('');
  const [isCfgLoading, setIsCfgLoading] = useState(false);

  // Search Filters
  const [symbolSearch, setSymbolSearch] = useState('');
  const [stringSearch, setStringSearch] = useState('');
  
  // Drag & Drop / Uploading states
  const [uploadStatus, setUploadStatus] = useState('');
  const [isUploading, setIsProtectingUploading] = useState(false);

  // Compiling Log states
  const [isProtecting, setIsProtecting] = useState(false);
  const [logs, setLogs] = useState('');
  const [success, setSuccess] = useState(null);
  const [downloadFileName, setDownloadFileName] = useState('');

  // Real-Time Compiler Progress States
  const [successCount, setSuccessCount] = useState(0);

  // Relative API routing since both static site and endpoints are served by the same Rust binary!
  const API_BASE = '/api';

  // Helper to dynamically compute instruction offsets under ASLR
  const formatOffset = (baseHex, offset) => {
    try {
      const cleanHex = baseHex.startsWith('0x') ? baseHex.substring(2) : baseHex;
      const base = parseInt(cleanHex, 16);
      return (base + offset).toString(16).toUpperCase().padStart(8, '0');
    } catch (e) {
      return '00000000';
    }
  };

  // Toggle body theme class and persist to localStorage
  useEffect(() => {
    localStorage.setItem('sentinel_theme', theme);
    if (theme === 'LIGHT') {
      document.body.classList.add('light-theme');
    } else {
      document.body.classList.remove('light-theme');
    }
  }, [theme]);

  const loadBinaries = () => {
    fetch(`${API_BASE}/binaries`)
      .then(res => res.json())
      .then(data => {
        setBinaries(data);
        if (data.length > 0) {
          const activeBin = data.find(b => b.exeName.includes('uploaded_target')) || data[0];
          setSelectedBinary(activeBin);
        }
      })
      .catch(err => console.error("Error loading binaries:", err));
  };

  // Load binaries on startup
  useEffect(() => {
    loadBinaries();
  }, []);

  // Fetch symbols and strings on binary change + Restore saved settings
  useEffect(() => {
    if (!selectedBinary) return;

    // Fetch Symbols
    fetch(`${API_BASE}/symbols?pdb=${selectedBinary.pdbName}`)
      .then(res => res.json())
      .then(data => {
        const cleanSymbols = data.filter(s => 
          !s.name.includes('std::') && 
          !s.name.includes('nlohmann::') &&
          !s.name.includes('ImGui') &&
          !s.name.startsWith('__')
        );
        setSymbols(cleanSymbols);
        
        // Restore settings for this specific binary from localStorage
        const saved = localStorage.getItem(`sentinel_settings_${selectedBinary.exeName}`);
        if (saved) {
          try {
            const config = JSON.parse(saved);
            setStagedSymbols(config.stagedSymbols || []);
            setStagedStrings(config.stagedStrings || []);
            setCffEnabled(config.cffEnabled !== undefined ? config.cffEnabled : true);
            setSehEnabled(config.sehEnabled !== undefined ? config.sehEnabled : true);
            setHijackEnabled(config.hijackEnabled !== undefined ? config.hijackEnabled : true);
            setTamperEnabled(config.tamperEnabled !== undefined ? config.tamperEnabled : true); // Restore tamper toggle!
            setObfuscationLevel(config.obfuscationLevel || 'HIGH');
            setEncryptMode(config.encryptMode || 'SPECIFIC');
            
            // Dynamic cache migration: upgrade legacy '.vmp' to '.shield'
            const savedSecName = config.secName || '.shield';
            setSecName(savedSecName === '.vmp' ? '.shield' : savedSecName);
          } catch (e) {
            console.error("Error parsing saved config:", e);
          }
        } else {
          // Defaults if no config saved
          setStagedSymbols([]);
          setStagedStrings([]);
          setCffEnabled(true);
          setSehEnabled(true);
          setHijackEnabled(true);
          setTamperEnabled(true);
          setObfuscationLevel('HIGH');
          setEncryptMode('SPECIFIC');
          setSecName('.shield');
        }
      })
      .catch(err => console.error("Error loading symbols:", err));

    // Fetch Strings
    fetch(`${API_BASE}/strings?exe=${selectedBinary.exeName}`)
      .then(res => res.json())
      .then(data => setStrings(data))
      .catch(err => console.error("Error loading strings:", err));

    setLogs('');
    setSuccess(null);
    setDownloadFileName('');
    setSuccessCount(0);

  }, [selectedBinary]);

  // Handle active CFG selection synchronization
  useEffect(() => {
    if (stagedSymbols.length > 0 && !stagedSymbols.includes(cfgActiveFunc)) {
      setCfgActiveFunc(stagedSymbols[0]);
    }
  }, [stagedSymbols]);

  // Fetch live disassembled CFG when the CFG Tab is opened or when the selected CFG function changes
  useEffect(() => {
    if (activeTab !== 'CFG_VISUALIZER' || !selectedBinary || !cfgActiveFunc) {
      setCfgOriginalBlocks([]);
      setCfgProtectedBlocks([]);
      return;
    }

    setIsCfgLoading(true);
    setCfgError('');

    fetch(`${API_BASE}/cfg?exe=${selectedBinary.exeName}&func=${cfgActiveFunc}&pdb=${selectedBinary.pdbName}`)
      .then(res => res.json())
      .then(data => {
        if (data.error) {
          setCfgError(data.error);
        } else {
          setCfgOriginalBlocks(data.original || []);
          setCfgProtectedBlocks(data.protected || []);
        }
      })
      .catch(err => setCfgError(`Fatal connection error: ${err.message}`))
      .finally(() => setIsCfgLoading(false));

  }, [activeTab, selectedBinary, cfgActiveFunc]);

  // Persist settings whenever staged elements or compiler options change
  useEffect(() => {
    if (!selectedBinary) return;
    
    const config = {
      stagedSymbols,
      stagedStrings,
      cffEnabled,
      sehEnabled,
      hijackEnabled,
      tamperEnabled, // Persist tamper Enabled!
      obfuscationLevel,
      encryptMode,
      secName // Persist custom section name!
    };
    localStorage.setItem(`sentinel_settings_${selectedBinary.exeName}`, JSON.stringify(config));
  }, [stagedSymbols, stagedStrings, cffEnabled, sehEnabled, hijackEnabled, tamperEnabled, obfuscationLevel, encryptMode, secName, selectedBinary]);

  // File Drag & Drop Handlers
  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDrop = async (e) => {
    e.preventDefault();
    e.stopPropagation();
    
    const files = Array.from(e.dataTransfer.files);
    const exeFile = files.find(f => f.name.endsWith('.exe'));
    const pdbFile = files.find(f => f.name.endsWith('.pdb'));

    if (!exeFile || !pdbFile) {
      setUploadStatus('ERROR: Staging failed. You must drop BOTH an .exe and .pdb file together!');
      return;
    }

    setIsProtectingUploading(true);
    setUploadStatus(`STAGING: '${exeFile.name}' & '${pdbFile.name}'...`);

    try {
      const readFileAsHex = (file) => {
        return new Promise((resolve, reject) => {
          const reader = new FileReader();
          reader.onload = (event) => {
            const arr = new Uint8Array(event.target.result);
            let hex = '';
            for (let i = 0; i < arr.length; i++) {
              hex += arr[i].toString(16).padStart(2, '0');
            }
            resolve(hex);
          };
          reader.onerror = reject;
          reader.readAsArrayBuffer(file);
        });
      };

      const exeHex = await readFileAsHex(exeFile);
      const pdbHex = await readFileAsHex(pdbFile);

      setUploadStatus('TRANSMITTING: Syncing file streams to Sentinel Core...');

      const res = await fetch(`${API_BASE}/upload`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          exeName: exeFile.name,
          exeHex,
          pdbName: pdbFile.name,
          pdbHex
        })
      });

      const data = await res.json();
      if (data.success) {
        setUploadStatus('SUCCESS: Files synchronized and registered.');
        loadBinaries();
      } else {
        setUploadStatus(`ERROR: ${data.error || 'Registration failed.'}`);
      }
    } catch (err) {
      setUploadStatus(`ERROR: ${err.message}`);
    } finally {
      setIsProtectingUploading(false);
    }
  };

  // Staging handlers
  const addSymbolToQueue = (symName) => {
    if (!stagedSymbols.includes(symName)) {
      setStagedSymbols([...stagedSymbols, symName]); // Staging multiple functions!
    }
  };

  const removeSymbolFromQueue = (symName) => {
    setStagedSymbols(stagedSymbols.filter(s => s !== symName));
  };

  const addStringToQueue = (str) => {
    if (!stagedStrings.includes(str)) {
      setStagedStrings([...stagedStrings, str]);
    }
  };

  const removeStringFromQueue = (str) => {
    setStagedStrings(stagedStrings.filter(s => s !== str));
  };

  const handleProtect = async () => {
    if (!selectedBinary || stagedSymbols.length === 0) {
      alert("Please stage at least one symbol function (+) to virtualize.");
      return;
    }

    setIsProtecting(true);
    setLogs("[SENTINEL CORE] Initializing dynamic PE section stretching pass...\n[SENTINEL CORE] Parsing compiled symbols and compiling IR to virtual instructions sequentially...\n");
    setSuccess(null);
    setDownloadFileName('');
    setSuccessCount(0);

    try {
      const response = await fetch(`${API_BASE}/protect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          exeName: selectedBinary.exeName,
          pdbName: selectedBinary.pdbName,
          funcNames: stagedSymbols, // Send multiple functions as array!
          strings: stagedStrings,
          encryptAll: encryptMode === 'ALL',
          cffEnabled,
          sehEnabled,
          hijackEnabled,
          tamperEnabled, // Pass tamper status!
          secName // Send custom section name to backend!
        })
      });

      const result = await response.json();
      
      let finalLogs = "";
      if (result.stdout) finalLogs += result.stdout;
      if (result.stderr) finalLogs += "\n[COMPILER STDERR]\n" + result.stderr;
      
      setLogs(prev => prev + finalLogs);
      setSuccess(result.success);
      if (result.success && result.outputFileName) {
        setDownloadFileName(result.outputFileName);
      }
      if (result.success && result.originalEntryPoint && result.hijackedEntryPoint) {
        // Sync PE compiler RVAs to disassembly headers dynamically!
        setOriginalEntryPoint(result.originalEntryPoint);
        setHijackedEntryPoint(result.hijackedEntryPoint);
      }

      // Count the successfully virtualized functions from logs to drive the SVG progress ring!
      const matches = finalLogs.match(/Successfully virtualized/g);
      if (matches) {
        setSuccessCount(matches.length);
      } else if (result.success) {
        setSuccessCount(stagedSymbols.length); // Fallback
      }
    } catch (err) {
      setLogs(prev => prev + `\n[FATAL ERROR] Compile pipeline aborted: ${err.message}`);
      setSuccess(false);
    } finally {
      setIsProtecting(false);
    }
  };

  const filteredSymbols = symbols.filter(s => 
    s.name.toLowerCase().includes(symbolSearch.toLowerCase())
  );

  const filteredStrings = strings.filter(s => 
    s.toLowerCase().includes(stringSearch.toLowerCase())
  );

  // Dynamic Percentage calculations for functions transformed
  const totalStaged = stagedSymbols.length;
  const transformPercentage = totalStaged > 0 ? Math.round((successCount / totalStaged) * 100) : 0;

  // SVG Progress Arc calculation variables
  const radius = 36;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (transformPercentage / 100) * circumference;

  return (
    <div style={{ padding: '20px', maxWidth: '1600px', margin: '0 auto', height: '100vh', display: 'flex', flexDirection: 'column' }}>
      
      {/* HUD HEADER */}
      <header className="dashed-box" style={{ padding: '12px 20px', marginBottom: '10px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ color: 'var(--sentinel-blue)', fontSize: '22px', letterSpacing: '2px', textTransform: 'uppercase' }}>
            BINARYDEFENDER // SENTINEL COMPILER DASHBOARD
          </h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '11px', marginTop: '3px' }}>
            SYMBOL-DRIVEN WINDOWS PE x64 MULTI-FUNCTION PROTECTION PLATFORM
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div>
            <span style={{ color: 'var(--text-muted)', fontSize: '11px', marginRight: '6px' }}>CORE ENGINE:</span>
            <span style={{ color: 'var(--sentinel-blue)', fontSize: '12px' }}>
              {selectedBinary ? selectedBinary.exeName : 'AWAITING SELECTION...'}
            </span>
          </div>
          
          {/* THEME TOGGLE BUTTON */}
          <button 
            onClick={() => setTheme(theme === 'DARK' ? 'LIGHT' : 'DARK')}
            style={{
              background: 'transparent',
              border: '1px dashed var(--border-blue)',
              color: 'var(--sentinel-blue)',
              padding: '6px 12px',
              cursor: 'pointer',
              fontFamily: 'Share Tech Mono',
              fontSize: '11px',
              textTransform: 'uppercase',
              transition: 'all 0.15s ease'
            }}
          >
            THEME: {theme}
          </button>
          
          {/* HELP / PROTOCOL MANUAL BUTTON */}
          <button 
            onClick={() => setIsHelpOpen(true)}
            style={{
              background: 'var(--sentinel-blue-dim)',
              border: '1px solid var(--sentinel-blue)',
              color: 'var(--sentinel-blue)',
              padding: '6px 14px',
              cursor: 'pointer',
              fontFamily: 'Share Tech Mono',
              fontSize: '11px',
              textTransform: 'uppercase',
              fontWeight: 'bold',
              letterSpacing: '1px',
              boxShadow: '0 0 10px var(--sentinel-blue-dim)',
              transition: 'all 0.15s ease'
            }}
          >
            [?] PROTOCOL MANUAL
          </button>
          
          <span className="pulse-indicator"></span>
        </div>
      </header>

      {/* TACTICAL TAB BAR */}
      <nav style={{ display: 'flex', gap: '10px', marginBottom: '14px' }}>
        {['WORKSPACE', 'CFG_VISUALIZER', 'ASSEMBLY_VIEW'].map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            style={{
              background: activeTab === tab ? 'var(--sentinel-blue-dim)' : 'var(--bg-panel)',
              border: activeTab === tab ? '1px solid var(--sentinel-blue)' : '1px dashed var(--border-blue)',
              color: activeTab === tab ? 'var(--sentinel-blue)' : 'var(--text-muted)',
              padding: '8px 24px',
              fontFamily: 'Share Tech Mono',
              fontSize: '12px',
              cursor: 'pointer',
              letterSpacing: '1px',
              transition: 'all 0.15s ease'
            }}
          >
            {tab === 'WORKSPACE' && "01 // COMPILER WORKSPACE"}
            {tab === 'CFG_VISUALIZER' && "02 // CONTROL FLOW GRAPH VISUALIZER"}
            {tab === 'ASSEMBLY_VIEW' && "03 // ENTRY POINT ASSEMBLY VIEW"}
          </button>
        ))}
      </nav>

      {/* CORE CONTROL HUB */}
      <div style={{ flex: 1, minHeight: '0', display: 'flex', flexDirection: 'column', marginBottom: '16px' }}>
        
        {/* TAB A: COMPILER WORKSPACE */}
        {activeTab === 'WORKSPACE' && (
          <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.2fr 1fr', gap: '16px', flex: 1, minHeight: '0' }}>
            
            {/* COLUMN 1: IDA PRO STYLE REPOSITORY PANELS */}
            <section className="dashed-box" style={{ padding: '16px', display: 'flex', flexDirection: 'column', minHeight: '0' }}>
              <h2 style={{ color: 'var(--sentinel-blue)', borderBottom: '1px dashed var(--border-blue)', paddingBottom: '6px', marginBottom: '12px', fontSize: '14px', letterSpacing: '1px' }}>
                01 // IDA PRO BINARY REPOSITORIES
              </h2>

              <div 
                onDragOver={handleDragOver}
                onDrop={handleDrop}
                style={{ 
                  border: '2px dashed var(--sentinel-blue)', 
                  background: 'var(--sentinel-blue-dim)', 
                  borderRadius: '4px',
                  padding: '16px',
                  textAlign: 'center',
                  cursor: 'pointer',
                  marginBottom: '12px',
                  transition: 'all 0.15s ease'
                }}
              >
                <p style={{ color: 'var(--sentinel-blue)', fontSize: '13px', letterSpacing: '1px' }}>DRAG & DROP NATIVE .EXE + .PDB HERE</p>
                {uploadStatus && (
                  <p style={{ 
                    color: uploadStatus.startsWith('ERROR') ? '#ff1744' : (uploadStatus.startsWith('SUCCESS') ? 'var(--text-green)' : 'var(--sentinel-blue)'),
                    fontSize: '11px',
                    marginTop: '6px',
                    fontWeight: 'bold'
                  }}>
                    {uploadStatus}
                  </p>
                )}
              </div>

              <div style={{ marginBottom: '12px' }}>
                <label style={{ display: 'block', color: 'var(--text-muted)', fontSize: '11px', marginBottom: '4px' }}>CHOOSE ACTIVE PE BINARY FILE</label>
                <select 
                  value={selectedBinary ? selectedBinary.exeName : ''} 
                  onChange={(e) => setSelectedBinary(binaries.find(b => b.exeName === e.target.value))}
                  style={{ width: '100%', padding: '8px', background: 'var(--bg-dark)', border: '1px solid var(--border-blue)', color: 'var(--sentinel-blue)', outline: 'none', fontFamily: 'Share Tech Mono', fontSize: '13px', transition: 'background-color 0.15s ease, color 0.15s ease' }}
                >
                  {binaries.map(b => (
                    <option key={b.exeName} value={b.exeName}>{b.exeName} (+ {b.pdbName})</option>
                  ))}
                </select>
              </div>

              {/* IDA PRO TAB SELECTORS */}
              <div style={{ display: 'flex', gap: '4px', background: 'var(--bg-dark)', padding: '2px', border: '1px solid var(--border-muted)', marginBottom: '10px' }}>
                {['FUNCTIONS', 'STRINGS'].map(repTab => (
                  <button
                    key={repTab}
                    onClick={() => setIdaRepositoryTab(repTab)}
                    style={{
                      flex: 1,
                      padding: '6px',
                      background: idaRepositoryTab === repTab ? 'var(--sentinel-blue-dim)' : 'transparent',
                      border: 'none',
                      color: idaRepositoryTab === repTab ? 'var(--sentinel-blue)' : 'var(--text-muted)',
                      fontSize: '11px',
                      fontFamily: 'Share Tech Mono',
                      cursor: 'pointer',
                      transition: 'all 0.15s ease'
                    }}
                  >
                    {repTab === 'FUNCTIONS' ? "FUNCTIONS TREE" : "STRINGS WINDOW"}
                  </button>
                ))}
              </div>

              {/* IDA PRO SUB-WINDOW: FUNCTIONS LIST */}
              {idaRepositoryTab === 'FUNCTIONS' && (
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: '0' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', texttransform: 'uppercase', alignItems: 'center', marginBottom: '6px' }}>
                    <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>FUNCTIONS RESOLVED FROM COMPANION PDB</span>
                    <input 
                      type="text" 
                      placeholder="SEARCH..." 
                      value={symbolSearch} 
                      onChange={(e) => setSymbolSearch(e.target.value)}
                      style={{ width: '120px', padding: '4px 8px', background: 'var(--bg-dark)', border: '1px solid var(--border-blue)', color: 'var(--text-primary)', fontSize: '11px', outline: 'none', fontFamily: 'Share Tech Mono', transition: 'background-color 0.15s ease' }}
                    />
                  </div>

                  {/* Bulk Staging Action Buttons */}
                  <div style={{ display: 'flex', gap: '8px', marginBottom: '8px' }}>
                    <button 
                      onClick={() => {
                        const allNames = filteredSymbols.map(s => s.name);
                        setStagedSymbols(prev => {
                          const combined = [...prev, ...allNames];
                          return [...new Set(combined)]; // Deduplicate staged set
                        });
                      }}
                      style={{ flex: 1, background: 'transparent', border: '1px dashed var(--border-blue)', color: 'var(--sentinel-blue)', padding: '5px', fontSize: '11px', fontFamily: 'Share Tech Mono', cursor: 'pointer', transition: 'all 0.1s ease' }}
                    >
                      STAGE ALL FILTERED
                    </button>
                    <button 
                      onClick={() => setStagedSymbols([])}
                      style={{ flex: 1, background: 'transparent', border: '1px dashed rgba(255, 23, 68, 0.4)', color: '#ff1744', padding: '5px', fontSize: '11px', fontFamily: 'Share Tech Mono', cursor: 'pointer', transition: 'all 0.1s ease' }}
                    >
                      CLEAR STAGED
                    </button>
                  </div>

                  {/* Smart Select Heuristic Action Trigger */}
                  <button 
                    onClick={() => {
                      const highPriorityKeywords = ['key', 'secret', 'license', 'validate', 'auth', 'decrypt', 'encrypt', 'check', 'serial', 'calculate', 'install', 'verify'];
                      const excludeKeywords = ['std::', '__', 'boost::', 'wndproc', 'windowproc', 'allocator', 'deleting destructor', 'atexit', 'crt', 'vftable'];
                      
                      const selected = symbols.filter(s => {
                        const lower = s.name.toLowerCase();
                        const isHighPriority = highPriorityKeywords.some(kw => lower.includes(kw));
                        const isExcluded = excludeKeywords.some(kw => lower.includes(kw));
                        return isHighPriority && !isExcluded;
                      }).map(s => s.name);
                      
                      setStagedSymbols(prev => {
                        const combined = [...prev, ...selected];
                        return [...new Set(combined)]; // Deduplicate staged set
                      });
                    }}
                    style={{ 
                      width: '100%', 
                      background: 'var(--sentinel-blue-dim)', 
                      border: '1px solid var(--sentinel-blue)', 
                      color: 'var(--sentinel-blue)', 
                      padding: '7px', 
                      fontSize: '11px', 
                      fontFamily: 'Share Tech Mono', 
                      fontWeight: 'bold',
                      cursor: 'pointer', 
                      marginBottom: '10px',
                      textTransform: 'uppercase',
                      letterSpacing: '1px',
                      boxShadow: '0 0 10px var(--sentinel-blue-dim)',
                      transition: 'all 0.15s ease'
                    }}
                  >
                    ⚡ Smart Select High-Priority Functions
                  </button>
                  
                  <div style={{ flex: 1, overflowY: 'auto', border: '1px dashed var(--border-blue)', background: 'var(--sentinel-blue-dim)', padding: '6px' }}>
                    {filteredSymbols.map(sym => (
                      <div key={sym.name} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '5px 8px', marginBottom: '4px', background: 'var(--bg-panel)', borderBottom: '1px solid var(--border-muted)', borderRadius: '2px' }}>
                        <span style={{ fontSize: '12px', wordBreak: 'break-all', color: 'var(--text-primary)', marginRight: '10px' }}>{sym.name}</span>
                        <button 
                          onClick={() => addSymbolToQueue(sym.name)}
                          style={{ background: 'transparent', border: '1px solid var(--border-blue)', color: 'var(--sentinel-blue)', padding: '2px 8px', fontSize: '12px', cursor: 'pointer', fontFamily: 'Share Tech Mono', fontWeight: 'bold' }}
                        >
                          +
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* IDA PRO SUB-WINDOW: PLAINTEXT STRINGS */}
              {idaRepositoryTab === 'STRINGS' && (
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: '0' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                    <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>PLAINTEXT STRINGS SCANNED FROM PE</span>
                    <input 
                      type="text" 
                      placeholder="SEARCH..." 
                      value={stringSearch} 
                      onChange={(e) => setStringSearch(e.target.value)}
                      style={{ width: '120px', padding: '4px 8px', background: 'var(--bg-dark)', border: '1px solid var(--border-blue)', color: 'var(--text-primary)', fontSize: '11px', outline: 'none', fontFamily: 'Share Tech Mono', transition: 'background-color 0.15s ease' }}
                    />
                  </div>
                  
                  <div style={{ flex: 1, overflowY: 'auto', border: '1px dashed var(--border-blue)', background: 'var(--sentinel-blue-dim)', padding: '6px' }}>
                    {filteredStrings.map(str => (
                      <div key={str} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '5px 8px', marginBottom: '4px', background: 'var(--bg-panel)', borderBottom: '1px solid var(--border-muted)', borderRadius: '2px' }}>
                        <span style={{ fontSize: '12px', wordBreak: 'break-all', color: 'var(--text-primary)', marginRight: '10px' }}>{str}</span>
                        <button 
                          onClick={() => addStringToQueue(str)}
                          style={{ background: 'transparent', border: '1px solid var(--border-blue)', color: 'var(--sentinel-blue)', padding: '2px 8px', fontSize: '12px', cursor: 'pointer', fontFamily: 'Share Tech Mono', fontWeight: 'bold' }}
                        >
                          +
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </section>

            {/* COLUMN 2: ACTIVE PROTECTION QUEUES */}
            <section className="dashed-box" style={{ padding: '16px', display: 'flex', flexDirection: 'column', minHeight: '0' }}>
              <h2 style={{ color: 'var(--sentinel-blue)', borderBottom: '1px dashed var(--border-blue)', paddingBottom: '6px', marginBottom: '12px', fontSize: '14px', letterSpacing: '1px' }}>
                02 // ACTIVE PROTECTION STAGE QUEUE
              </h2>

              {/* Staged functions list (Support multiple functions sequentially!) */}
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: '0', marginBottom: '16px' }}>
                <span style={{ color: 'var(--sentinel-blue)', fontSize: '12px', marginBottom: '6px', display: 'block' }}>&gt;&gt; TARGET FUNCTIONS TO VIRTUALIZE (vISA COMPILER)</span>
                <div style={{ flex: 1, overflowY: 'auto', border: '1px dashed var(--border-blue)', background: 'var(--sentinel-blue-dim)', padding: '10px' }}>
                  {stagedSymbols.length === 0 ? (
                    <p style={{ color: 'var(--text-muted)', fontSize: '12px', textAlign: 'center', marginTop: '20px' }}>[No functions staged. Click '+' on left symbol repository]</p>
                  ) : (
                    stagedSymbols.map(sym => (
                      <div key={sym} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px', marginBottom: '6px', background: 'var(--bg-dark)', borderLeft: '4px solid var(--sentinel-blue)' }}>
                        <span style={{ fontSize: '12px', wordBreak: 'break-all', color: 'var(--sentinel-blue)' }}>{sym}</span>
                        <button 
                          onClick={() => removeSymbolFromQueue(sym)}
                          style={{ background: 'transparent', border: '1px solid #ff1744', color: '#ff1744', padding: '2px 8px', fontSize: '11px', cursor: 'pointer', fontFamily: 'Share Tech Mono' }}
                        >
                          REMOVE
                        </button>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* Staged strings list */}
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: '0' }}>
                <span style={{ color: 'var(--sentinel-blue)', fontSize: '12px', marginBottom: '6px', display: 'block' }}>&gt;&gt; TARGET STRINGS TO ENCRYPT (XOR ENTROPY PASSTHROUGH)</span>
                
                <div style={{ flex: 1, overflowY: 'auto', border: '1px dashed var(--border-blue)', background: 'var(--sentinel-blue-dim)', padding: '10px' }}>
                  {encryptMode === 'ALL' ? (
                    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%', color: 'var(--sentinel-blue)', fontSize: '12px', textAlign: 'center' }}>
                      [BULK STRING ENCRYPTION MODE ENABLED]<br/>All extracted .rdata text fields will be decrypted in memory.
                    </div>
                  ) : stagedStrings.length === 0 ? (
                    <p style={{ color: 'var(--text-muted)', fontSize: '12px', textAlign: 'center', marginTop: '20px' }}>[No strings staged. Click '+' on left strings repository]</p>
                  ) : (
                    stagedStrings.map(str => (
                      <div key={str} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px', marginBottom: '6px', background: 'var(--bg-dark)', borderLeft: '4px solid var(--sentinel-blue)' }}>
                        <span style={{ fontSize: '12px', wordBreak: 'break-all', color: 'var(--sentinel-blue)' }}>{str}</span>
                        <button 
                          onClick={() => removeStringFromQueue(str)}
                          style={{ background: 'transparent', border: '1px solid #ff1744', color: '#ff1744', padding: '2px 8px', fontSize: '11px', cursor: 'pointer', fontFamily: 'Share Tech Mono' }}
                        >
                          REMOVE
                        </button>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </section>

            {/* COLUMN 3: OBFUSCATION PROFILER */}
            <section className="dashed-box" style={{ padding: '16px', display: 'flex', flexDirection: 'column', minHeight: '0' }}>
              <h2 style={{ color: 'var(--sentinel-blue)', borderBottom: '1px dashed var(--border-blue)', paddingBottom: '6px', marginBottom: '12px', fontSize: '14px', letterSpacing: '1px' }}>
                03 // OBFUSCATION COMPILER PROFILER
              </h2>

              <div style={{ marginBottom: '16px' }}>
                <span style={{ display: 'block', color: 'var(--text-muted)', fontSize: '11px', marginBottom: '6px' }}>STRING SECURITY SCHEME</span>
                <div style={{ display: 'flex', gap: '12px' }}>
                  <button 
                    onClick={() => setEncryptMode('SPECIFIC')}
                    style={{ flex: 1, padding: '6px 10px', fontSize: '12px', border: '1px solid var(--border-blue)', background: encryptMode === 'SPECIFIC' ? 'var(--sentinel-blue-dim)' : 'transparent', color: encryptMode === 'SPECIFIC' ? 'var(--sentinel-blue)' : 'var(--text-muted)', cursor: 'pointer', fontFamily: 'Share Tech Mono' }}
                  >
                    MANUAL QUEUE
                  </button>
                  <button 
                    onClick={() => setEncryptMode('ALL')}
                    style={{ flex: 1, padding: '6px 10px', fontSize: '12px', border: '1px solid var(--border-blue)', background: encryptMode === 'ALL' ? 'var(--sentinel-blue-dim)' : 'transparent', color: encryptMode === 'ALL' ? 'var(--sentinel-blue)' : 'var(--text-muted)', cursor: 'pointer', fontFamily: 'Share Tech Mono' }}
                  >
                    BULK ENCRYPTER
                  </button>
                </div>
              </div>

              {/* CFF toggle */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 12px', marginBottom: '10px', background: 'var(--bg-panel-header)', border: '1px solid var(--border-muted)' }}>
                <div>
                  <span style={{ display: 'block', fontSize: '13px', color: 'var(--text-primary)' }}>CONTROL FLOW FLATTENING</span>
                  <span style={{ display: 'block', fontSize: '10px', color: 'var(--text-muted)' }}>Non-linear state loop protection</span>
                </div>
                <button 
                  onClick={() => setCffEnabled(!cffEnabled)}
                  style={{ padding: '4px 12px', fontSize: '11px', border: '1px solid var(--border-blue)', background: cffEnabled ? 'var(--sentinel-blue-dim)' : 'var(--bg-dark)', color: cffEnabled ? 'var(--sentinel-blue)' : 'var(--text-muted)', cursor: 'pointer', fontFamily: 'Share Tech Mono' }}
                >
                  {cffEnabled ? "ENABLED" : "DISABLED"}
                </button>
              </div>

              {/* SEH toggle */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 12px', marginBottom: '10px', background: 'var(--bg-panel-header)', border: '1px solid var(--border-muted)' }}>
                <div>
                  <span style={{ display: 'block', fontSize: '13px', color: 'var(--text-primary)' }}>STRUCTURED EXCEPTION HANDLING</span>
                  <span style={{ display: 'block', fontSize: '10px', color: 'var(--text-muted)' }}>OS unwind pdata registration</span>
                </div>
                <button 
                  onClick={() => setSehEnabled(!sehEnabled)}
                  style={{ padding: '4px 12px', fontSize: '11px', border: '1px solid var(--border-blue)', background: sehEnabled ? 'var(--sentinel-blue-dim)' : 'var(--bg-dark)', color: sehEnabled ? 'var(--sentinel-blue)' : 'var(--text-muted)', cursor: 'pointer', fontFamily: 'Share Tech Mono' }}
                >
                  {sehEnabled ? "ENABLED" : "DISABLED"}
                </button>
              </div>

              {/* EPH toggle */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 12px', marginBottom: '10px', background: 'var(--bg-panel-header)', border: '1px solid var(--border-muted)' }}>
                <div>
                  <span style={{ display: 'block', fontSize: '13px', color: 'var(--text-primary)' }}>ENTRY POINT HIJACKING</span>
                  <span style={{ display: 'block', fontSize: '10px', color: 'var(--text-muted)' }}>Redirect entry point to wrapper</span>
                </div>
                <button 
                  onClick={() => setHijackEnabled(!hijackEnabled)}
                  style={{ padding: '4px 12px', fontSize: '11px', border: '1px solid var(--border-blue)', background: hijackEnabled ? 'var(--sentinel-blue-dim)' : 'var(--bg-dark)', color: hijackEnabled ? 'var(--sentinel-blue)' : 'var(--text-muted)', cursor: 'pointer', fontFamily: 'Share Tech Mono' }}
                >
                  {hijackEnabled ? "ENABLED" : "DISABLED"}
                </button>
              </div>

              {/* Anti-Tamper self-integrity check toggle */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 12px', marginBottom: '10px', background: 'var(--bg-panel-header)', border: '1px solid var(--border-muted)' }}>
                <div>
                  <span style={{ display: 'block', fontSize: '13px', color: 'var(--text-primary)' }}>ANTI-TAMPER INTEGRITY</span>
                  <span style={{ display: 'block', fontSize: '10px', color: 'var(--text-muted)' }}>Self-integrity check and execution lock</span>
                </div>
                <button 
                  onClick={() => setTamperEnabled(!tamperEnabled)}
                  style={{ padding: '4px 12px', fontSize: '11px', border: '1px solid var(--border-blue)', background: tamperEnabled ? 'var(--sentinel-blue-dim)' : 'var(--bg-dark)', color: tamperEnabled ? 'var(--sentinel-blue)' : 'var(--text-muted)', cursor: 'pointer', fontFamily: 'Share Tech Mono' }}
                >
                  {tamperEnabled ? "ENABLED" : "DISABLED"}
                </button>
              </div>

              {/* Custom PE Section Name Input */}
              <div style={{ marginBottom: '16px', marginTop: '10px' }}>
                <span style={{ display: 'block', color: 'var(--text-muted)', fontSize: '11px', marginBottom: '6px' }}>CUSTOM PE SECTION NAME</span>
                <input 
                  type="text" 
                  placeholder=".shield" 
                  maxLength={8}
                  value={secName}
                  onChange={(e) => {
                    let val = e.target.value;
                    if (val.length <= 8) {
                      setSecName(val);
                    }
                  }}
                  style={{ width: '100%', padding: '10px', background: 'var(--bg-dark)', border: '1px solid var(--border-blue)', color: 'var(--text-primary)', outline: 'none', fontFamily: 'Share Tech Mono', fontSize: '13px', transition: 'background-color 0.15s ease' }}
                />
              </div>

              {/* Obfuscation Level */}
              <div style={{ marginBottom: '16px', marginTop: '10px' }}>
                <span style={{ display: 'block', color: 'var(--text-muted)', fontSize: '11px', marginBottom: '6px' }}>MATH OBFUSCATION PASS INTENSITY</span>
                <div style={{ display: 'flex', gap: '8px' }}>
                  {['LOW', 'MEDIUM', 'HIGH'].map(lvl => (
                    <button 
                      key={lvl}
                      onClick={() => setObfuscationLevel(lvl)}
                      style={{ flex: 1, padding: '6px', fontSize: '11px', border: '1px solid var(--border-blue)', background: obfuscationLevel === lvl ? 'var(--sentinel-blue-dim)' : 'transparent', color: obfuscationLevel === lvl ? 'var(--sentinel-blue)' : 'var(--text-muted)', cursor: 'pointer', fontFamily: 'Share Tech Mono' }}
                    >
                      {lvl}
                    </button>
                  ))}
                </div>
              </div>

              {/* Action Trigger */}
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'flex-end', marginTop: '20px' }}>
                <button 
                  onClick={handleProtect}
                  disabled={isProtecting || stagedSymbols.length === 0}
                  style={{ 
                    width: '100%',
                    background: isProtecting ? 'var(--bg-dark)' : 'var(--sentinel-blue)',
                    color: isProtecting ? 'var(--text-muted)' : 'var(--bg-dark)',
                    border: '1px solid var(--sentinel-blue)',
                    padding: '14px',
                    fontFamily: 'Share Tech Mono',
                    fontWeight: 'bold',
                    fontSize: '14px',
                    cursor: isProtecting || stagedSymbols.length === 0 ? 'not-allowed' : 'pointer',
                    letterSpacing: '2px',
                    textTransform: 'uppercase',
                    boxShadow: isProtecting || stagedSymbols.length === 0 ? 'none' : '0 0 15px var(--sentinel-blue)',
                    transition: 'all 0.2s ease'
                  }}
                >
                  {isProtecting ? "EXECUTING COMPILER PASSES..." : "COMPILE SECURE IMAGE"}
                </button>
              </div>
            </section>

          </div>
        )}

        {/* TAB B: CONTROL FLOW GRAPH VISUALIZER */}
        {activeTab === 'CFG_VISUALIZER' && (
          <div className="dashed-box" style={{ padding: '20px', flex: 1, display: 'flex', flexDirection: 'column', minHeight: '0' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px dashed var(--border-blue)', paddingBottom: '6px', marginBottom: '12px' }}>
              <h2 style={{ color: 'var(--sentinel-blue)', fontSize: '14px', letterSpacing: '1px', margin: 0 }}>
                MUTATION GRAPH // REAL-TIME CONTROL FLOW FLATTENING ANALYZER
              </h2>
              
              {/* Dynamic CFG Selector dropdown for multi-function support! */}
              {stagedSymbols.length > 1 && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>ACTIVE CFG VISUALIZER TARGET:</span>
                  <select
                    value={cfgActiveFunc}
                    onChange={(e) => setCfgActiveFunc(e.target.value)}
                    style={{ background: 'var(--bg-dark)', border: '1px solid var(--border-blue)', color: 'var(--sentinel-blue)', outline: 'none', padding: '4px 10px', fontFamily: 'Share Tech Mono', fontSize: '11px' }}
                  >
                    {stagedSymbols.map(sym => (
                      <option key={sym} value={sym}>{sym}</option>
                    ))}
                  </select>
                </div>
              )}
            </div>
            
            {stagedSymbols.length === 0 ? (
              <div style={{ flex: 1, display: 'flex', justifyContent: 'center', alignItems: 'center', color: 'var(--text-muted)', fontSize: '14px', textAlign: 'center' }}>
                [NO ACTIVE FUNCTION DETECTED]<br/>Please return to the Compiler Workspace (Tab 1) and stage a target function symbol (+) first.
              </div>
            ) : isCfgLoading ? (
              <div style={{ flex: 1, display: 'flex', justifyContent: 'center', alignItems: 'center', color: 'var(--sentinel-blue)', fontSize: '14px', letterSpacing: '2px' }}>
                [LODING SECURE CONTROL FLOW BLUEPRINTS...]
              </div>
            ) : cfgError ? (
              <div style={{ flex: 1, display: 'flex', justifyContent: 'center', alignItems: 'center', color: '#ff1744', fontSize: '14px', textAlign: 'center' }}>
                ERROR RESOLVING CFG: {cfgError}<br/>Make sure your target companion PDB is aligned and uploaded.
              </div>
            ) : (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.2fr', gap: '16px', flex: 1, minHeight: '0' }}>
                
                {/* Left visual: Original Linear CFG */}
                <div style={{ border: '1px dashed var(--border-blue)', background: 'var(--sentinel-blue-dim)', padding: '16px', display: 'flex', flexDirection: 'column', minHeight: '0' }}>
                  <h3 style={{ color: 'var(--text-muted)', fontSize: '12px', marginBottom: '12px', letterSpacing: '1px', textTransform: 'uppercase', borderBottom: '1px solid var(--border-muted)', paddingBottom: '4px' }}>
                    ORIGINAL CONTROL FLOW (DISASSEMBLED BASIC BLOCKS)
                  </h3>
                  
                  {/* Scrollable List of Original Blocks */}
                  <div style={{ flex: 1, overflowY: 'auto', paddingRight: '4px' }}>
                    {cfgOriginalBlocks.map((block, idx) => (
                      <div key={block.id} style={{ marginBottom: '14px', position: 'relative' }}>
                        <div style={{ border: '1px dashed var(--border-blue)', background: 'var(--bg-panel)', padding: '10px', borderRadius: '3px' }}>
                          <span style={{ color: 'var(--sentinel-blue)', fontSize: '11px', display: 'block', borderBottom: '1px solid var(--border-muted)', paddingBottom: '4px', marginBottom: '6px', fontWeight: 'bold' }}>
                            {block.id} {idx === 0 ? " (ENTRY)" : ""}
                          </span>
                          <div style={{ fontFamily: 'monospace', fontSize: '11px', color: 'var(--text-primary)', lineHeight: '1.4' }}>
                            {block.instructions.map((inst, i) => (
                              <div key={i}>{inst}</div>
                            ))}
                          </div>
                        </div>
                        {idx < cfgOriginalBlocks.length - 1 && (
                          <div style={{ display: 'flex', justifyContent: 'center', height: '14px' }}>
                            <div style={{ borderLeft: '1px dashed var(--border-blue)', height: '100%' }}></div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Right visual: Flattened CFG (Hub and Spoke) */}
                <div style={{ border: '1px dashed var(--border-blue)', background: 'var(--sentinel-blue-dim)', padding: '16px', display: 'flex', flexDirection: 'column', minHeight: '0' }}>
                  <h3 style={{ color: 'var(--sentinel-blue)', fontSize: '12px', marginBottom: '12px', letterSpacing: '1px', textTransform: 'uppercase', borderBottom: '1px solid var(--border-muted)', paddingBottom: '4px' }}>
                    FLATTENED STATE-MACHINE DISPATCHER (OBFUSCATED HUD BLOCKS)
                  </h3>
                  
                  {/* Scrollable List of Flattened Blocks */}
                  <div style={{ flex: 1, overflowY: 'auto', paddingRight: '4px' }}>
                    {cfgProtectedBlocks.map((block, idx) => (
                      <div key={block.id} style={{ marginBottom: '12px' }}>
                        <div style={{ 
                          border: block.id === 'CFF_DISPATCHER' ? '1px solid var(--sentinel-blue)' : '1px dashed var(--border-blue)', 
                          background: block.id === 'CFF_DISPATCHER' ? 'var(--sentinel-blue-dim)' : 'var(--bg-panel)', 
                          padding: '10px', 
                          borderRadius: '3px' 
                        }}>
                          <span style={{ color: 'var(--sentinel-blue)', fontSize: '11px', display: 'block', borderBottom: '1px solid var(--border-muted)', paddingBottom: '4px', marginBottom: '6px', fontWeight: 'bold' }}>
                            {block.id}
                          </span>
                          <div style={{ fontFamily: 'monospace', fontSize: '11px', color: 'var(--text-primary)', lineHeight: '1.4' }}>
                            {block.instructions.map((inst, i) => (
                              <div key={i} style={{ color: block.id === 'CFF_DISPATCHER' && i > 6 ? 'var(--sentinel-blue)' : 'var(--text-primary)' }}>
                                {inst}
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

              </div>
            )}
          </div>
        )}

        {/* TAB C: ENTRY POINT ASSEMBLY VIEW */}
        {activeTab === 'ASSEMBLY_VIEW' && (
          <div className="dashed-box" style={{ padding: '24px', flex: 1, display: 'flex', flexDirection: 'column', minHeight: '0' }}>
            <h2 style={{ color: 'var(--sentinel-blue)', fontSize: '16px', letterSpacing: '1px', borderBottom: '1px dashed var(--border-blue)', paddingBottom: '8px', marginBottom: '16px' }}>
              ENTRY POINT ASSEMBLY INTERCEPTOR // COMPARATIVE ANALYSIS
            </h2>
            
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', flex: 1, minHeight: '0' }}>
              
              {/* Left column: Original Entry Point */}
              <div style={{ display: 'flex', flexDirection: 'column', minHeight: '0' }}>
                <h3 style={{ color: 'var(--text-muted)', fontSize: '12px', marginBottom: '8px', letterSpacing: '1px' }}>
                  A // ORIGINAL ENTRY POINT (OEP BEFORE HIJACK)
                </h3>
                <div style={{ flex: 1, background: 'var(--bg-dark)', border: '1px dashed var(--border-blue)', padding: '12px', fontFamily: 'monospace', fontSize: '11px', color: 'var(--text-muted)', overflowY: 'auto' }}>
                  <div style={{ color: 'var(--text-muted)', marginBottom: '8px' }}>; Header: OptionalHeader64.AddressOfEntryPoint = {originalEntryPoint}</div>
                  <div style={{ display: 'flex', marginBottom: '4px' }}>
                    <span style={{ width: '90px' }}>{formatOffset(originalEntryPoint, 0)}:</span>
                    <span style={{ width: '120px', color: '#888' }}>48 83 EC 28</span>
                    <span style={{ color: 'var(--text-primary)' }}>sub      rsp, 28h</span>
                  </div>
                  <div style={{ display: 'flex', marginBottom: '4px' }}>
                    <span style={{ width: '90px' }}>{formatOffset(originalEntryPoint, 4)}:</span>
                    <span style={{ width: '120px', color: '#888' }}>E8 57 02 00 00</span>
                    <span style={{ color: 'var(--text-primary)' }}>call     __security_init_cookie</span>
                  </div>
                  <div style={{ display: 'flex', marginBottom: '4px' }}>
                    <span style={{ width: '90px' }}>{formatOffset(originalEntryPoint, 9)}:</span>
                    <span style={{ width: '120px', color: '#888' }}>48 83 C4 28</span>
                    <span style={{ color: 'var(--text-primary)' }}>add      rsp, 28h</span>
                  </div>
                  <div style={{ display: 'flex', marginBottom: '4px' }}>
                    <span style={{ width: '90px' }}>{formatOffset(originalEntryPoint, 13)}:</span>
                    <span style={{ width: '120px', color: '#888' }}>E9 EE 45 00 00</span>
                    <span style={{ color: 'var(--text-primary)' }}>jmp      _WinMain</span>
                  </div>
                  <div style={{ display: 'flex', marginBottom: '4px' }}>
                    <span style={{ width: '90px' }}>{formatOffset(originalEntryPoint, 18)}:</span>
                    <span style={{ width: '120px', color: '#888' }}>CC</span>
                    <span style={{ color: 'var(--text-primary)' }}>int3</span>
                  </div>
                </div>
              </div>

              {/* Right column: Hijacked EP */}
              <div style={{ display: 'flex', flexDirection: 'column', minHeight: '0' }}>
                <h3 style={{ color: 'var(--sentinel-blue)', fontSize: '12px', marginBottom: '8px', letterSpacing: '1px' }}>
                  B // HIJACKED ENTRY POINT ({secName.toUpperCase().replace('.', '')} WRAPPER AFTER TRAMPOLINE)
                </h3>
                <div style={{ flex: 1, background: 'var(--bg-dark)', border: '1px dashed var(--border-blue)', padding: '12px', fontFamily: 'monospace', fontSize: '11px', color: '#fff', overflowY: 'auto' }}>
                  <div style={{ color: 'var(--sentinel-blue)', marginBottom: '8px' }}>; Header: OptionalHeader64.AddressOfEntryPoint = {hijackedEntryPoint} ({secName} Section EP)</div>
                  
                  {/* Prologue / Push Context */}
                  <div style={{ display: 'flex', marginBottom: '4px' }}>
                    <span style={{ width: '90px', color: 'var(--sentinel-blue)' }}>{formatOffset(hijackedEntryPoint, 0)}:</span>
                    <span style={{ width: '120px', color: '#888' }}>51</span>
                    <span style={{ color: 'var(--text-primary)' }}>push     rcx</span>
                  </div>
                  <div style={{ display: 'flex', marginBottom: '4px' }}>
                    <span style={{ width: '90px', color: 'var(--sentinel-blue)' }}>{formatOffset(hijackedEntryPoint, 1)}:</span>
                    <span style={{ width: '120px', color: '#888' }}>52</span>
                    <span style={{ color: 'var(--text-primary)' }}>push     rdx</span>
                  </div>
                  <div style={{ display: 'flex', marginBottom: '4px' }}>
                    <span style={{ width: '90px', color: 'var(--sentinel-blue)' }}>{formatOffset(hijackedEntryPoint, 2)}:</span>
                    <span style={{ width: '120px', color: '#888' }}>41 53</span>
                    <span style={{ color: 'var(--text-primary)' }}>push     r11</span>
                  </div>

                  {/* ASLR Resolution */}
                  <div style={{ display: 'flex', marginBottom: '4px', background: 'rgba(0,176,255,0.04)' }}>
                    <span style={{ width: '90px', color: 'var(--sentinel-blue)' }}>{formatOffset(hijackedEntryPoint, 4)}:</span>
                    <span style={{ width: '120px', color: '#888' }}>E8 00 00 00 00</span>
                    <span style={{ color: 'var(--text-green)' }}>call     {formatOffset(hijackedEntryPoint, 9)} (get_rip)</span>
                  </div>
                  <div style={{ display: 'flex', marginBottom: '4px', background: 'rgba(0,176,255,0.04)' }}>
                    <span style={{ width: '90px', color: 'var(--sentinel-blue)' }}>{formatOffset(hijackedEntryPoint, 9)}:</span>
                    <span style={{ width: '120px', color: '#888' }}>41 5B</span>
                    <span style={{ color: 'var(--text-green)' }}>pop      r11</span>
                  </div>
                  <div style={{ display: 'flex', marginBottom: '4px', background: 'rgba(0,176,255,0.04)' }}>
                    <span style={{ width: '90px', color: 'var(--sentinel-blue)' }}>{formatOffset(hijackedEntryPoint, 11)}:</span>
                    <span style={{ width: '120px', color: '#888' }}>49 81 EB {formatOffset(hijackedEntryPoint, 9).substring(2)}h</span>
                    <span style={{ color: 'var(--text-green)' }}>sub      r11, {formatOffset(hijackedEntryPoint, 9)}h (ASLR Base Resolved)</span>
                  </div>

                  {/* CFF state initialization */}
                  <div style={{ display: 'flex', marginBottom: '4px' }}>
                    <span style={{ width: '90px', color: 'var(--sentinel-blue)' }}>{formatOffset(hijackedEntryPoint, 17)}:</span>
                    <span style={{ width: '120px', color: '#888' }}>B8 00 00 00 00</span>
                    <span style={{ color: 'var(--text-primary)' }}>mov      eax, 0 (State Init)</span>
                  </div>

                  {/* Decrypting Loop */}
                  <div style={{ display: 'flex', marginBottom: '4px', background: 'rgba(0,230,118,0.04)' }}>
                    <span style={{ width: '90px', color: 'var(--sentinel-blue)' }}>{formatOffset(hijackedEntryPoint, 22)}:</span>
                    <span style={{ width: '120px', color: '#888' }}>4C 89 DB</span>
                    <span style={{ color: 'var(--text-green)' }}>mov      rbx, r11</span>
                  </div>
                  <div style={{ display: 'flex', marginBottom: '4px', background: 'rgba(0,230,118,0.04)' }}>
                    <span style={{ width: '90px', color: 'var(--sentinel-blue)' }}>{formatOffset(hijackedEntryPoint, 25)}:</span>
                    <span style={{ width: '120px', color: '#888' }}>48 81 C3 B2...</span>
                    <span style={{ color: 'var(--text-green)' }}>add      rbx, rdata_string_rva</span>
                  </div>
                  <div style={{ display: 'flex', marginBottom: '4px', background: 'rgba(0,230,118,0.04)' }}>
                    <span style={{ width: '90px', color: 'var(--sentinel-blue)' }}>{formatOffset(hijackedEntryPoint, 31)}:</span>
                    <span style={{ width: '120px', color: '#888' }}>80 33 AA</span>
                    <span style={{ color: 'var(--text-green)' }}>xor      byte ptr [rbx], 0xAA (Decrypt Loop)</span>
                  </div>

                  {/* JMP to OEP */}
                  <div style={{ display: 'flex', marginBottom: '4px', background: 'rgba(0,176,255,0.08)' }}>
                    <span style={{ width: '90px', color: 'var(--sentinel-blue)' }}>{formatOffset(hijackedEntryPoint, 129)}:</span>
                    <span style={{ width: '120px', color: '#888' }}>41 5B</span>
                    <span style={{ color: 'var(--text-primary)' }}>pop      r11</span>
                  </div>
                  <div style={{ display: 'flex', marginBottom: '4px', background: 'rgba(0,176,255,0.08)' }}>
                    <span style={{ width: '90px', color: 'var(--sentinel-blue)' }}>{formatOffset(hijackedEntryPoint, 131)}:</span>
                    <span style={{ width: '120px', color: '#888' }}>5A</span>
                    <span style={{ color: 'var(--text-primary)' }}>pop      rdx</span>
                  </div>
                  <div style={{ display: 'flex', marginBottom: '4px', background: 'rgba(0,176,255,0.08)' }}>
                    <span style={{ width: '90px', color: 'var(--sentinel-blue)' }}>{formatOffset(hijackedEntryPoint, 132)}:</span>
                    <span style={{ width: '120px', color: '#888' }}>59</span>
                    <span style={{ color: 'var(--text-primary)' }}>pop      rcx</span>
                  </div>
                  <div style={{ display: 'flex', marginBottom: '4px', background: 'rgba(0,176,255,0.08)' }}>
                    <span style={{ width: '90px', color: 'var(--sentinel-blue)' }}>{formatOffset(hijackedEntryPoint, 133)}:</span>
                    <span style={{ width: '120px', color: '#888' }}>E9 BB 17 FE FF</span>
                    <span style={{ color: 'var(--sentinel-blue)' }}>jmp      {originalEntryPoint} (Jump back to OEP!)</span>
                  </div>
                </div>
              </div>

            </div>
          </div>
        )}

      </div>

      {/* LOWER PANEL: TERMINAL LOGGER */}
      <footer className="dashed-box" style={{ padding: '16px', display: 'flex', gap: '20px', height: '220px', minHeight: '220px' }}>
        
        {/* Dynamic Percentage transformed HUD Graphics! */}
        {isProtecting || success !== null ? (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', width: '140px', borderRight: '1px dashed var(--border-muted)', paddingRight: '20px' }}>
            <span style={{ color: 'var(--text-muted)', fontSize: '10px', textTransform: 'uppercase', marginBottom: '8px', letterSpacing: '1px', textAlign: 'center' }}>VIRTUALIZATION TRANSFORMS</span>
            <div style={{ position: 'relative', width: '80px', height: '80px' }}>
              <svg width="80" height="80" viewBox="0 0 80 80">
                <circle cx="40" cy="40" r="36" fill="transparent" stroke="var(--bg-dark)" strokeWidth="4" />
                <circle 
                  cx="40" cy="40" r="36" 
                  fill="transparent" 
                  stroke="var(--sentinel-blue)" 
                  strokeWidth="5" 
                  strokeDasharray={circumference}
                  strokeDashoffset={strokeDashoffset}
                  strokeLinecap="round"
                  transform="rotate(-90 40 40)"
                  style={{ transition: 'stroke-dashoffset 0.35s ease' }}
                />
              </svg>
              <div style={{ position: 'absolute', top: 0, left: 0, right: 0, bottom: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', fontFamily: 'Share Tech Mono' }}>
                <span style={{ color: 'var(--sentinel-blue)', fontSize: '18px', fontWeight: 'bold' }}>{transformPercentage}%</span>
                <span style={{ color: 'var(--text-muted)', fontSize: '9px' }}>{successCount} / {totalStaged}</span>
              </div>
            </div>
          </div>
        ) : null}

        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: '0' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <h3 style={{ color: 'var(--sentinel-blue)', fontSize: '13px', letterSpacing: '1px' }}>
              04 // LOG TERMINAL CONSOLE
            </h3>
            {success && downloadFileName && (
              <a 
                href={`${API_BASE}/download?file=${downloadFileName}`}
                download
                style={{ 
                  background: 'var(--sentinel-blue)',
                  color: 'var(--bg-dark)',
                  border: '1px solid var(--sentinel-blue)',
                  padding: '4px 16px',
                  fontFamily: 'Share Tech Mono',
                  fontWeight: 'bold',
                  fontSize: '11px',
                  cursor: 'pointer',
                  textDecoration: 'none',
                  letterSpacing: '1px',
                  boxShadow: '0 0 10px var(--sentinel-blue)',
                  transition: 'all 0.15s ease'
                }}
              >
                DOWNLOAD PROTECTED BINARY (.EXE)
              </a>
            )}
          </div>

          <div 
            style={{ 
              flex: 1, 
              background: 'var(--bg-dark)', 
              border: '1px dashed var(--border-blue)', 
              padding: '10px', 
              overflowY: 'auto',
              fontFamily: 'monospace',
              fontSize: '12px',
              color: 'var(--text-primary)',
              whiteSpace: 'pre-wrap',
              lineHeight: '1.4',
              transition: 'background-color 0.15s ease, color 0.15s ease'
            }}
          >
            {logs ? logs : (
              <span style={{ color: 'var(--text-muted)' }}>[Awaiting Target staging parameters. Click 'COMPILE SECURE IMAGE' to launch sentinel compile loop...]</span>
            )}
            
            {success === true && (
              <div style={{ marginTop: '10px', padding: '8px', border: '1px dashed var(--text-green)', background: 'var(--sentinel-blue-dim)', color: 'var(--text-green)' }}>
                &gt;&gt;&gt; [SUCCESS] DYNAMIC PE RESTRESTRUCTURING COMPLETED successfully! Secure image generated at output path.
              </div>
            )}
            {success === false && (
              <div style={{ marginTop: '10px', padding: '8px', border: '1px dashed #ff1744', background: 'rgba(255,23,68,0.05)', color: '#ff1744' }}>
                &gt;&gt;&gt; [FAILED] COMPILATION INTERRUPTED. Check exception frames or relocation offsets.
              </div>
            )}
          </div>
        </div>
      </footer>

      {/* DYNAMIC TECHNICAL HELP MODAL DIALOG */}
      {isHelpOpen && (
        <div style={{
          position: 'fixed',
          top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.8)',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          zIndex: 9999,
          padding: '20px'
        }}>
          <div className="dashed-box" style={{
            background: 'var(--bg-panel)',
            width: '90%',
            maxWidth: '1000px',
            height: '85%',
            display: 'flex',
            flexDirection: 'column',
            padding: '24px',
            boxShadow: '0 0 30px rgba(0, 176, 255, 0.2)'
          }}>
            
            {/* Modal Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px dashed var(--border-blue)', paddingBottom: '12px', marginBottom: '16px' }}>
              <div>
                <h2 style={{ color: 'var(--sentinel-blue)', fontSize: '18px', letterSpacing: '2px', textTransform: 'uppercase' }}>
                  SENTINEL COMPILER SYSTEM PROTOCOL MANUAL
                </h2>
                <p style={{ color: 'var(--text-muted)', fontSize: '10px', marginTop: '2px' }}>
                  UNDERSTANDING POST-LINK SYSTEM-LEVEL BINARY PROTECTION PASSTHROUGHS
                </p>
              </div>
              <button 
                onClick={() => setIsHelpOpen(false)}
                style={{
                  background: 'transparent',
                  border: '1px solid var(--sentinel-blue)',
                  color: 'var(--sentinel-blue)',
                  padding: '4px 14px',
                  cursor: 'pointer',
                  fontFamily: 'Share Tech Mono',
                  fontSize: '12px'
                }}
              >
                CLOSE [ESC]
              </button>
            </div>

            {/* Modal Content - Scrollable */}
            <div style={{ flex: 1, overflowY: 'auto', paddingRight: '8px', fontSize: '12px', color: 'var(--text-primary)', lineHeight: '1.5' }}>
              
              {/* SYSTEM FLOW CHART */}
              <h3 style={{ color: 'var(--sentinel-blue)', fontSize: '13px', marginBottom: '8px', borderBottom: '1px solid var(--border-muted)', paddingBottom: '4px' }}>
                01 // PIPELINE SYSTEM FLOW CHART
              </h3>
              <div style={{ background: 'var(--bg-dark)', padding: '12px', borderRadius: '4px', fontFamily: 'monospace', fontSize: '11px', color: 'var(--sentinel-blue)', whiteSpace: 'pre-wrap', marginBottom: '20px', lineHeight: '1.2' }}>
{`+-----------------------+      +-----------------------+
|  Input Native x64 PE  |      |   Companion PDB Tree  |
+-----------+-----------+      +-----------+-----------+
            |                              |
            +---------------+--------------+
                            |
                            v [Mount & Ingest]
            +------------------------------+
            |  IDA Pro Repositories Tab    | ---> (Symbols Tree / Strings Scanned)
            +--------------+---------------+
                           |
                           v [User Staging Queue]
            +------------------------------+
            | Staged Functions & Strings   |
            +--------------+---------------+
                           |
                           v [COMPILE TRIGGER]
            +------------------------------+
            | Sequential VM Compilations   | ---> (Generates separate vISA bytecode)
            +--------------+---------------+
                           |
                           v [Control Flow Flattening]
            +------------------------------+
            | State Machine Dispatcher     | ---> (Injects Non-linear JMP switches)
            +--------------+---------------+
                           |
                           v [PE Section Rebuilder]
            +------------------------------+
            |  Injected Section (.shield)  | ---> (Custom stretch + Runtime Register)
            +--------------+---------------+
                           |
                           v [In-Place Hooking]
            +------------------------------+
            |  5-Byte Relative JMP Patch   | ---> (Rewrites original prologues)
            +--------------+---------------+
                           |
                           v [OEP Trampoline]
            +------------------------------+
            |  EP Hijack to vISA Decrypter | ---> (Anti-Debug + String XOR payload)
            +--------------+---------------+
                           |
                           v
            +------------------------------+
            |  Protected Native Binary     | ---> (Fully loader-ready executable!)
            +------------------------------+`}
              </div>

              {/* STEP THROUGH TECHNICAL EXPLANATION */}
              <h3 style={{ color: 'var(--sentinel-blue)', fontSize: '13px', marginBottom: '8px', borderBottom: '1px solid var(--border-muted)', paddingBottom: '4px' }}>
                02 // PROTOCOL PIPELINE STEP-BY-STEP FLOW
              </h3>
              
              <div style={{ marginBottom: '16px' }}>
                <span style={{ color: 'var(--sentinel-blue)', fontWeight: 'bold', display: 'block' }}>FLOW 1 // MULTI-SYMBOL MOUNT & INGESTION (IDA PRO TABBED LAYOUT)</span>
                <p style={{ color: 'var(--text-muted)', marginTop: '4px', marginBottom: '10px' }}>
                  The companion PDB file is parsed using Rust APIs to resolve exact 32-bit Relative Virtual Addresses (RVAs) for all procedure and public symbols. Plaint-text ASCII string tables are extracted via in-place linear scanning of the PE’s read-only data segment. This tree is mapped into high-density IDA Pro style repository panels, allowing the staging of multiple simultaneous target functions.
                </p>
              </div>

              <div style={{ marginBottom: '16px' }}>
                <span style={{ color: 'var(--sentinel-blue)', fontWeight: 'bold', display: 'block' }}>FLOW 2 // SEQUENTIAL VM INTERPRETER COMPILATION</span>
                <p style={{ color: 'var(--text-muted)', marginTop: '4px', marginBottom: '10px' }}>
                  The compiler generates separate Virtual Machine (VM) execution handlers and unique compiled bytecode arrays sequentially for every single staged function in the queue. Each VM is independent, maintaining its own registers, localized scratch stacks, opcode lookup tables, and custom operations, ensuring that the original x64 instruction semantics are completely obfuscated into virtual instructions (vISA).
                </p>
              </div>

              <div style={{ marginBottom: '16px' }}>
                <span style={{ color: 'var(--sentinel-blue)', fontWeight: 'bold', display: 'block' }}>FLOW 3 // CONTROL FLOW FLATTENING (CFF OBFUSCATION)</span>
                <p style={{ color: 'var(--text-muted)', marginTop: '4px', marginBottom: '10px' }}>
                  To destroy basic block linearity and prevent structural visual mapping in decompilers (such as Ghidra or IDA Pro), the execution structure of each function is flattened. A central state dispatcher, utilizing a pseudo-random state-key, directs execution dynamically via switch jumps to localized basic blocks, transforming linear function flows into a hub-and-spoke topology.
                </p>
              </div>

              <div style={{ marginBottom: '16px' }}>
                <span style={{ color: 'var(--sentinel-blue)', fontWeight: 'bold', display: 'block' }}>FLOW 4 // PE REBUILDING & CUSTOM SECTION STRETCHING</span>
                <p style={{ color: 'var(--text-muted)', marginTop: '4px', marginBottom: '10px' }}>
                  The PE section header array is extended by appending a custom header mapped as `0xE0000060` (Executable, Readable, Writable). The compiler increments `NumberOfSections` in the COFF header, updates `SizeOfImage` inside the Optional Header to retain loader alignment, and stretches the file buffer to write all sequentially compiled VM bodies and custom bytecode streams straight into the new `.shield` section.
                </p>
              </div>

              <div style={{ marginBottom: '16px' }}>
                <span style={{ color: 'var(--sentinel-blue)', fontWeight: 'bold', display: 'block' }}>FLOW 5 // IN-PLACE RELATIVE JMP HOOKING</span>
                <p style={{ color: 'var(--text-muted)', marginTop: '4px', marginBottom: '10px' }}>
                  To securely route traffic from the original execution flows into our virtualized VM shells, the entry point prologue of each staged function in the original `.text` section is surgically patched. A 5-byte relative jump stub (`jmp rel32`) is written in place, calculating the dynamic relative offset from the function's original address to its specific VM entry in `.shield`. Any boundary overrun is prevented by keeping stubs strictly bounded within 5 bytes.
                </p>
              </div>

              <div style={{ marginBottom: '16px' }}>
                <span style={{ color: 'var(--sentinel-blue)', fontWeight: 'bold', display: 'block' }}>FLOW 6 // ENTRY POINT HIJACK & DYNAMIC DECRYPTION TRAMPOLINE</span>
                <p style={{ color: 'var(--text-muted)', marginTop: '4px', marginBottom: '10px' }}>
                  The AddressOfEntryPoint variable inside the Optional Header is hijacked, redirecting initial program execution directly into our injected decrypter trampoline. When spawned, the trampoline resolves the dynamic ASLR ImageBase, decrypts staged `.rdata` strings in memory, initializes Structured Exception Handling (SEH) runtime unwind tables with `RtlAddFunctionTable`, runs anti-debug checks, and jumps back to the Original Entry Point (OEP) to continue standard execution securely.
                </p>
              </div>

            </div>

            {/* Modal Footer */}
            <div style={{ marginTop: '16px', paddingTop: '12px', borderTop: '1px dashed var(--border-blue)', textAlign: 'right', fontSize: '10px', color: 'var(--text-muted)' }}>
              BINARYDEFENDER COMPILER SUITE V2.6 // DESIGNED IN SLATE-CONCRETE CAD contrast.
            </div>

          </div>
        </div>
      )}

    </div>
  );
}
