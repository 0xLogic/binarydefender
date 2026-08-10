//! Architectural Proof-of-Concept: Obfuscation Compiler & PE Generator Pipeline
//!
//! This module acts as a complete end-to-end compiler-protector pipeline. It:
//!   1. Takes an input algorithm in native representation (Fibonacci).
//!   2. Lifts it to LLVM-like SSA IR and reconstructs the CFG.
//!   3. Executes the Middle-End Virtualization Pass, creating a randomized vISA and compiling to bytecode.
//!   4. Generates a standalone, dependency-free Rust source file containing the VM Runtime,
//!      the randomized vISA decoder, and the static compiled bytecode.
//!   5. Invokes the compiler backend (`rustc`) to output a native Windows x64 binary (`protected_binary.exe`).
//!   6. Runs the compiled executable, proving that a virtualized standalone binary executes natively and correctly.

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::process::Command;

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

// ============================================================================
// Data Structures: Native Register Assembly Model
// ============================================================================
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Register {
    Rax = 0,
    Rbx = 1,
    Rcx = 2,
    Rdx = 3,
}

impl Register {
    pub fn as_str(&self) -> &'static str {
        match self {
            Register::Rax => "rax",
            Register::Rbx => "rbx",
            Register::Rcx => "rcx",
            Register::Rdx => "rdx",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operand {
    Reg(Register),
    Imm(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeInstruction {
    Mov(Register, Operand),
    Add(Register, Operand),
    Sub(Register, Operand),
    Cmp(Register, Operand),
    Jmp(String),
    Je(String),
    Jg(String),
    Ret,
}

#[derive(Debug, Clone)]
pub struct NativeFunction {
    pub name: String,
    pub instructions: Vec<(Option<String>, NativeInstruction)>,
}

// ============================================================================
// Data Structures: LLVM-like SSA Intermediate Representation (IR)
// ============================================================================
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrValue {
    Const(u64),
    Temp(usize),
}

impl IrValue {
    pub fn to_string(&self) -> String {
        match self {
            IrValue::Const(c) => format!("{}", c),
            IrValue::Temp(t) => format!("%{}", t),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    Eq,
    Gt,
}

impl Condition {
    pub fn as_str(&self) -> &'static str {
        match self {
            Condition::Eq => "eq",
            Condition::Gt => "gt",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrInstruction {
    LoadReg(usize, Register),
    StoreReg(Register, IrValue),
    Add(usize, IrValue, IrValue),
    Sub(usize, IrValue, IrValue),
    Cmp(IrValue, IrValue),
    Br(String),
    CondBr(Condition, String, String),
    Ret,
}

#[derive(Debug, Clone)]
pub struct IrBasicBlock {
    pub label: String,
    pub instructions: Vec<IrInstruction>,
}

#[derive(Debug, Clone)]
pub struct ControlFlowGraph {
    pub name: String,
    pub entry_label: String,
    pub blocks: HashMap<String, IrBasicBlock>,
    pub block_order: Vec<String>,
}

// ============================================================================
// Phase A & B: The Lifter & CFG Reconstruction
// ============================================================================
pub struct Lifter;

impl Lifter {
    pub fn lift(func: &NativeFunction) -> ControlFlowGraph {
        let mut block_bounds = Vec::new();
        block_bounds.push(0);

        for (i, (label, inst)) in func.instructions.iter().enumerate() {
            if label.is_some() && i > 0 {
                block_bounds.push(i);
            }
            if matches!(
                inst,
                NativeInstruction::Jmp(_)
                    | NativeInstruction::Je(_)
                    | NativeInstruction::Jg(_)
                    | NativeInstruction::Ret
            ) {
                if i + 1 < func.instructions.len() {
                    block_bounds.push(i + 1);
                }
            }
        }

        block_bounds.sort();
        block_bounds.dedup();

        let mut native_blocks = Vec::new();
        for i in 0..block_bounds.len() {
            let start = block_bounds[i];
            let end = if i + 1 < block_bounds.len() {
                block_bounds[i + 1]
            } else {
                func.instructions.len()
            };

            let instructions = &func.instructions[start..end];
            let label = if let Some(ref lbl) = instructions[0].0 {
                lbl.clone()
            } else if start == 0 {
                "entry".to_string()
            } else {
                format!("block_0x{:02X}", start)
            };

            native_blocks.push((label, instructions));
        }

        let mut blocks = HashMap::new();
        let mut block_order = Vec::new();
        let entry_label = native_blocks[0].0.clone();

        let mut next_ssa_id = 0;

        for idx in 0..native_blocks.len() {
            let (label, raw_insts) = &native_blocks[idx];
            block_order.push(label.clone());

            let mut ir_instructions = Vec::new();
            let next_physical_block_label = if idx + 1 < native_blocks.len() {
                Some(native_blocks[idx + 1].0.clone())
            } else {
                None
            };

            for (_, inst) in raw_insts.iter() {
                match inst {
                    NativeInstruction::Mov(dest, src) => {
                        let src_val = match src {
                            Operand::Imm(imm) => IrValue::Const(*imm),
                            Operand::Reg(reg) => {
                                let t = next_ssa_id;
                                next_ssa_id += 1;
                                ir_instructions.push(IrInstruction::LoadReg(t, *reg));
                                IrValue::Temp(t)
                            }
                        };
                        ir_instructions.push(IrInstruction::StoreReg(*dest, src_val));
                    }
                    NativeInstruction::Add(dest, src) => {
                        let t_dest = next_ssa_id;
                        next_ssa_id += 1;
                        ir_instructions.push(IrInstruction::LoadReg(t_dest, *dest));

                        let src_val = match src {
                            Operand::Imm(imm) => IrValue::Const(*imm),
                            Operand::Reg(reg) => {
                                let t_src = next_ssa_id;
                                next_ssa_id += 1;
                                ir_instructions.push(IrInstruction::LoadReg(t_src, *reg));
                                IrValue::Temp(t_src)
                            }
                        };

                        let t_res = next_ssa_id;
                        next_ssa_id += 1;
                        ir_instructions.push(IrInstruction::Add(t_res, IrValue::Temp(t_dest), src_val));
                        ir_instructions.push(IrInstruction::StoreReg(*dest, IrValue::Temp(t_res)));
                    }
                    NativeInstruction::Sub(dest, src) => {
                        let t_dest = next_ssa_id;
                        next_ssa_id += 1;
                        ir_instructions.push(IrInstruction::LoadReg(t_dest, *dest));

                        let src_val = match src {
                            Operand::Imm(imm) => IrValue::Const(*imm),
                            Operand::Reg(reg) => {
                                let t_src = next_ssa_id;
                                next_ssa_id += 1;
                                ir_instructions.push(IrInstruction::LoadReg(t_src, *reg));
                                IrValue::Temp(t_src)
                            }
                        };

                        let t_res = next_ssa_id;
                        next_ssa_id += 1;
                        ir_instructions.push(IrInstruction::Sub(t_res, IrValue::Temp(t_dest), src_val));
                        ir_instructions.push(IrInstruction::StoreReg(*dest, IrValue::Temp(t_res)));
                    }
                    NativeInstruction::Cmp(dest, src) => {
                        let t_dest = next_ssa_id;
                        next_ssa_id += 1;
                        ir_instructions.push(IrInstruction::LoadReg(t_dest, *dest));

                        let src_val = match src {
                            Operand::Imm(imm) => IrValue::Const(*imm),
                            Operand::Reg(reg) => {
                                let t_src = next_ssa_id;
                                next_ssa_id += 1;
                                ir_instructions.push(IrInstruction::LoadReg(t_src, *reg));
                                IrValue::Temp(t_src)
                            }
                        };

                        ir_instructions.push(IrInstruction::Cmp(IrValue::Temp(t_dest), src_val));
                    }
                    NativeInstruction::Jmp(target) => {
                        ir_instructions.push(IrInstruction::Br(target.clone()));
                    }
                    NativeInstruction::Je(target) => {
                        let fallthrough = next_physical_block_label
                            .as_ref()
                            .expect("Branch fallthrough label missing")
                            .clone();
                        ir_instructions.push(IrInstruction::CondBr(
                            Condition::Eq,
                            target.clone(),
                            fallthrough,
                        ));
                    }
                    NativeInstruction::Jg(target) => {
                        let fallthrough = next_physical_block_label
                            .as_ref()
                            .expect("Branch fallthrough label missing")
                            .clone();
                        ir_instructions.push(IrInstruction::CondBr(
                            Condition::Gt,
                            target.clone(),
                            fallthrough,
                        ));
                    }
                    NativeInstruction::Ret => {
                        ir_instructions.push(IrInstruction::Ret);
                    }
                }
            }

            let has_terminator = ir_instructions.iter().last().map_or(false, |inst| {
                matches!(
                    inst,
                    IrInstruction::Br(_) | IrInstruction::CondBr(_, _, _) | IrInstruction::Ret
                )
            });

            if !has_terminator {
                if let Some(ref next_lbl) = next_physical_block_label {
                    ir_instructions.push(IrInstruction::Br(next_lbl.clone()));
                } else {
                    ir_instructions.push(IrInstruction::Ret);
                }
            }

            blocks.insert(
                label.clone(),
                IrBasicBlock {
                    label: label.clone(),
                    instructions: ir_instructions,
                },
            );
        }

        ControlFlowGraph {
            name: func.name.clone(),
            entry_label,
            blocks,
            block_order,
        }
    }
}

// ============================================================================
// Phase C: Opcode Randomization & Bytecode Compilation
// ============================================================================
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VirtualOpcode {
    PushReg,
    PopReg,
    PushConst,
    Add,
    Sub,
    Cmp,
    Jmp,
    Jz,
    Jnz,
    Jg,
    Ret,
}

impl VirtualOpcode {
    pub fn name(&self) -> &'static str {
        match self {
            VirtualOpcode::PushReg => "PushReg",
            VirtualOpcode::PopReg => "PopReg",
            VirtualOpcode::PushConst => "PushConst",
            VirtualOpcode::Add => "Add",
            VirtualOpcode::Sub => "Sub",
            VirtualOpcode::Cmp => "Cmp",
            VirtualOpcode::Jmp => "Jmp",
            VirtualOpcode::Jz => "Jz",
            VirtualOpcode::Jnz => "Jnz",
            VirtualOpcode::Jg => "Jg",
            VirtualOpcode::Ret => "Ret",
        }
    }
}

pub struct IsaMapper {
    opcode_to_byte: HashMap<VirtualOpcode, u8>,
}

impl IsaMapper {
    pub fn generate_random(seed: u64) -> Self {
        let opcodes = vec![
            VirtualOpcode::PushReg,
            VirtualOpcode::PopReg,
            VirtualOpcode::PushConst,
            VirtualOpcode::Add,
            VirtualOpcode::Sub,
            VirtualOpcode::Cmp,
            VirtualOpcode::Jmp,
            VirtualOpcode::Jz,
            VirtualOpcode::Jnz,
            VirtualOpcode::Jg,
            VirtualOpcode::Ret,
        ];

        let mut rng = SimpleRng::new(seed);
        let mut byte_pool: Vec<u8> = (0..=255).collect();
        rng.shuffle(&mut byte_pool);

        let mut opcode_to_byte = HashMap::new();
        for (i, op) in opcodes.into_iter().enumerate() {
            opcode_to_byte.insert(op, byte_pool[i]);
        }

        Self { opcode_to_byte }
    }

    pub fn encode(&self, op: VirtualOpcode) -> u8 {
        *self.opcode_to_byte.get(&op).unwrap()
    }
}

struct PendingJump {
    instruction_offset: usize,
    target_block: String,
}

pub struct VirtualizationPass;

impl VirtualizationPass {
    pub fn compile(cfg: &ControlFlowGraph, isa: &IsaMapper) -> Vec<u8> {
        let mut bytecode = Vec::new();
        let mut block_offsets = HashMap::new();
        let mut pending_jumps = Vec::new();

        let mut sorted_labels = vec![cfg.entry_label.clone()];
        for label in &cfg.block_order {
            if *label != cfg.entry_label {
                sorted_labels.push(label.clone());
            }
        }

        for label in &sorted_labels {
            let block = &cfg.blocks[label];
            block_offsets.insert(label.clone(), bytecode.len());

            for ir_inst in &block.instructions {
                match ir_inst {
                    IrInstruction::LoadReg(_, reg) => {
                        bytecode.push(isa.encode(VirtualOpcode::PushReg));
                        bytecode.push(*reg as u8);
                    }
                    IrInstruction::StoreReg(reg, val) => {
                        match val {
                            IrValue::Const(c) => {
                                bytecode.push(isa.encode(VirtualOpcode::PushConst));
                                bytecode.extend_from_slice(&c.to_le_bytes());
                            }
                            IrValue::Temp(_) => {}
                        }
                        bytecode.push(isa.encode(VirtualOpcode::PopReg));
                        bytecode.push(*reg as u8);
                    }
                    IrInstruction::Add(_, _, val2) => {
                        if let IrValue::Const(c) = val2 {
                            bytecode.push(isa.encode(VirtualOpcode::PushConst));
                            bytecode.extend_from_slice(&c.to_le_bytes());
                        }
                        bytecode.push(isa.encode(VirtualOpcode::Add));
                    }
                    IrInstruction::Sub(_, _, val2) => {
                        if let IrValue::Const(c) = val2 {
                            bytecode.push(isa.encode(VirtualOpcode::PushConst));
                            bytecode.extend_from_slice(&c.to_le_bytes());
                        }
                        bytecode.push(isa.encode(VirtualOpcode::Sub));
                    }
                    IrInstruction::Cmp(_, val2) => {
                        if let IrValue::Const(c) = val2 {
                            bytecode.push(isa.encode(VirtualOpcode::PushConst));
                            bytecode.extend_from_slice(&c.to_le_bytes());
                        }
                        bytecode.push(isa.encode(VirtualOpcode::Cmp));
                    }
                    IrInstruction::Br(target) => {
                        bytecode.push(isa.encode(VirtualOpcode::Jmp));
                        pending_jumps.push(PendingJump {
                            instruction_offset: bytecode.len(),
                            target_block: target.clone(),
                        });
                        bytecode.push(0x00);
                        bytecode.push(0x00);
                    }
                    IrInstruction::CondBr(cond, true_lbl, false_lbl) => {
                        let jump_op = match cond {
                            Condition::Eq => VirtualOpcode::Jz,
                            Condition::Gt => VirtualOpcode::Jg,
                        };

                        bytecode.push(isa.encode(jump_op));
                        pending_jumps.push(PendingJump {
                            instruction_offset: bytecode.len(),
                            target_block: true_lbl.clone(),
                        });
                        bytecode.push(0x00);
                        bytecode.push(0x00);

                        bytecode.push(isa.encode(VirtualOpcode::Jmp));
                        pending_jumps.push(PendingJump {
                            instruction_offset: bytecode.len(),
                            target_block: false_lbl.clone(),
                        });
                        bytecode.push(0x00);
                        bytecode.push(0x00);
                    }
                    IrInstruction::Ret => {
                        bytecode.push(isa.encode(VirtualOpcode::Ret));
                    }
                }
            }
        }

        for patch in &pending_jumps {
            let target_offset = *block_offsets.get(&patch.target_block).unwrap();
            let dest_u16 = target_offset as u16;
            let bytes = dest_u16.to_le_bytes();
            bytecode[patch.instruction_offset] = bytes[0];
            bytecode[patch.instruction_offset + 1] = bytes[1];
        }

        bytecode
    }
}

// ============================================================================
// Main Code Compilation & PE Generation Loop
// ============================================================================
fn main() {
    println!("+----------------------------------------------------------------------+");
    println!("|             OBFUSCATION COMPILER PIPELINE - STANDALONE BINARY        |");
    println!("+----------------------------------------------------------------------+");
    println!("Generating, virtualizing, and compiling an executable...");

    // Setup input algorithm (Fibonacci)
    let native_fib = NativeFunction {
        name: "fibonacci".to_string(),
        instructions: vec![
            (Some("_start".to_string()), NativeInstruction::Mov(Register::Rbx, Operand::Imm(0))),
            (None, NativeInstruction::Mov(Register::Rcx, Operand::Imm(1))),
            (None, NativeInstruction::Cmp(Register::Rax, Operand::Imm(0))),
            (None, NativeInstruction::Je("_exit".to_string())),
            (Some("_loop".to_string()), NativeInstruction::Mov(Register::Rdx, Operand::Reg(Register::Rbx))),
            (None, NativeInstruction::Add(Register::Rbx, Operand::Reg(Register::Rcx))),
            (None, NativeInstruction::Mov(Register::Rcx, Operand::Reg(Register::Rdx))),
            (None, NativeInstruction::Sub(Register::Rax, Operand::Imm(1))),
            (None, NativeInstruction::Cmp(Register::Rax, Operand::Imm(0))),
            (None, NativeInstruction::Jg("_loop".to_string())),
            (Some("_exit".to_string()), NativeInstruction::Ret),
        ],
    };

    println!("[1/4] Lifting source function to compiler IR...");
    let cfg = Lifter::lift(&native_fib);

    println!("[2/4] Randomizing Virtual ISA and compiling to VM bytecode...");
    let seed = 0x1337C0DE;
    let isa = IsaMapper::generate_random(seed);
    let bytecode = VirtualizationPass::compile(&cfg, &isa);

    // Format bytecode as static array text
    let mut bytecode_tokens = Vec::new();
    for byte in &bytecode {
        bytecode_tokens.push(format!("0x{:02X}", byte));
    }
    let bytecode_str = bytecode_tokens.join(", ");

    // Create randomized decoder match statement text
    let opcodes = vec![
        VirtualOpcode::PushReg,
        VirtualOpcode::PopReg,
        VirtualOpcode::PushConst,
        VirtualOpcode::Add,
        VirtualOpcode::Sub,
        VirtualOpcode::Cmp,
        VirtualOpcode::Jmp,
        VirtualOpcode::Jz,
        VirtualOpcode::Jnz,
        VirtualOpcode::Jg,
        VirtualOpcode::Ret,
    ];

    let mut match_arms = Vec::new();
    for op in opcodes {
        let assigned_byte = isa.encode(op);
        match_arms.push(format!("        0x{:02X} => Some(VirtualOpcode::{}),", assigned_byte, op.name()));
    }
    let match_statement_str = match_arms.join("\n");

    // Standalone source file template
    let standalone_source_code = format!(
r#"// Standalone Obfuscated Virtualized Binary
// Automatically compiled by BinaryDefender Obfuscation Compiler

use std::env;

#[derive(Debug, Clone, Copy, Default)]
pub struct RegState {{
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub zf: bool,
    pub sf: bool,
}}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtualOpcode {{
    PushReg,
    PopReg,
    PushConst,
    Add,
    Sub,
    Cmp,
    Jmp,
    Jz,
    Jnz,
    Jg,
    Ret,
}}

// The static compiled, randomized bytecode representing the Fibonacci function
const BYTECODE: &[u8] = &[{bytecode}];

// Fast dynamic lookup mapping randomized opcode bytes back to the VM opcodes
fn decode_opcode(byte: u8) -> Option<VirtualOpcode> {{
    match byte {{
{match_arms}
        _ => None,
    }}
}}

fn main() {{
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {{
        eprintln!("Usage: {{}} <input_n>", args[0]);
        std::process::exit(1);
    }}

    let n: u64 = args[1].parse().unwrap_or_else(|_| {{
        eprintln!("Error: Input must be a valid 64-bit integer.");
        std::process::exit(1);
    }});

    println!("+-------------------------------------------------------------+");
    println!("|          VIRTUALIZED Standalone Native Windows Binary       |");
    println!("+-------------------------------------------------------------+");
    println!("[NATIVE] Input parameter received: N = {{}}", n);
    println!("[NATIVE] Initializing virtual registers RAX = {{}}", n);

    let mut reg_state = RegState {{
        rax: n,
        ..Default::default()
    }};

    println!("[NATIVE] Transitioning execution to VM interpreter...");
    execute_vm(BYTECODE, &mut reg_state);

    println!("[NATIVE] Returned from Virtual Machine execution context.");
    println!("[NATIVE] Final protected output: FIB(N) = Register RBX = {{}}", reg_state.rbx);
    println!("+-------------------------------------------------------------+");
}}

fn execute_vm(bytecode: &[u8], reg_state: &mut RegState) {{
    let mut vip = 0;
    let mut stack: Vec<u64> = Vec::new();

    while vip < bytecode.len() {{
        let current_ip = vip;
        let opcode_byte = bytecode[vip];
        vip += 1;

        let opcode = match decode_opcode(opcode_byte) {{
            Some(op) => op,
            None => {{
                panic!("CRITICAL EXCEPTION: Executed unknown/corrupt bytecode 0x{{:02X}} at IP: 0x{{:04X}}", opcode_byte, current_ip);
            }}
        }};

        match opcode {{
            VirtualOpcode::PushReg => {{
                let reg_idx = bytecode[vip];
                vip += 1;
                let val = match reg_idx {{
                    0 => reg_state.rax,
                    1 => reg_state.rbx,
                    2 => reg_state.rcx,
                    3 => reg_state.rdx,
                    _ => panic!("VM Stack Error: Invalid register index"),
                }};
                stack.push(val);
            }}
            VirtualOpcode::PopReg => {{
                let reg_idx = bytecode[vip];
                vip += 1;
                let val = stack.pop().expect("VM Stack Underflow during PopReg");
                match reg_idx {{
                    0 => reg_state.rax = val,
                    1 => reg_state.rbx = val,
                    2 => reg_state.rcx = val,
                    3 => reg_state.rdx = val,
                    _ => panic!("VM Stack Error: Invalid register index"),
                }}
            }}
            VirtualOpcode::PushConst => {{
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&bytecode[vip..vip + 8]);
                vip += 8;
                let val = u64::from_le_bytes(bytes);
                stack.push(val);
            }}
            VirtualOpcode::Add => {{
                let val2 = stack.pop().expect("VM Stack Underflow during Add");
                let val1 = stack.pop().expect("VM Stack Underflow during Add");
                stack.push(val1.wrapping_add(val2));
            }}
            VirtualOpcode::Sub => {{
                let val2 = stack.pop().expect("VM Stack Underflow during Sub");
                let val1 = stack.pop().expect("VM Stack Underflow during Sub");
                stack.push(val1.wrapping_sub(val2));
            }}
            VirtualOpcode::Cmp => {{
                let val2 = stack.pop().expect("VM Stack Underflow during Cmp");
                let val1 = stack.pop().expect("VM Stack Underflow during Cmp");
                reg_state.zf = val1 == val2;
                reg_state.sf = val1 < val2;
            }}
            VirtualOpcode::Jmp => {{
                let mut bytes = [0u8; 2];
                bytes.copy_from_slice(&bytecode[vip..vip + 2]);
                let dest = u16::from_le_bytes(bytes) as usize;
                vip = dest;
            }}
            VirtualOpcode::Jz => {{
                let mut bytes = [0u8; 2];
                bytes.copy_from_slice(&bytecode[vip..vip + 2]);
                let dest = u16::from_le_bytes(bytes) as usize;
                if reg_state.zf {{
                    vip = dest;
                }} else {{
                    vip += 2;
                }}
            }}
            VirtualOpcode::Jnz => {{
                let mut bytes = [0u8; 2];
                bytes.copy_from_slice(&bytecode[vip..vip + 2]);
                let dest = u16::from_le_bytes(bytes) as usize;
                if !reg_state.zf {{
                    vip = dest;
                }} else {{
                    vip += 2;
                }}
            }}
            VirtualOpcode::Jg => {{
                let mut bytes = [0u8; 2];
                bytes.copy_from_slice(&bytecode[vip..vip + 2]);
                let dest = u16::from_le_bytes(bytes) as usize;
                if !reg_state.zf && !reg_state.sf {{
                    vip = dest;
                }} else {{
                    vip += 2;
                }}
            }}
            VirtualOpcode::Ret => {{
                return;
            }}
        }}
    }}
}}
"#,
        bytecode = bytecode_str,
        match_arms = match_statement_str
    );

    println!("[3/4] Writing auto-generated standalone protected source code file...");
    let temp_src_path = "temp_protected_project.rs";
    let mut file = File::create(temp_src_path).expect("Failed to create temporary project file");
    file.write_all(standalone_source_code.as_bytes()).expect("Failed to write standalone source code");

    println!("[4/4] Compiling temporary source file into a native Windows x64 executable...");
    // We invoke rustc explicitly to generate a native standalone PE executable .exe file
    let compile_status = Command::new("rustc")
        .args(&[temp_src_path, "-o", "protected_binary.exe"])
        .status()
        .expect("Failed to invoke rustc. Make sure rustc is installed in your system PATH.");

    // Clean up temporary source file
    let _ = std::fs::remove_file(temp_src_path);

    if compile_status.success() {
        println!("\n[SUCCESS] Standing native x64 Windows binary generated successfully!");
        println!("Output File: protected_binary.exe\n");

        // Execute the generated native protected binary with inputs
        for n in &[5, 10, 15] {
            println!(">>> RUNNING Standalone Virtualized Binary with parameter N = {}...", n);
            let run_output = Command::new("./protected_binary.exe")
                .arg(n.to_string())
                .output()
                .expect("Failed to run compiled protected_binary.exe");

            let stdout = String::from_utf8_lossy(&run_output.stdout);
            print!("{}", stdout);
        }
    } else {
        panic!("CRITICAL: Compilation failed inside rustc backend!");
    }
}
