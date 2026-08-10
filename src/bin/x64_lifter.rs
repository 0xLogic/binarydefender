//! Architectural Proof-of-Concept: Low-Level X64 Machine Code Lifter & Virtualizer
//!
//! This module implements a complete machine-code binary lifting pipeline that
//! decodes raw x64 instructions from binary bytes, resolves relative branch offsets
//! into symbolic basic block labels, lifts them into an SSA LLVM-like IR,
//! reconstructs the CFG, virtualizes the IR into randomized bytecode,
//! and executes it via the VM Interpreter Runtime.
//!
//! Supported X64 Instruction Decoding:
//!   - MOV rax/rbx, imm32  (48 C7 C0 / 48 C7 C3)
//!   - ADD rax, rbx        (48 01 D8)
//!   - ADD rbx, rax        (48 01 C3)
//!   - SUB rax/rbx, imm8   (48 83 E8 / 48 83 EB)
//!   - CMP rax/rbx, imm8   (48 83 F8 / 48 83 FB)
//!   - JMP rel8            (EB ib)
//!   - JE rel8             (74 ib)
//!   - JNE rel8            (75 ib)
//!   - RET                 (C3)

use std::collections::{HashMap, HashSet};

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
    Mul(Register, Operand),
    Cmp(Register, Operand),
    Jmp(String),
    Je(String),
    Jne(String),
    Ret,
}

#[derive(Debug, Clone)]
pub struct NativeFunction {
    pub name: String,
    pub instructions: Vec<(Option<String>, NativeInstruction)>,
}

// ============================================================================
// Machine Code Decoder: Low-Level X64 Instruction Set Parser
// ============================================================================
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum X64Instruction {
    MovImm(Register, u64),
    AddReg(Register, Register),
    SubImm(Register, u64),
    CmpImm(Register, u64),
    JmpRel(i8),
    JeRel(i8),
    JneRel(i8),
    Ret,
}

#[derive(Debug, Clone)]
pub struct ParsedInstruction {
    pub offset: usize, // Starting byte offset of instruction
    pub size: usize,   // Size of instruction in bytes
    pub inst: X64Instruction,
}

pub struct X64Decoder;

impl X64Decoder {
    /// Parses raw x64 bytes into structured abstract X64 instructions.
    pub fn decode_bytes(bytes: &[u8]) -> Vec<ParsedInstruction> {
        let mut instructions = Vec::new();
        let mut pc = 0;

        while pc < bytes.len() {
            let start_pc = pc;

            // Ensure we don't read out of bounds
            if pc >= bytes.len() {
                break;
            }

            let byte = bytes[pc];

            // 1. Decode RET (0xC3)
            if byte == 0xC3 {
                instructions.push(ParsedInstruction {
                    offset: start_pc,
                    size: 1,
                    inst: X64Instruction::Ret,
                });
                pc += 1;
                continue;
            }

            // 2. Decode Short jumps (EB, 74, 75)
            if byte == 0xEB {
                let offset = bytes[pc + 1] as i8;
                instructions.push(ParsedInstruction {
                    offset: start_pc,
                    size: 2,
                    inst: X64Instruction::JmpRel(offset),
                });
                pc += 2;
                continue;
            }
            if byte == 0x74 {
                let offset = bytes[pc + 1] as i8;
                instructions.push(ParsedInstruction {
                    offset: start_pc,
                    size: 2,
                    inst: X64Instruction::JeRel(offset),
                });
                pc += 2;
                continue;
            }
            if byte == 0x75 {
                let offset = bytes[pc + 1] as i8;
                instructions.push(ParsedInstruction {
                    offset: start_pc,
                    size: 2,
                    inst: X64Instruction::JneRel(offset),
                });
                pc += 2;
                continue;
            }

            // 3. Decode instructions with prefix REX.W (0x48)
            if byte == 0x48 {
                let op1 = bytes[pc + 1];
                let op2 = bytes[pc + 2];

                // 48 C7 C0 / 48 C7 C3 -> MOV reg, imm32
                if op1 == 0xC7 {
                    if op2 == 0xC0 {
                        // MOV rax, imm32
                        let mut imm_bytes = [0u8; 4];
                        imm_bytes.copy_from_slice(&bytes[pc + 3..pc + 7]);
                        let val = u32::from_le_bytes(imm_bytes) as u64;
                        instructions.push(ParsedInstruction {
                            offset: start_pc,
                            size: 7,
                            inst: X64Instruction::MovImm(Register::Rax, val),
                        });
                        pc += 7;
                        continue;
                    } else if op2 == 0xC3 {
                        // MOV rbx, imm32
                        let mut imm_bytes = [0u8; 4];
                        imm_bytes.copy_from_slice(&bytes[pc + 3..pc + 7]);
                        let val = u32::from_le_bytes(imm_bytes) as u64;
                        instructions.push(ParsedInstruction {
                            offset: start_pc,
                            size: 7,
                            inst: X64Instruction::MovImm(Register::Rbx, val),
                        });
                        pc += 7;
                        continue;
                    }
                }

                // 48 01 D8 -> ADD rax, rbx
                if op1 == 0x01 && op2 == 0xD8 {
                    instructions.push(ParsedInstruction {
                        offset: start_pc,
                        size: 3,
                        inst: X64Instruction::AddReg(Register::Rax, Register::Rbx),
                    });
                    pc += 3;
                    continue;
                }

                // 48 01 C3 -> ADD rbx, rax
                if op1 == 0x01 && op2 == 0xC3 {
                    instructions.push(ParsedInstruction {
                        offset: start_pc,
                        size: 3,
                        inst: X64Instruction::AddReg(Register::Rbx, Register::Rax),
                    });
                    pc += 3;
                    continue;
                }

                // 48 83 E8 / 48 83 EB -> SUB reg, imm8
                if op1 == 0x83 {
                    if op2 == 0xE8 {
                        // SUB rax, imm8
                        let val = bytes[pc + 3] as u64;
                        instructions.push(ParsedInstruction {
                            offset: start_pc,
                            size: 4,
                            inst: X64Instruction::SubImm(Register::Rax, val),
                        });
                        pc += 4;
                        continue;
                    } else if op2 == 0xEB {
                        // SUB rbx, imm8
                        let val = bytes[pc + 3] as u64;
                        instructions.push(ParsedInstruction {
                            offset: start_pc,
                            size: 4,
                            inst: X64Instruction::SubImm(Register::Rbx, val),
                        });
                        pc += 4;
                        continue;
                    }
                }

                // 48 83 F8 / 48 83 FB -> CMP reg, imm8
                if op1 == 0x83 {
                    if op2 == 0xF8 {
                        // CMP rax, imm8
                        let val = bytes[pc + 3] as u64;
                        instructions.push(ParsedInstruction {
                            offset: start_pc,
                            size: 4,
                            inst: X64Instruction::CmpImm(Register::Rax, val),
                        });
                        pc += 4;
                        continue;
                    } else if op2 == 0xFB {
                        // CMP rbx, imm8
                        let val = bytes[pc + 3] as u64;
                        instructions.push(ParsedInstruction {
                            offset: start_pc,
                            size: 4,
                            inst: X64Instruction::CmpImm(Register::Rbx, val),
                        });
                        pc += 4;
                        continue;
                    }
                }
            }

            panic!(
                "X64 DECODER EXCEPTION: Unimplemented/Unknown opcode byte 0x{:02X} at PC: 0x{:X}",
                byte, pc
            );
        }

        instructions
    }

    /// Converts raw x64 instructions to symbolic, label-resolved Native Assembly.
    pub fn lift_to_native(name: &str, parsed: &[ParsedInstruction]) -> NativeFunction {
        let mut jump_targets = HashSet::new();

        // Pass 1: Identify all absolute byte offsets targeted by branch instructions
        for p_inst in parsed {
            let next_pc = p_inst.offset + p_inst.size;
            match p_inst.inst {
                X64Instruction::JmpRel(offset) => {
                    let dest = (next_pc as isize + offset as isize) as usize;
                    jump_targets.insert(dest);
                }
                X64Instruction::JeRel(offset) => {
                    let dest = (next_pc as isize + offset as isize) as usize;
                    jump_targets.insert(dest);
                }
                X64Instruction::JneRel(offset) => {
                    let dest = (next_pc as isize + offset as isize) as usize;
                    jump_targets.insert(dest);
                }
                _ => {}
            }
        }

        // Pass 2: Translate instructions and attach labels at target offsets
        let mut instructions = Vec::new();

        for p_inst in parsed {
            let next_pc = p_inst.offset + p_inst.size;

            // Generate label name if this instruction is a branch target
            let label = if jump_targets.contains(&p_inst.offset) {
                Some(format!("_offset_0x{:02X}", p_inst.offset))
            } else {
                None
            };

            let native_inst = match &p_inst.inst {
                X64Instruction::MovImm(reg, val) => {
                    NativeInstruction::Mov(*reg, Operand::Imm(*val))
                }
                X64Instruction::AddReg(reg1, reg2) => {
                    NativeInstruction::Add(*reg1, Operand::Reg(*reg2))
                }
                X64Instruction::SubImm(reg, val) => {
                    NativeInstruction::Sub(*reg, Operand::Imm(*val))
                }
                X64Instruction::CmpImm(reg, val) => {
                    NativeInstruction::Cmp(*reg, Operand::Imm(*val))
                }
                X64Instruction::JmpRel(offset) => {
                    let dest = (next_pc as isize + *offset as isize) as usize;
                    NativeInstruction::Jmp(format!("_offset_0x{:02X}", dest))
                }
                X64Instruction::JeRel(offset) => {
                    let dest = (next_pc as isize + *offset as isize) as usize;
                    NativeInstruction::Je(format!("_offset_0x{:02X}", dest))
                }
                X64Instruction::JneRel(offset) => {
                    let dest = (next_pc as isize + *offset as isize) as usize;
                    NativeInstruction::Jne(format!("_offset_0x{:02X}", dest))
                }
                X64Instruction::Ret => NativeInstruction::Ret,
            };

            instructions.push((label, native_inst));
        }

        NativeFunction {
            name: name.to_string(),
            instructions,
        }
    }
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
    Ne,
}

impl Condition {
    pub fn as_str(&self) -> &'static str {
        match self {
            Condition::Eq => "eq",
            Condition::Ne => "ne",
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

impl IrInstruction {
    pub fn to_string(&self) -> String {
        match self {
            IrInstruction::LoadReg(t, r) => format!("%{} = load {}", t, r.as_str()),
            IrInstruction::StoreReg(r, v) => format!("store {}, {}*", v.to_string(), r.as_str()),
            IrInstruction::Add(t, v1, v2) => format!("%{} = add {}, {}", t, v1.to_string(), v2.to_string()),
            IrInstruction::Sub(t, v1, v2) => format!("%{} = sub {}, {}", t, v1.to_string(), v2.to_string()),
            IrInstruction::Cmp(v1, v2) => format!("cmp {}, {}", v1.to_string(), v2.to_string()),
            IrInstruction::Br(l) => format!("br label %{}", l),
            IrInstruction::CondBr(c, t, f) => format!("br i1 %flags.{}, label %{}, label %{}", c.as_str(), t, f),
            IrInstruction::Ret => "ret void".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IrBasicBlock {
    pub label: String,
    pub instructions: Vec<IrInstruction>,
    pub successors: Vec<String>,
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
                    | NativeInstruction::Jne(_)
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
                    NativeInstruction::Jne(target) => {
                        let fallthrough = next_physical_block_label
                            .as_ref()
                            .expect("Branch fallthrough label missing")
                            .clone();
                        ir_instructions.push(IrInstruction::CondBr(
                            Condition::Ne,
                            target.clone(),
                            fallthrough,
                        ));
                    }
                    NativeInstruction::Ret => {
                        ir_instructions.push(IrInstruction::Ret);
                    }
                    other => panic!("Lifter Exception: Instruction {:?} is unsupported in raw x64 subset", other),
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

            let mut successors = Vec::new();
            if let Some(last_inst) = ir_instructions.last() {
                match last_inst {
                    IrInstruction::Br(dest) => successors.push(dest.clone()),
                    IrInstruction::CondBr(_, true_lbl, false_lbl) => {
                        successors.push(true_lbl.clone());
                        successors.push(false_lbl.clone());
                    }
                    IrInstruction::Ret => {}
                    _ => {}
                }
            }

            blocks.insert(
                label.clone(),
                IrBasicBlock {
                    label: label.clone(),
                    instructions: ir_instructions,
                    successors,
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

    pub fn render_cfg(cfg: &ControlFlowGraph) {
        println!("\n[PHASE B] CONTROL FLOW GRAPH (CFG) RECONSTRUCTION FROM RAW X64");
        println!("======================================================================");
        println!("FUNCTION: {} (Entry Point: %{})", cfg.name, cfg.entry_label);
        println!("======================================================================");

        for label in &cfg.block_order {
            let block = &cfg.blocks[label];
            println!("Block %{} -> Successors: {:?}", block.label, block.successors);
            println!("----------------------------------------------------------------------");
            for inst in &block.instructions {
                println!("  {}", inst.to_string());
            }
            println!();
        }
        println!("======================================================================\n");
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
    Ret,
}

impl VirtualOpcode {
    pub fn name(&self) -> &'static str {
        match self {
            VirtualOpcode::PushReg => "V_PUSH_REG",
            VirtualOpcode::PopReg => "V_POP_REG",
            VirtualOpcode::PushConst => "V_PUSH_CONST",
            VirtualOpcode::Add => "V_ADD",
            VirtualOpcode::Sub => "V_SUB",
            VirtualOpcode::Cmp => "V_CMP",
            VirtualOpcode::Jmp => "V_JMP",
            VirtualOpcode::Jz => "V_JZ",
            VirtualOpcode::Jnz => "V_JNZ",
            VirtualOpcode::Ret => "V_RET",
        }
    }
}

#[derive(Debug, Clone)]
pub struct IsaMapper {
    opcode_to_byte: HashMap<VirtualOpcode, u8>,
    byte_to_opcode: HashMap<u8, VirtualOpcode>,
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
            VirtualOpcode::Ret,
        ];

        let mut rng = SimpleRng::new(seed);
        let mut byte_pool: Vec<u8> = (0..=255).collect();
        rng.shuffle(&mut byte_pool);

        let mut opcode_to_byte = HashMap::new();
        let mut byte_to_opcode = HashMap::new();

        for (i, op) in opcodes.into_iter().enumerate() {
            let assigned_byte = byte_pool[i];
            opcode_to_byte.insert(op, assigned_byte);
            byte_to_opcode.insert(assigned_byte, op);
        }

        Self {
            opcode_to_byte,
            byte_to_opcode,
        }
    }

    pub fn encode(&self, op: VirtualOpcode) -> u8 {
        *self.opcode_to_byte.get(&op).expect("Opcode unmapped")
    }

    pub fn decode(&self, byte: u8) -> Option<VirtualOpcode> {
        self.byte_to_opcode.get(&byte).copied()
    }

    pub fn print_isa(&self) {
        println!("\n[PHASE C] RANDOMIZED VIRTUAL INSTRUCTION SET ARCHITECTURE (vISA)");
        println!("----------------------------------------------------------------------");
        let mut sorted_opcodes: Vec<&VirtualOpcode> = self.opcode_to_byte.keys().collect();
        sorted_opcodes.sort_by_key(|op| op.name());
        for op in sorted_opcodes {
            let byte = self.opcode_to_byte[op];
            println!("  {:.<20} -> Opcode Byte: 0x{:02X}", op.name(), byte);
        }
        println!("----------------------------------------------------------------------\n");
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
                            Condition::Ne => VirtualOpcode::Jnz,
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
            let target_offset = *block_offsets
                .get(&patch.target_block)
                .unwrap_or_else(|| panic!("Linker Exception: Label '{}' unresolved", patch.target_block));
            
            let dest_u16 = target_offset as u16;
            let bytes = dest_u16.to_le_bytes();
            bytecode[patch.instruction_offset] = bytes[0];
            bytecode[patch.instruction_offset + 1] = bytes[1];
        }

        bytecode
    }

    pub fn print_bytecode(bytecode: &[u8]) {
        println!("\n[PHASE C] COMPILED SERIALIZED BYTECODESTREAM FROM X64 (Size: {} bytes)", bytecode.len());
        println!("----------------------------------------------------------------------");
        for chunk in bytecode.chunks(16) {
            let hex_string: Vec<String> = chunk.iter().map(|b| format!("{:02X}", b)).collect();
            println!("  {}", hex_string.join(" "));
        }
        println!("----------------------------------------------------------------------\n");
    }
}

// ============================================================================
// Phase D: The VM Runtime & Interpreter (Execution Engine)
// ============================================================================
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RegState {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub zf: bool,
    pub sf: bool,
}

pub struct VmRuntime;

impl VmRuntime {
    pub fn execute(bytecode: &[u8], reg_state: &mut RegState, isa: &IsaMapper, verbose: bool) {
        let mut vip = 0;
        let mut stack: Vec<u64> = Vec::new();

        if verbose {
            println!("\n[PHASE D] VM EXECUTION ENGINE - INTERPRETER RUNTIME");
            println!("======================================================================");
            println!("Initial Register Context: rax={:<4} rbx={:<4} rcx={:<4} rdx={:<4} ZF={}", 
                reg_state.rax, reg_state.rbx, reg_state.rcx, reg_state.rdx, 
                if reg_state.zf { 1 } else { 0 });
            println!("----------------------------------------------------------------------");
        }

        while vip < bytecode.len() {
            let current_ip = vip;
            let opcode_byte = bytecode[vip];
            vip += 1;

            let opcode = match isa.decode(opcode_byte) {
                Some(op) => op,
                None => {
                    panic!(
                        "CRITICAL CRASH: VM executed invalid/obfuscated instruction 0x{:02X} at IP: 0x{:04X}",
                        opcode_byte, current_ip
                    );
                }
            };

            match opcode {
                VirtualOpcode::PushReg => {
                    let reg_idx = bytecode[vip];
                    vip += 1;
                    let val = match reg_idx {
                        0 => reg_state.rax,
                        1 => reg_state.rbx,
                        2 => reg_state.rcx,
                        3 => reg_state.rdx,
                        _ => panic!("VM Exception: Invalid register reference in opcode stream"),
                    };
                    stack.push(val);
                    if verbose {
                        println!("0x{:04X} | V_PUSH_REG R{} ({})", current_ip, reg_idx, val);
                    }
                }
                VirtualOpcode::PopReg => {
                    let reg_idx = bytecode[vip];
                    vip += 1;
                    let val = stack.pop().expect("VM Exception: Stack Underflow during PopReg");
                    match reg_idx {
                        0 => reg_state.rax = val,
                        1 => reg_state.rbx = val,
                        2 => reg_state.rcx = val,
                        3 => reg_state.rdx = val,
                        _ => panic!("VM Exception: Invalid register reference in opcode stream"),
                    };
                    if verbose {
                        println!("0x{:04X} | V_POP_REG R{} <- {}", current_ip, reg_idx, val);
                    }
                }
                VirtualOpcode::PushConst => {
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&bytecode[vip..vip + 8]);
                    vip += 8;
                    let val = u64::from_le_bytes(bytes);
                    stack.push(val);
                    if verbose {
                        println!("0x{:04X} | V_PUSH_CONST {}", current_ip, val);
                    }
                }
                VirtualOpcode::Add => {
                    let val2 = stack.pop().expect("VM Exception: Stack Underflow during Add");
                    let val1 = stack.pop().expect("VM Exception: Stack Underflow during Add");
                    let res = val1.wrapping_add(val2);
                    stack.push(res);
                    if verbose {
                        println!("0x{:04X} | V_ADD ({} + {} = {})", current_ip, val1, val2, res);
                    }
                }
                VirtualOpcode::Sub => {
                    let val2 = stack.pop().expect("VM Exception: Stack Underflow during Sub");
                    let val1 = stack.pop().expect("VM Exception: Stack Underflow during Sub");
                    let res = val1.wrapping_sub(val2);
                    stack.push(res);
                    if verbose {
                        println!("0x{:04X} | V_SUB ({} - {} = {})", current_ip, val1, val2, res);
                    }
                }
                VirtualOpcode::Cmp => {
                    let val2 = stack.pop().expect("VM Exception: Stack Underflow during Cmp");
                    let val1 = stack.pop().expect("VM Exception: Stack Underflow during Cmp");
                    reg_state.zf = val1 == val2;
                    reg_state.sf = val1 < val2;
                    if verbose {
                        println!(
                            "0x{:04X} | V_CMP ({} vs {}) -> ZF={}, SF={}",
                            current_ip, val1, val2, if reg_state.zf { 1 } else { 0 }, if reg_state.sf { 1 } else { 0 }
                        );
                    }
                }
                VirtualOpcode::Jmp => {
                    let mut bytes = [0u8; 2];
                    bytes.copy_from_slice(&bytecode[vip..vip + 2]);
                    let dest = u16::from_le_bytes(bytes) as usize;
                    vip = dest;
                    if verbose {
                        println!("0x{:04X} | V_JMP to 0x{:04X}", current_ip, dest);
                    }
                }
                VirtualOpcode::Jz => {
                    let mut bytes = [0u8; 2];
                    bytes.copy_from_slice(&bytecode[vip..vip + 2]);
                    let dest = u16::from_le_bytes(bytes) as usize;
                    if reg_state.zf {
                        vip = dest;
                        if verbose {
                            println!("0x{:04X} | V_JZ to 0x{:04X} (TAKEN)", current_ip, dest);
                        }
                    } else {
                        vip += 2;
                        if verbose {
                            println!("0x{:04X} | V_JZ to 0x{:04X} (NOT TAKEN)", current_ip, dest);
                        }
                    }
                }
                VirtualOpcode::Jnz => {
                    let mut bytes = [0u8; 2];
                    bytes.copy_from_slice(&bytecode[vip..vip + 2]);
                    let dest = u16::from_le_bytes(bytes) as usize;
                    if !reg_state.zf {
                        vip = dest;
                        if verbose {
                            println!("0x{:04X} | V_JNZ to 0x{:04X} (TAKEN)", current_ip, dest);
                        }
                    } else {
                        vip += 2;
                        if verbose {
                            println!("0x{:04X} | V_JNZ to 0x{:04X} (NOT TAKEN)", current_ip, dest);
                        }
                    }
                }
                VirtualOpcode::Ret => {
                    if verbose {
                        println!("0x{:04X} | V_RET (Halting Execution)", current_ip);
                        println!("----------------------------------------------------------------------");
                        println!("Final Register Context: rax={:<4} rbx={:<4} rcx={:<4} rdx={:<4} ZF={}", 
                            reg_state.rax, reg_state.rbx, reg_state.rcx, reg_state.rdx, 
                            if reg_state.zf { 1 } else { 0 });
                        println!("======================================================================\n");
                    }
                    return;
                }
            }
        }
    }
}

// ============================================================================
// Core Execution Entrypoint & Differential Verification
// ============================================================================
fn main() {
    println!("+----------------------------------------------------------------------+");
    println!("|          X64 BINARY LIFTER & VIRTUALIZATION PROTECTOR PoC            |");
    println!("+----------------------------------------------------------------------+");
    println!("System Target architecture: x86_64 / X64 Windows PE compatibility");
    println!("Decoder status: Loaded");

    let seed: u64 = 0xCAFEEB0B;
    let isa = IsaMapper::generate_random(seed);
    isa.print_isa();

    // ------------------------------------------------------------------------
    // Case 1: Simple x64 Arithmetic Instruction Block
    // ------------------------------------------------------------------------
    println!("\n>>> TEST CASE 1: LIFTING RAW X64 ARITHMETIC MACHINE BYTES");
    println!("----------------------------------------------------------------------");
    // Target compiled machine bytes for:
    //   mov rax, 10           (48 c7 c0 0a 00 00 00)
    //   mov rbx, 5            (48 c7 c3 05 00 00 00)
    //   add rax, rbx          (48 01 d8)
    //   ret                   (c3)
    let x64_bytes_arithmetic = vec![
        0x48, 0xC7, 0xC0, 0x0A, 0x00, 0x00, 0x00, // mov rax, 10
        0x48, 0xC7, 0xC3, 0x05, 0x00, 0x00, 0x00, // mov rbx, 5
        0x48, 0x01, 0xD8,                         // add rax, rbx
        0xC3,                                     // ret
    ];

    println!("[1/5] Decoding raw machine code bytes...");
    let parsed_arith = X64Decoder::decode_bytes(&x64_bytes_arithmetic);
    for p in &parsed_arith {
        println!("  Offset 0x{:02X} | Size: {} bytes | Instruction: {:?}", p.offset, p.size, p.inst);
    }

    println!("[2/5] Performing Symbolic Translation & Reference Assembly Construction...");
    let native_arith = X64Decoder::lift_to_native("x64_arithmetic", &parsed_arith);

    println!("[3/5] Performing Binary Lifting (SSA LLVM IR) & CFG Reconstruction...");
    let arith_cfg = Lifter::lift(&native_arith);
    Lifter::render_cfg(&arith_cfg);

    println!("[4/5] Running Obfuscation Compiler Pass (Randomized vISA Compilation)...");
    let arith_bytecode = VirtualizationPass::compile(&arith_cfg, &isa);
    VirtualizationPass::print_bytecode(&arith_bytecode);

    println!("[5/5] Running VM Interpreter & Verifying Execution fidelity...");
    let mut reg_context = RegState::default();
    VmRuntime::execute(&arith_bytecode, &mut reg_context, &isa, true);

    // Assert that: rax = 10 + 5 = 15, rbx = 5
    assert_eq!(reg_context.rax, 15);
    assert_eq!(reg_context.rbx, 5);
    println!(">>> TEST CASE 1 PASSED: Registers RAX and RBX matched native execution exactly!");

    // ------------------------------------------------------------------------
    // Case 2: Stateful x64 Iterative Loop Block
    // ------------------------------------------------------------------------
    println!("\n\n>>> TEST CASE 2: LIFTING RAW X64 ITERATIVE LOOP MACHINE BYTES");
    println!("----------------------------------------------------------------------");
    // Target compiled machine bytes for:
    // _start:
    //   mov rax, 5            (48 c7 c0 05 00 00 00)
    //   mov rbx, 0            (48 c7 c3 00 00 00 00)
    // _loop:
    //   add rbx, rax          (48 01 c3)
    //   sub rax, 1            (48 83 e8 01)
    //   cmp rax, 0            (48 83 f8 00)
    //   jne _loop             (75 f3  -> relative -13 offset)
    //   ret                   (c3)
    // Total sum calculated (5 + 4 + 3 + 2 + 1) = 15 stored in RBX.
    let x64_bytes_loop = vec![
        0x48, 0xC7, 0xC0, 0x05, 0x00, 0x00, 0x00, // mov rax, 5
        0x48, 0xC7, 0xC3, 0x00, 0x00, 0x00, 0x00, // mov rbx, 0
        0x48, 0x01, 0xC3,                         // add rbx, rax
        0x48, 0x83, 0xE8, 0x01,                   // sub rax, 1
        0x48, 0x83, 0xF8, 0x00,                   // cmp rax, 0
        0x75, 0xF3,                               // jne _loop (offset 14 - pc 27 = -13 bytes)
        0xC3,                                     // ret
    ];

    println!("[1/5] Decoding raw stateful loop machine code bytes...");
    let parsed_loop = X64Decoder::decode_bytes(&x64_bytes_loop);
    for p in &parsed_loop {
        println!("  Offset 0x{:02X} | Size: {} bytes | Instruction: {:?}", p.offset, p.size, p.inst);
    }

    println!("[2/5] Performing Branch Target Resolution & Symbolic Native Function Construction...");
    let native_loop = X64Decoder::lift_to_native("x64_loop_sum", &parsed_loop);
    println!("Symbolic Instructions Generated:");
    for (lbl, inst) in &native_loop.instructions {
        if let Some(l) = lbl {
            println!("  %{}:", l);
        }
        println!("    {:?}", inst);
    }

    println!("[3/5] Performing Binary Lifting (SSA LLVM IR) & CFG Reconstruction...");
    let loop_cfg = Lifter::lift(&native_loop);
    Lifter::render_cfg(&loop_cfg);

    println!("[4/5] Running Obfuscation Compiler Pass (Randomized vISA Compilation)...");
    let loop_bytecode = VirtualizationPass::compile(&loop_cfg, &isa);
    VirtualizationPass::print_bytecode(&loop_bytecode);

    println!("[5/5] Running VM Interpreter & Verifying Execution fidelity...");
    let mut reg_context_loop = RegState::default();
    VmRuntime::execute(&loop_bytecode, &mut reg_context_loop, &isa, true);

    // Assert that: rax = 0 (counted down), rbx = 15 (sum of 5+4+3+2+1)
    assert_eq!(reg_context_loop.rbx, 15);
    assert_eq!(reg_context_loop.rax, 0);
    println!(">>> TEST CASE 2 PASSED: Loop result RBX=15 matched native mathematical expectation exactly!");

    println!("\n======================================================================");
    println!("SUCCESS: Both raw X64 machine code lifter POC cases successfully verified.");
    println!("X64 Binary Lifting & Translation pipeline completed successfully.");
    println!("======================================================================\n");
}
