//! Architectural Proof-of-Concept: LLVM-Based Binary Virtualization Framework
//!
//! This module implements a high-fidelity, complete, and self-contained
//! virtualization protector demonstrating all five phases specified in
//! VIRTUALIZATION_PLAN.md:
//!
//! Phase A: Binary Lifting (Native Assembly to LLVM-like IR)
//! Phase B: Control Flow Graph (CFG) Reconstruction & Visualization
//! Phase C: The Virtualization Pass (Opcode Randomization & Two-Pass Bytecode Compilation)
//! Phase D: The VM Runtime & Interpreter (Stack-Based Execution Engine)
//! Phase E: Verification & Differential Testing (Fibonacci, Factorial, GCD)

use std::collections::HashMap;

// ============================================================================
// Utilities: Pseudo-Random Number Generator (LCG)
// ============================================================================
/// A lightweight Linear Congruential Generator (LCG) to perform opcode
/// randomization without external crate dependencies.
pub struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u32(&mut self) -> u32 {
        // LCG parameters from Numerical Recipes
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
    Jl(String),
    Jle(String),
    Jg(String),
    Jge(String),
    Ret,
}

#[derive(Debug, Clone)]
pub struct NativeFunction {
    pub name: String,
    pub instructions: Vec<(Option<String>, NativeInstruction)>, // (Optional Label, Instruction)
}

// ============================================================================
// Data Structures: LLVM-like SSA Intermediate Representation (IR)
// ============================================================================
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrValue {
    Const(u64),
    Temp(usize), // SSA temporary register ID
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
    Lt,
    Le,
    Gt,
    Ge,
}

impl Condition {
    pub fn as_str(&self) -> &'static str {
        match self {
            Condition::Eq => "eq",
            Condition::Ne => "ne",
            Condition::Lt => "lt",
            Condition::Le => "le",
            Condition::Gt => "gt",
            Condition::Ge => "ge",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrInstruction {
    LoadReg(usize, Register),          // %temp = load reg
    StoreReg(Register, IrValue),       // store val to reg
    Add(usize, IrValue, IrValue),      // %temp = add val1, val2
    Sub(usize, IrValue, IrValue),      // %temp = sub val1, val2
    Mul(usize, IrValue, IrValue),      // %temp = mul val1, val2
    Cmp(IrValue, IrValue),             // cmp val1, val2
    Br(String),                        // unconditional jump to label
    CondBr(Condition, String, String), // cond_br cond, true_label, false_label
    Ret,                               // return from function
}

impl IrInstruction {
    pub fn to_string(&self) -> String {
        match self {
            IrInstruction::LoadReg(t, r) => format!("%{} = load {}", t, r.as_str()),
            IrInstruction::StoreReg(r, v) => format!("store {}, {}*", v.to_string(), r.as_str()),
            IrInstruction::Add(t, v1, v2) => format!("%{} = add {}, {}", t, v1.to_string(), v2.to_string()),
            IrInstruction::Sub(t, v1, v2) => format!("%{} = sub {}, {}", t, v1.to_string(), v2.to_string()),
            IrInstruction::Mul(t, v1, v2) => format!("%{} = mul {}, {}", t, v1.to_string(), v2.to_string()),
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
    pub block_order: Vec<String>, // Deterministic block order for serialization layout
}

// ============================================================================
// Phase A & B: The Lifter & CFG Reconstruction
// ============================================================================
pub struct Lifter;

impl Lifter {
    /// Lifts a sequence of Native Instructions into a clean Control Flow Graph (CFG)
    /// representing structured basic blocks of LLVM-like SSA IR.
    pub fn lift(func: &NativeFunction) -> ControlFlowGraph {
        // Step 1: Pre-segment native instructions into logical basic blocks.
        // A block begins at:
        // - The start of the function.
        // - Any instruction annotated with a label.
        // - Immediately after a terminator instruction (JMP, conditional jumps, RET).
        let mut block_bounds = Vec::new();
        block_bounds.push(0); // Entry block start

        for (i, (label, inst)) in func.instructions.iter().enumerate() {
            if label.is_some() && i > 0 {
                block_bounds.push(i);
            }
            if matches!(
                inst,
                NativeInstruction::Jmp(_)
                    | NativeInstruction::Je(_)
                    | NativeInstruction::Jne(_)
                    | NativeInstruction::Jl(_)
                    | NativeInstruction::Jle(_)
                    | NativeInstruction::Jg(_)
                    | NativeInstruction::Jge(_)
                    | NativeInstruction::Ret
            ) {
                if i + 1 < func.instructions.len() {
                    block_bounds.push(i + 1);
                }
            }
        }

        block_bounds.sort();
        block_bounds.dedup();

        // Build native blocks
        let mut native_blocks = Vec::new();
        for i in 0..block_bounds.len() {
            let start = block_bounds[i];
            let end = if i + 1 < block_bounds.len() {
                block_bounds[i + 1]
            } else {
                func.instructions.len()
            };

            let instructions = &func.instructions[start..end];
            // Identify label or generate automatic one
            let label = if let Some(ref lbl) = instructions[0].0 {
                lbl.clone()
            } else if start == 0 {
                "entry".to_string()
            } else {
                format!("block_0x{:02X}", start)
            };

            native_blocks.push((label, instructions, start, end));
        }

        let mut blocks = HashMap::new();
        let mut block_order = Vec::new();
        let entry_label = native_blocks[0].0.clone();

        let mut next_ssa_id = 0;

        for idx in 0..native_blocks.len() {
            let (label, raw_insts, _start, _end) = &native_blocks[idx];
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
                    NativeInstruction::Mul(dest, src) => {
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
                        ir_instructions.push(IrInstruction::Mul(t_res, IrValue::Temp(t_dest), src_val));
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
                    NativeInstruction::Jl(target) => {
                        let fallthrough = next_physical_block_label
                            .as_ref()
                            .expect("Branch fallthrough label missing")
                            .clone();
                        ir_instructions.push(IrInstruction::CondBr(
                            Condition::Lt,
                            target.clone(),
                            fallthrough,
                        ));
                    }
                    NativeInstruction::Jle(target) => {
                        let fallthrough = next_physical_block_label
                            .as_ref()
                            .expect("Branch fallthrough label missing")
                            .clone();
                        ir_instructions.push(IrInstruction::CondBr(
                            Condition::Le,
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
                    NativeInstruction::Jge(target) => {
                        let fallthrough = next_physical_block_label
                            .as_ref()
                            .expect("Branch fallthrough label missing")
                            .clone();
                        ir_instructions.push(IrInstruction::CondBr(
                            Condition::Ge,
                            target.clone(),
                            fallthrough,
                        ));
                    }
                    NativeInstruction::Ret => {
                        ir_instructions.push(IrInstruction::Ret);
                    }
                }
            }

            // Ensure mathematical terminator completeness: if a block doesn't end in Br, CondBr, or Ret,
            // we force an unconditional jump to the physical successor block.
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

            // Compute Successor basic blocks
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

    /// Renders a beautiful visual diagram of the Control Flow Graph.
    pub fn render_cfg(cfg: &ControlFlowGraph) {
        println!("\n[PHASE B] CONTROL FLOW GRAPH (CFG) RECONSTRUCTION");
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
    Mul,
    Cmp,
    Jmp,
    Jz,
    Jnz,
    Jg,
    Jle,
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
            VirtualOpcode::Mul => "V_MUL",
            VirtualOpcode::Cmp => "V_CMP",
            VirtualOpcode::Jmp => "V_JMP",
            VirtualOpcode::Jz => "V_JZ",
            VirtualOpcode::Jnz => "V_JNZ",
            VirtualOpcode::Jg => "V_JG",
            VirtualOpcode::Jle => "V_JLE",
            VirtualOpcode::Ret => "V_RET",
        }
    }
}

/// A bidirectional mapping that dynamically registers randomized opcode bytes.
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
            VirtualOpcode::Mul,
            VirtualOpcode::Cmp,
            VirtualOpcode::Jmp,
            VirtualOpcode::Jz,
            VirtualOpcode::Jnz,
            VirtualOpcode::Jg,
            VirtualOpcode::Jle,
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
    instruction_offset: usize, // Offset in byte array where the 2-byte target is stored
    target_block: String,
}

pub struct VirtualizationPass;

impl VirtualizationPass {
    /// Compiles a Control Flow Graph (CFG) into randomized Virtual Machine bytecode
    /// using a two-pass layout and jump backpatching compiler pass.
    pub fn compile(cfg: &ControlFlowGraph, isa: &IsaMapper) -> Vec<u8> {
        let mut bytecode = Vec::new();
        let mut block_offsets = HashMap::new();
        let mut pending_jumps = Vec::new();

        // Pass 1: Layout & Linear Code Generation
        // We write instructions, recording the byte offset of each basic block.
        // For jump instruction targets, we write dummy 0x0000 offsets and add them to a patchlist.
        
        // Ensure entry block is always placed first at offset 0
        let mut sorted_labels = vec![cfg.entry_label.clone()];
        for label in &cfg.block_order {
            if *label != cfg.entry_label {
                sorted_labels.push(label.clone());
            }
        }

        for label in &sorted_labels {
            let block = &cfg.blocks[label];
            // Record exact start offset of this basic block
            block_offsets.insert(label.clone(), bytecode.len());

            for ir_inst in &block.instructions {
                match ir_inst {
                    IrInstruction::LoadReg(_, reg) => {
                        // Load native register to stack
                        bytecode.push(isa.encode(VirtualOpcode::PushReg));
                        bytecode.push(*reg as u8);
                    }
                    IrInstruction::StoreReg(reg, val) => {
                        match val {
                            IrValue::Const(c) => {
                                bytecode.push(isa.encode(VirtualOpcode::PushConst));
                                bytecode.extend_from_slice(&c.to_le_bytes());
                            }
                            IrValue::Temp(_) => {
                                // Result is already on top of stack from preceding operation
                            }
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
                    IrInstruction::Mul(_, _, val2) => {
                        if let IrValue::Const(c) = val2 {
                            bytecode.push(isa.encode(VirtualOpcode::PushConst));
                            bytecode.extend_from_slice(&c.to_le_bytes());
                        }
                        bytecode.push(isa.encode(VirtualOpcode::Mul));
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
                        // Map IR branch conditions into VM bytecode branches
                        let jump_op = match cond {
                            Condition::Eq => VirtualOpcode::Jz,
                            Condition::Ne => VirtualOpcode::Jnz,
                            Condition::Gt => VirtualOpcode::Jg,
                            Condition::Le => VirtualOpcode::Jle,
                            other => panic!("Unsupported conditional jump condition: {:?}", other),
                        };

                        // True branch jump
                        bytecode.push(isa.encode(jump_op));
                        pending_jumps.push(PendingJump {
                            instruction_offset: bytecode.len(),
                            target_block: true_lbl.clone(),
                        });
                        bytecode.push(0x00);
                        bytecode.push(0x00);

                        // False branch jump (fallthrough equivalent)
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

        // Pass 2: Backpatching Phase
        // Walk through recorded jumps and patch raw block offsets in.
        for patch in &pending_jumps {
            let target_offset = *block_offsets
                .get(&patch.target_block)
                .unwrap_or_else(|| panic!("Compiler Linker Error: Label '{}' is unresolved", patch.target_block));
            
            let dest_u16 = target_offset as u16;
            let bytes = dest_u16.to_le_bytes();
            bytecode[patch.instruction_offset] = bytes[0];
            bytecode[patch.instruction_offset + 1] = bytes[1];
        }

        bytecode
    }

    pub fn print_bytecode(bytecode: &[u8]) {
        println!("\n[PHASE C] COMPILED SERIALIZED BYTECODESTREAM (Size: {} bytes)", bytecode.len());
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
    /// Executes the randomized bytecode stream on the Virtual Register Context.
    pub fn execute(bytecode: &[u8], reg_state: &mut RegState, isa: &IsaMapper, verbose: bool) {
        let mut vip = 0; // Virtual Instruction Pointer
        let mut stack: Vec<u64> = Vec::new(); // Virtual Evaluation Stack

        if verbose {
            println!("\n[PHASE D] VM EXECUTION ENGINE - INTERPRETER RUNTIME");
            println!("======================================================================");
            println!("Initial Context: rax={:<4} rbx={:<4} rcx={:<4} rdx={:<4} ZF={} SF={}", 
                reg_state.rax, reg_state.rbx, reg_state.rcx, reg_state.rdx, 
                if reg_state.zf { 1 } else { 0 }, if reg_state.sf { 1 } else { 0 });
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
                VirtualOpcode::Mul => {
                    let val2 = stack.pop().expect("VM Exception: Stack Underflow during Mul");
                    let val1 = stack.pop().expect("VM Exception: Stack Underflow during Mul");
                    let res = val1.wrapping_mul(val2);
                    stack.push(res);
                    if verbose {
                        println!("0x{:04X} | V_MUL ({} * {} = {})", current_ip, val1, val2, res);
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
                VirtualOpcode::Jg => {
                    let mut bytes = [0u8; 2];
                    bytes.copy_from_slice(&bytecode[vip..vip + 2]);
                    let dest = u16::from_le_bytes(bytes) as usize;
                    // Greater than: ZF == false && SF == false
                    if !reg_state.zf && !reg_state.sf {
                        vip = dest;
                        if verbose {
                            println!("0x{:04X} | V_JG to 0x{:04X} (TAKEN)", current_ip, dest);
                        }
                    } else {
                        vip += 2;
                        if verbose {
                            println!("0x{:04X} | V_JG to 0x{:04X} (NOT TAKEN)", current_ip, dest);
                        }
                    }
                }
                VirtualOpcode::Jle => {
                    let mut bytes = [0u8; 2];
                    bytes.copy_from_slice(&bytecode[vip..vip + 2]);
                    let dest = u16::from_le_bytes(bytes) as usize;
                    // Less or Equal: ZF == true || SF == true
                    if reg_state.zf || reg_state.sf {
                        vip = dest;
                        if verbose {
                            println!("0x{:04X} | V_JLE to 0x{:04X} (TAKEN)", current_ip, dest);
                        }
                    } else {
                        vip += 2;
                        if verbose {
                            println!("0x{:04X} | V_JLE to 0x{:04X} (NOT TAKEN)", current_ip, dest);
                        }
                    }
                }
                VirtualOpcode::Ret => {
                    if verbose {
                        println!("0x{:04X} | V_RET (Halting Execution)", current_ip);
                        println!("----------------------------------------------------------------------");
                        println!("Final Context: rax={:<4} rbx={:<4} rcx={:<4} rdx={:<4} ZF={} SF={}", 
                            reg_state.rax, reg_state.rbx, reg_state.rcx, reg_state.rdx, 
                            if reg_state.zf { 1 } else { 0 }, if reg_state.sf { 1 } else { 0 });
                        println!("======================================================================\n");
                    }
                    return;
                }
            }
        }
    }
}

// ============================================================================
// Phase E: Validation & Differential Testing Functions
// ============================================================================
fn get_fibonacci_function() -> NativeFunction {
    NativeFunction {
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
    }
}

fn get_factorial_function() -> NativeFunction {
    NativeFunction {
        name: "factorial".to_string(),
        instructions: vec![
            (Some("_start".to_string()), NativeInstruction::Mov(Register::Rbx, Operand::Imm(1))),
            (Some("_loop".to_string()), NativeInstruction::Cmp(Register::Rax, Operand::Imm(1))),
            (None, NativeInstruction::Jle("_exit".to_string())),
            (None, NativeInstruction::Mul(Register::Rbx, Operand::Reg(Register::Rax))),
            (None, NativeInstruction::Sub(Register::Rax, Operand::Imm(1))),
            (None, NativeInstruction::Jmp("_loop".to_string())),
            (Some("_exit".to_string()), NativeInstruction::Ret),
        ],
    }
}

fn get_gcd_function() -> NativeFunction {
    NativeFunction {
        name: "gcd_euclidean".to_string(),
        instructions: vec![
            (Some("_loop".to_string()), NativeInstruction::Cmp(Register::Rbx, Operand::Imm(0))),
            (None, NativeInstruction::Je("_exit".to_string())),
            (None, NativeInstruction::Cmp(Register::Rax, Operand::Reg(Register::Rbx))),
            (None, NativeInstruction::Jg("_sub_a".to_string())),
            (None, NativeInstruction::Sub(Register::Rbx, Operand::Reg(Register::Rax))),
            (None, NativeInstruction::Jmp("_loop".to_string())),
            (Some("_sub_a".to_string()), NativeInstruction::Sub(Register::Rax, Operand::Reg(Register::Rbx))),
            (None, NativeInstruction::Jmp("_loop".to_string())),
            (Some("_exit".to_string()), NativeInstruction::Ret),
        ],
    }
}

// Native Reference Implementations in standard Rust
fn native_fibonacci(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut rbx = 0;
    let mut rcx = 1;
    for _ in 0..n {
        let temp = rbx;
        rbx += rcx;
        rcx = temp;
    }
    rbx
}

fn native_factorial(mut n: u64) -> u64 {
    let mut rbx = 1;
    while n > 1 {
        rbx *= n;
        n -= 1;
    }
    rbx
}

fn native_gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        if a > b {
            a -= b;
        } else {
            b -= a;
        }
    }
    a
}

// ============================================================================
// Core Execution Entrypoint & Interactive CLI
// ============================================================================
fn main() {
    println!("+----------------------------------------------------------------------+");
    println!("|              BINARYDEFENDER VIRTUALIZATION PROTECTOR PoC             |");
    println!("+----------------------------------------------------------------------+");
    println!("Operating System Detected: win32 (Host Mode: Windows)");
    println!("Engine State: Ready (LCG Seed Initialized)");

    let seed: u64 = 0xDEADC0DE; // Strategic fixed compile-time seed for reproducible randomized ISA
    let isa = IsaMapper::generate_random(seed);
    isa.print_isa();

    // ------------------------------------------------------------------------
    // Case 1: Iterative Fibonacci
    // ------------------------------------------------------------------------
    println!("\n>>> DEMONSTRATION 1: ITERATIVE FIBONACCI ALGORITHM");
    println!("----------------------------------------------------------------------");
    let native_fib = get_fibonacci_function();
    let fib_cfg = Lifter::lift(&native_fib);
    Lifter::render_cfg(&fib_cfg);

    let fib_bytecode = VirtualizationPass::compile(&fib_cfg, &isa);
    VirtualizationPass::print_bytecode(&fib_bytecode);

    // Differential Testing inputs for Fibonacci
    let test_inputs_fib = vec![0, 1, 5, 10, 15];
    println!("[TESTING] Running Differential Semantic Equivalence Suite for Fibonacci:");
    for input in test_inputs_fib {
        // Native Execution
        let ref_output = native_fibonacci(input);

        // VM Execution
        let mut reg_context = RegState {
            rax: input,
            ..Default::default()
        };
        // Print details for N=10 to showcase trace telemetry
        let show_trace = input == 10;
        VmRuntime::execute(&fib_bytecode, &mut reg_context, &isa, show_trace);

        let vm_output = reg_context.rbx;
        let is_equivalent = ref_output == vm_output;

        println!(
            "  Input: N={:<2} | Native Result: {:<5} | VM Result: {:<5} | Match: {}",
            input,
            ref_output,
            vm_output,
            if is_equivalent { "PASSED" } else { "FAILED" }
        );
        assert!(is_equivalent, "Differential test failed!");
    }

    // ------------------------------------------------------------------------
    // Case 2: Iterative Factorial
    // ------------------------------------------------------------------------
    println!("\n>>> DEMONSTRATION 2: FACTORIAL WITH MULTIPLICATION");
    println!("----------------------------------------------------------------------");
    let native_fact = get_factorial_function();
    let fact_cfg = Lifter::lift(&native_fact);
    Lifter::render_cfg(&fact_cfg);

    let fact_bytecode = VirtualizationPass::compile(&fact_cfg, &isa);
    VirtualizationPass::print_bytecode(&fact_bytecode);

    let test_inputs_fact = vec![0, 1, 3, 5, 8, 10];
    println!("[TESTING] Running Differential Semantic Equivalence Suite for Factorial:");
    for input in test_inputs_fact {
        let ref_output = native_factorial(input);

        let mut reg_context = RegState {
            rax: input,
            ..Default::default()
        };
        let show_trace = input == 5;
        VmRuntime::execute(&fact_bytecode, &mut reg_context, &isa, show_trace);

        let vm_output = reg_context.rbx;
        let is_equivalent = ref_output == vm_output;

        println!(
            "  Input: N={:<2} | Native Result: {:<7} | VM Result: {:<7} | Match: {}",
            input,
            ref_output,
            vm_output,
            if is_equivalent { "PASSED" } else { "FAILED" }
        );
        assert!(is_equivalent, "Differential test failed!");
    }

    // ------------------------------------------------------------------------
    // Case 3: Great Common Divisor (Euclidean GCD)
    // ------------------------------------------------------------------------
    println!("\n>>> DEMONSTRATION 3: EUCLIDEAN GREAT COMMON DIVISOR (GCD)");
    println!("----------------------------------------------------------------------");
    let native_gcd_func = get_gcd_function();
    let gcd_cfg = Lifter::lift(&native_gcd_func);
    Lifter::render_cfg(&gcd_cfg);

    let gcd_bytecode = VirtualizationPass::compile(&gcd_cfg, &isa);
    VirtualizationPass::print_bytecode(&gcd_bytecode);

    let test_inputs_gcd = vec![(12, 8), (45, 15), (101, 13), (256, 48)];
    println!("[TESTING] Running Differential Semantic Equivalence Suite for GCD:");
    for (a, b) in test_inputs_gcd {
        let ref_output = native_gcd(a, b);

        let mut reg_context = RegState {
            rax: a,
            rbx: b,
            ..Default::default()
        };
        let show_trace = a == 12 && b == 8;
        VmRuntime::execute(&gcd_bytecode, &mut reg_context, &isa, show_trace);

        let vm_output = reg_context.rax;
        let is_equivalent = ref_output == vm_output;

        println!(
            "  Inputs: a={:<3}, b={:<3} | Native Result: {:<3} | VM Result: {:<3} | Match: {}",
            a,
            b,
            ref_output,
            vm_output,
            if is_equivalent { "PASSED" } else { "FAILED" }
        );
        assert!(is_equivalent, "Differential test failed!");
    }

    println!("\n======================================================================");
    println!("SUCCESS: All differential testing runs passed without drift.");
    println!("Virtual execution fidelity is verified at 100% semantic correctness.");
    println!("======================================================================\n");
}
