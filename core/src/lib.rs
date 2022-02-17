//! Core layer for EVM.

#![deny(warnings)]
#![forbid(unsafe_code, unused_variables, unused_imports)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
extern crate core;

mod error;
mod eval;
mod memory;
mod opcode;
mod stack;
mod utils;
mod valids;

pub use crate::error::{Capture, ExitError, ExitFatal, ExitReason, ExitRevert, ExitSucceed, Trap};
pub use crate::memory::Memory;
pub use crate::opcode::Opcode;
pub use crate::stack::Stack;
pub use crate::valids::Valids;

use crate::eval::{eval, Control};
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::ops::Range;
use primitive_types::{H160, U256};

/// Core execution layer for EVM.
pub struct Machine {
	/// Program data.
	data: Rc<Vec<u8>>,
	/// Program code.
	code: Rc<Vec<u8>>,
	/// Program counter.
	position: Result<usize, ExitReason>,
	/// Return value.
	return_range: Range<U256>,
	/// Code validity maps.
	valids: Valids,
	/// Memory.
	memory: Memory,
	/// Stack.
	stack: Stack,
}

/// EVM interpreter handler.
pub trait InterpreterHandler {
	fn before_bytecode(
		&mut self,
		opcode: Opcode,
		pc: usize,
		machine: &Machine,
		address: &H160,
	) -> Result<(), ExitError>;

	// Only invoked if #[cfg(feature = "tracing")]
	fn after_bytecode(&mut self, result: &Result<(), Capture<ExitReason, Trap>>, machine: &Machine);
}

impl Machine {
	/// Reference of machine stack.
	pub fn stack(&self) -> &Stack {
		&self.stack
	}
	/// Mutable reference of machine stack.
	pub fn stack_mut(&mut self) -> &mut Stack {
		&mut self.stack
	}
	/// Reference of machine memory.
	pub fn memory(&self) -> &Memory {
		&self.memory
	}
	/// Mutable reference of machine memory.
	pub fn memory_mut(&mut self) -> &mut Memory {
		&mut self.memory
	}
	/// Return a reference of the program counter.
	pub fn position(&self) -> &Result<usize, ExitReason> {
		&self.position
	}

	/// Create a new machine with given code and data.
	pub fn new(
		code: Rc<Vec<u8>>,
		data: Rc<Vec<u8>>,
		stack_limit: usize,
		memory_limit: usize,
	) -> Self {
		let valids = Valids::new(&code[..]);

		Self {
			data,
			code,
			position: Ok(0),
			return_range: U256::zero()..U256::zero(),
			valids,
			memory: Memory::new(memory_limit),
			stack: Stack::new(stack_limit),
		}
	}

	/// Explicit exit of the machine. Further step will return error.
	pub fn exit(&mut self, reason: ExitReason) {
		self.position = Err(reason);
	}

	/// Inspect the machine's next opcode and current stack.
	pub fn inspect(&self) -> Option<(Opcode, &Stack)> {
		let position = match self.position {
			Ok(position) => position,
			Err(_) => return None,
		};
		self.code.get(position).map(|v| (Opcode(*v), &self.stack))
	}

	/// Copy and get the return value of the machine, if any.
	pub fn return_value(&self) -> Vec<u8> {
		if self.return_range.start > U256::from(usize::MAX) {
			let mut ret = Vec::new();
			ret.resize(
				(self.return_range.end - self.return_range.start).as_usize(),
				0,
			);
			ret
		} else if self.return_range.end > U256::from(usize::MAX) {
			let mut ret = self.memory.get(
				self.return_range.start.as_usize(),
				usize::MAX - self.return_range.start.as_usize(),
			);
			while ret.len() < (self.return_range.end - self.return_range.start).as_usize() {
				ret.push(0);
			}
			ret
		} else {
			self.memory.get(
				self.return_range.start.as_usize(),
				(self.return_range.end - self.return_range.start).as_usize(),
			)
		}
	}

	/// Loop stepping the machine, until it stops.
	pub fn run(&mut self) -> Capture<ExitReason, Trap> {
		let mut handler = SimpleInterpreterHandler::default();
		loop {
			match self.step(&mut handler, &H160::default()) {
				Ok(()) => (),
				Err(res) => return res,
			}
		}
	}

	#[inline]
	/// Step the machine, executing until exit or trap.
	pub fn step<H: InterpreterHandler>(
		&mut self,
		handler: &mut H,
		address: &H160,
	) -> Result<(), Capture<ExitReason, Trap>> {
		let position = *self
			.position
			.as_ref()
			.map_err(|reason| Capture::Exit(reason.clone()))?;
		match eval(self, position, handler, address) {
			Control::Continue(_) | Control::Jump(_) => {
				unreachable!("must not be here, eval computes branches");
			}
			Control::Exit(e) => {
				self.position = Err(e.clone());
				Err(Capture::Exit(e))
			}
			Control::Trap(opcode) => Err(Capture::Trap(opcode)),
		}
	}
}

pub struct SimpleInterpreterHandler {
	pub executed: u64,
	pub profile: [u64; 256],
	pub address: H160,
}

impl SimpleInterpreterHandler {
	pub fn new(address: H160) -> Self {
		Self {
			executed: 0,
			profile: [0; 256],
			address,
		}
	}

	pub fn default() -> Self {
		Self {
			executed: 0,
			profile: [0; 256],
			address: H160::default(),
		}
	}
}

impl InterpreterHandler for SimpleInterpreterHandler {
	fn before_bytecode(
		&mut self,
		opcode: Opcode,
		_pc: usize,
		_machine: &Machine,
		_address: &H160,
	) -> Result<(), ExitError> {
		self.executed += 1;
		self.profile[opcode.as_usize()] += 1;
		Ok(())
	}

	fn after_bytecode(
		&mut self,
		_result: &Result<(), Capture<ExitReason, Trap>>,
		_machine: &Machine,
	) {
	}
}
