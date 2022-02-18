#[macro_use]
mod macros;
mod system;

use crate::{CallScheme, ExitFatal, ExitReason, Handler, Opcode, Runtime};
use evm_core::{ExitError, Machine};
use primitive_types::{H256, U256};
use sha3::{Digest, Keccak256};

pub enum Control<H: Handler> {
	Continue,
	CallInterrupt(H::CallInterrupt),
	CreateInterrupt(H::CreateInterrupt),
	Exit(ExitReason),
}

fn handle_other<H: Handler>(state: &mut Runtime, opcode: Opcode, handler: &mut H) -> Control<H> {
	match handler.other(opcode, &mut state.machine) {
		Ok(()) => Control::Continue,
		Err(e) => Control::Exit(e.into()),
	}
}

pub fn eval<H: Handler>(state: &mut Runtime, opcode: Opcode, handler: &mut H) -> Control<H> {
	match opcode {
		Opcode::SHA3 => system::sha3(state),
		Opcode::ADDRESS => system::address(state),
		Opcode::BALANCE => system::balance(state, handler),
		Opcode::SELFBALANCE => system::selfbalance(state, handler),
		Opcode::ORIGIN => system::origin(state, handler),
		Opcode::CALLER => system::caller(state),
		Opcode::CALLVALUE => system::callvalue(state),
		Opcode::GASPRICE => system::gasprice(state, handler),
		Opcode::EXTCODESIZE => system::extcodesize(state, handler),
		Opcode::EXTCODEHASH => system::extcodehash(state, handler),
		Opcode::EXTCODECOPY => system::extcodecopy(state, handler),
		Opcode::RETURNDATASIZE => system::returndatasize(state),
		Opcode::RETURNDATACOPY => system::returndatacopy(state),
		Opcode::BLOCKHASH => system::blockhash(state, handler),
		Opcode::COINBASE => system::coinbase(state, handler),
		Opcode::TIMESTAMP => system::timestamp(state, handler),
		Opcode::NUMBER => system::number(state, handler),
		Opcode::DIFFICULTY => system::difficulty(state, handler),
		Opcode::GASLIMIT => system::gaslimit(state, handler),
		Opcode::SLOAD => system::sload(state, handler),
		Opcode::SSTORE => system::sstore(state, handler),
		Opcode::GAS => system::gas(state, handler),
		Opcode::LOG0 => system::log(state, 0, handler),
		Opcode::LOG1 => system::log(state, 1, handler),
		Opcode::LOG2 => system::log(state, 2, handler),
		Opcode::LOG3 => system::log(state, 3, handler),
		Opcode::LOG4 => system::log(state, 4, handler),
		Opcode::SUICIDE => system::suicide(state, handler),
		Opcode::CREATE => system::create(state, false, handler),
		Opcode::CREATE2 => system::create(state, true, handler),
		Opcode::CALL => system::call(state, CallScheme::Call, handler),
		Opcode::CALLCODE => system::call(state, CallScheme::CallCode, handler),
		Opcode::DELEGATECALL => system::call(state, CallScheme::DelegateCall, handler),
		Opcode::STATICCALL => system::call(state, CallScheme::StaticCall, handler),
		Opcode::CHAINID => system::chainid(state, handler),
		Opcode::BASEFEE => system::base_fee(state, handler),
		_ => handle_other(state, opcode, handler),
	}
}

pub fn fill_external_table(
	table: &mut [fn(state: &mut Machine, position: usize, context: usize) -> evm_core::Control;
		     256],
) {
	use std::mem::transmute;
	macro_rules! from_context {
		( $context:expr ) => {
			unsafe { transmute::<usize, &mut Runtime>($context) }
		};
	}
	macro_rules! pop_u256 {
		( $machine:expr, $( $x:ident ),* ) => (
			$(
				let $x = match $machine.stack_mut().pop() {
				Ok(value) => value,
				Err(e) => return evm_core::Control::Exit(e.into()),
			};
		)*
	);
	}
	macro_rules! push_u256 {
		( $machine:expr, $( $x:expr ),* ) => (
			$(
				match $machine.stack_mut().push($x) {
					Ok(_) => {},
					Err(e) => return evm_core::Control::Exit(e.into()),
				};
			)*
		);
	}
	macro_rules! push_h256 {
	( $machine:expr, $( $x:expr ),* ) => (
		$(
			match $machine.stack_mut().push(U256::from_big_endian(&$x[..])) {
				Ok(()) => (),
				Err(e) => return evm_core::Control::Exit(e.into()),
			}
		)*
		)
	}
	macro_rules! try_or_fail {
		( $e:expr ) => {
			match $e {
				Ok(v) => v,
				Err(e) => return evm_core::Control::Exit(e.into()),
			}
		};
	}
	macro_rules! as_usize_or_fail {
		( $v:expr ) => {{
			if $v > U256::from(usize::MAX) {
				return evm_core::Control::Exit(ExitFatal::NotSupported.into());
			}
			$v.as_usize()
		}};

		( $v:expr, $reason:expr ) => {{
			if $v > U256::from(usize::MAX) {
				return evm_core::Control::Exit($reason.into());
			}
			$v.as_usize()
		}};
	}
	fn address(machine: &mut Machine, _position: usize, context: usize) -> evm_core::Control {
		let runtime = from_context!(context);
		let ret = H256::from(runtime.context.address);
		push_h256!(machine, ret);
		evm_core::Control::Continue(1)
	}
	fn sha3(machine: &mut Machine, _position: usize, _context: usize) -> evm_core::Control {
		pop_u256!(machine, from, len);
		try_or_fail!(machine.memory_mut().resize_offset(from, len));
		let data = if len == U256::zero() {
			Vec::new()
		} else {
			let from = as_usize_or_fail!(from);
			let len = as_usize_or_fail!(len);
			machine.memory_mut().get(from, len)
		};

		let ret = Keccak256::digest(data.as_slice());
		push_h256!(machine, H256::from_slice(ret.as_slice()));

		evm_core::Control::Continue(1)
	}
	fn caller(machine: &mut Machine, _position: usize, context: usize) -> evm_core::Control {
		let runtime = from_context!(context);
		let ret = H256::from(runtime.context.caller);
		push_h256!(machine, ret);
		evm_core::Control::Continue(1)
	}
	fn callvalue(machine: &mut Machine, _position: usize, context: usize) -> evm_core::Control {
		let runtime = from_context!(context);
		let mut ret = H256::default();
		runtime.context.apparent_value.to_big_endian(&mut ret[..]);
		push_h256!(machine, ret);
		evm_core::Control::Continue(1)
	}
	fn returndatasize(machine: &mut Machine, _position: usize, context: usize) -> evm_core::Control {
		let runtime = from_context!(context);
		let size = U256::from(runtime.return_data_buffer.len());
		push_u256!(machine, size);
		evm_core::Control::Continue(1)
	}
	fn returndatacopy(machine: &mut Machine, _position: usize, context: usize) -> evm_core::Control {
		pop_u256!(machine, memory_offset, data_offset, len);
		try_or_fail!(machine
			.memory_mut()
			.resize_offset(memory_offset, len));
		let runtime = from_context!(context);
		if data_offset
			.checked_add(len)
			.map(|l| l > U256::from(runtime.return_data_buffer.len()))
			.unwrap_or(true)
		{
			return evm_core::Control::Exit(ExitError::OutOfOffset.into());
		}

		match machine.memory_mut().copy_large(
			memory_offset,
			data_offset,
			len,
			&runtime.return_data_buffer,
		) {
			Ok(()) => evm_core::Control::Continue(1),
			Err(e) => evm_core::Control::Exit(e.into()),
		}
	}

	table[Opcode::ADDRESS.as_usize()] = address;
	table[Opcode::SHA3.as_usize()] = sha3;
	table[Opcode::CALLER.as_usize()] = caller;
	table[Opcode::CALLVALUE.as_usize()] = callvalue;
	table[Opcode::RETURNDATASIZE.as_usize()] = returndatasize;
	table[Opcode::RETURNDATACOPY.as_usize()] = returndatacopy;

}
