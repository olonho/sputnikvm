#[macro_use]
mod macros;
mod system;

use primitive_types::{H256, U256};
use evm_core::Machine;
use crate::{CallScheme, ExitReason, Handler, Opcode, Runtime};

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

pub fn fill_external_table(table: &mut [fn(state: &mut Machine, position: usize, context: usize) -> evm_core::Control; 256]) {
	use std::mem::transmute;
	macro_rules! from_context {
		( $context:expr ) => (
			unsafe { transmute::<usize, &mut Runtime>($context) }
		)
	}
	fn address(machine: &mut Machine, _position: usize, context: usize) -> evm_core::Control {
		let runtime = from_context!(context); // unsafe { transmute::<usize, &mut Runtime>(context) };
		let ret = H256::from(runtime.context.address);
		match machine.stack_mut().push(U256::from_big_endian(ret.as_bytes())) {
			Ok(()) => (),
			Err(e) => return evm_core::Control::Exit(e.into()),
		}
		evm_core::Control::Continue(1)
	}

	table[Opcode::ADDRESS.as_usize()] = address;
}
