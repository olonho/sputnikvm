#[macro_use]
mod macros;
mod system;

use crate::{CallScheme, Context, ExitFatal, ExitReason, Handler, Opcode, Runtime, Transfer};
use alloc::vec::Vec;
use core::cmp::min;
use evm_core::{Capture, ExitError, ExitSucceed, Machine};
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

pub fn fill_external_table<H: Handler>(
	table: &mut [fn(
		state: &mut Machine,
		position: usize,
		context: usize,
		handler: usize,
	) -> evm_core::Control; 256],
) {
	use core::intrinsics::transmute;
	macro_rules! from_context {
		( $context:expr ) => {
			unsafe { transmute::<usize, &mut Runtime>($context) }
		};
	}
	macro_rules! from_handler {
		( $handler:expr, $H:ident ) => {
			unsafe { transmute::<usize, &mut $H>($handler) }
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
	macro_rules! pop_h256 {
		( $machine:expr, $( $x:ident ),* ) => (
			$(
				let $x = match $machine.stack_mut().pop() {
					Ok(value) => {
						let mut res = H256([0; 32]);
						value.to_big_endian(&mut res[..]);
						res
					},
					Err(e) =>return evm_core::Control::Exit(e.into()),
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
	fn address(
		machine: &mut Machine,
		_position: usize,
		context: usize,
		_handler: usize,
	) -> evm_core::Control {
		let runtime = from_context!(context);
		let ret = H256::from(runtime.context.address);
		push_h256!(machine, ret);
		evm_core::Control::Continue(1)
	}
	fn sha3(
		machine: &mut Machine,
		_position: usize,
		_context: usize,
		_handler: usize,
	) -> evm_core::Control {
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
	fn callvalue(
		machine: &mut Machine,
		_position: usize,
		context: usize,
		_handler: usize,
	) -> evm_core::Control {
		let runtime = from_context!(context);
		let mut ret = H256::default();
		runtime.context.apparent_value.to_big_endian(&mut ret[..]);
		push_h256!(machine, ret);
		evm_core::Control::Continue(1)
	}
	fn returndatasize(
		machine: &mut Machine,
		_position: usize,
		context: usize,
		_handler: usize,
	) -> evm_core::Control {
		let runtime = from_context!(context);
		let size = U256::from(runtime.return_data_buffer.len());
		push_u256!(machine, size);
		evm_core::Control::Continue(1)
	}
	fn returndatacopy(
		machine: &mut Machine,
		_position: usize,
		context: usize,
		_handler: usize,
	) -> evm_core::Control {
		pop_u256!(machine, memory_offset, data_offset, len);
		try_or_fail!(machine.memory_mut().resize_offset(memory_offset, len));
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
	fn chainid<H: Handler>(
		machine: &mut Machine,
		_position: usize,
		_context: usize,
		handler: usize,
	) -> evm_core::Control {
		let handler = from_handler!(handler, H);
		push_u256!(machine, handler.chain_id());
		evm_core::Control::Continue(1)
	}
	fn balance<H: Handler>(
		machine: &mut Machine,
		_position: usize,
		_context: usize,
		handler: usize,
	) -> evm_core::Control {
		let handler = from_handler!(handler, H);
		pop_h256!(machine, address);
		push_u256!(machine, handler.balance(address.into()));
		evm_core::Control::Continue(1)
	}
	fn selfbalance<H: Handler>(
		machine: &mut Machine,
		_position: usize,
		context: usize,
		handler: usize,
	) -> evm_core::Control {
		let handler = from_handler!(handler, H);
		let runtime = from_context!(context);
		push_u256!(machine, handler.balance(runtime.context.address));
		evm_core::Control::Continue(1)
	}
	fn origin<H: Handler>(
		machine: &mut Machine,
		_position: usize,
		_context: usize,
		handler: usize,
	) -> evm_core::Control {
		let handler = from_handler!(handler, H);
		let ret = H256::from(handler.origin());
		push_h256!(machine, ret);
		evm_core::Control::Continue(1)
	}
	fn caller<H: Handler>(
		machine: &mut Machine,
		_position: usize,
		context: usize,
		_handler: usize,
	) -> evm_core::Control {
		let runtime = from_context!(context);
		let ret = H256::from(runtime.context.caller);
		push_h256!(machine, ret);
		evm_core::Control::Continue(1)
	}
	fn gasprice<H: Handler>(
		machine: &mut Machine,
		_position: usize,
		_context: usize,
		handler: usize,
	) -> evm_core::Control {
		let mut ret = H256::default();
		let handler = from_handler!(handler, H);
		handler.gas_price().to_big_endian(&mut ret[..]);
		push_h256!(machine, ret);
		evm_core::Control::Continue(1)
	}
	fn base_fee<H: Handler>(
		machine: &mut Machine,
		_position: usize,
		_context: usize,
		handler: usize,
	) -> evm_core::Control {
		let mut ret = H256::default();
		let handler = from_handler!(handler, H);
		handler.block_base_fee_per_gas().to_big_endian(&mut ret[..]);
		push_h256!(machine, ret);
		evm_core::Control::Continue(1)
	}
	fn extcodesize<H: Handler>(
		machine: &mut Machine,
		_position: usize,
		_context: usize,
		handler: usize,
	) -> evm_core::Control {
		let handler = from_handler!(handler, H);
		pop_h256!(machine, address);
		push_u256!(machine, handler.code_size(address.into()));
		evm_core::Control::Continue(1)
	}
	fn extcodehash<H: Handler>(
		machine: &mut Machine,
		_position: usize,
		_context: usize,
		handler: usize,
	) -> evm_core::Control {
		let handler = from_handler!(handler, H);
		pop_h256!(machine, address);
		push_h256!(machine, handler.code_hash(address.into()));
		evm_core::Control::Continue(1)
	}
	fn extcodecopy<H: Handler>(
		machine: &mut Machine,
		_position: usize,
		_context: usize,
		handler: usize,
	) -> evm_core::Control {
		pop_h256!(machine, address);
		pop_u256!(machine, memory_offset, code_offset, len);
		try_or_fail!(machine.memory_mut().resize_offset(memory_offset, len));
		let handler = from_handler!(handler, H);
		match machine.memory_mut().copy_large(
			memory_offset,
			code_offset,
			len,
			&handler.code(address.into()),
		) {
			Ok(()) => (),
			Err(e) => return evm_core::Control::Exit(e.into()),
		};
		evm_core::Control::Continue(1)
	}
	fn blockhash<H: Handler>(
		machine: &mut Machine,
		_position: usize,
		_context: usize,
		handler: usize,
	) -> evm_core::Control {
		let handler = from_handler!(handler, H);
		pop_u256!(machine, number);
		push_h256!(machine, handler.block_hash(number));
		evm_core::Control::Continue(1)
	}
	fn coinbase<H: Handler>(
		machine: &mut Machine,
		_position: usize,
		_context: usize,
		handler: usize,
	) -> evm_core::Control {
		let handler = from_handler!(handler, H);
		push_h256!(machine, handler.block_coinbase());
		evm_core::Control::Continue(1)
	}

	fn timestamp<H: Handler>(
		machine: &mut Machine,
		_position: usize,
		_context: usize,
		handler: usize,
	) -> evm_core::Control {
		let handler = from_handler!(handler, H);
		push_u256!(machine, handler.block_timestamp());
		evm_core::Control::Continue(1)
	}

	fn number<H: Handler>(
		machine: &mut Machine,
		_position: usize,
		_context: usize,
		handler: usize,
	) -> evm_core::Control {
		let handler = from_handler!(handler, H);
		push_u256!(machine, handler.block_number());
		evm_core::Control::Continue(1)
	}
	fn difficulty<H: Handler>(
		machine: &mut Machine,
		_position: usize,
		_context: usize,
		handler: usize,
	) -> evm_core::Control {
		let handler = from_handler!(handler, H);
		push_u256!(machine, handler.block_difficulty());
		evm_core::Control::Continue(1)
	}
	fn gaslimit<H: Handler>(
		machine: &mut Machine,
		_position: usize,
		_context: usize,
		handler: usize,
	) -> evm_core::Control {
		let handler = from_handler!(handler, H);
		push_u256!(machine, handler.block_gas_limit());
		evm_core::Control::Continue(1)
	}
	fn sload<H: Handler>(
		machine: &mut Machine,
		_position: usize,
		context: usize,
		handler: usize,
	) -> evm_core::Control {
		let handler = from_handler!(handler, H);
		let runtime = from_context!(context);

		pop_h256!(machine, index);
		let value = handler.storage(runtime.context.address, index);
		push_h256!(machine, value);

		event!(SLoad {
			address: runtime.context.address,
			index,
			value
		});
		evm_core::Control::Continue(1)
	}
	fn sstore<H: Handler>(
		machine: &mut Machine,
		_position: usize,
		context: usize,
		handler: usize,
	) -> evm_core::Control {
		let handler = from_handler!(handler, H);
		let runtime = from_context!(context);
		pop_h256!(machine, index, value);

		event!(SStore {
			address: runtime.context.address,
			index,
			value
		});
		match handler.set_storage(runtime.context.address, index, value) {
			Ok(()) => evm_core::Control::Continue(1),
			Err(e) => evm_core::Control::Exit(e.into()),
		}
	}
	fn gas<H: Handler>(
		machine: &mut Machine,
		_position: usize,
		_context: usize,
		handler: usize,
	) -> evm_core::Control {
		let handler = from_handler!(handler, H);
		push_u256!(machine, handler.gas_left());
		evm_core::Control::Continue(1)
	}
	fn log<H: Handler>(
		machine: &mut Machine,
		_position: usize,
		context: usize,
		handler: usize,
		n: i32,
	) -> evm_core::Control {
		pop_u256!(machine, offset, len);

		try_or_fail!(machine.memory_mut().resize_offset(offset, len));
		let data = if len == U256::zero() {
			Vec::new()
		} else {
			let offset = as_usize_or_fail!(offset);
			let len = as_usize_or_fail!(len);

			machine.memory().get(offset, len)
		};

		let mut topics = Vec::new();
		for _ in 0..(n as usize) {
			match machine.stack_mut().pop_h256() {
				Ok(value) => {
					topics.push(value);
				}
				Err(e) => return evm_core::Control::Exit(e.into()),
			}
		}

		let runtime = from_context!(context);
		let handler = from_handler!(handler, H);
		match handler.log(runtime.context.address, topics, data) {
			Ok(()) => evm_core::Control::Continue(1),
			Err(e) => evm_core::Control::Exit(e.into()),
		}
	}
	fn log0<H: Handler>(
		machine: &mut Machine,
		position: usize,
		context: usize,
		handler: usize,
	) -> evm_core::Control {
		log::<H>(machine, position, context, handler, 0)
	}
	fn log1<H: Handler>(
		machine: &mut Machine,
		position: usize,
		context: usize,
		handler: usize,
	) -> evm_core::Control {
		log::<H>(machine, position, context, handler, 1)
	}
	fn log2<H: Handler>(
		machine: &mut Machine,
		position: usize,
		context: usize,
		handler: usize,
	) -> evm_core::Control {
		log::<H>(machine, position, context, handler, 2)
	}
	fn log3<H: Handler>(
		machine: &mut Machine,
		position: usize,
		context: usize,
		handler: usize,
	) -> evm_core::Control {
		log::<H>(machine, position, context, handler, 3)
	}
	fn log4<H: Handler>(
		machine: &mut Machine,
		position: usize,
		context: usize,
		handler: usize,
	) -> evm_core::Control {
		log::<H>(machine, position, context, handler, 4)
	}
	fn suicide<H: Handler>(
		machine: &mut Machine,
		_position: usize,
		context: usize,
		handler: usize,
	) -> evm_core::Control {
		pop_h256!(machine, target);
		let handler = from_handler!(handler, H);
		let runtime = from_context!(context);
		match handler.mark_delete(runtime.context.address, target.into()) {
			Ok(()) => (),
			Err(e) => return evm_core::Control::Exit(e.into()),
		}
		evm_core::Control::Exit(ExitSucceed::Suicided.into())
	}
	/*
	fn create<H: Handler>(
		machine: &mut Machine,
		_position: usize,
		context: usize,
		handler: usize,
		is_create2: bool,
	) -> evm_core::Control {
		let handler = from_handler!(handler, H);
		let runtime = from_context!(context);
		runtime.return_data_buffer = Vec::new();

		pop_u256!(machine, value, code_offset, len);

		try_or_fail!(machine.memory_mut().resize_offset(code_offset, len));
		let code = if len == U256::zero() {
			Vec::new()
		} else {
			let code_offset = as_usize_or_fail!(code_offset);
			let len = as_usize_or_fail!(len);

			machine.memory().get(code_offset, len)
		};

		let scheme = if is_create2 {
			pop_h256!(machine, salt);
			let code_hash = H256::from_slice(Keccak256::digest(&code).as_slice());
			CreateScheme::Create2 {
				caller: runtime.context.address,
				salt,
				code_hash,
			}
		} else {
			CreateScheme::Legacy {
				caller: runtime.context.address,
			}
		};

		match handler.create(runtime.context.address, scheme, value, code, None) {
			Capture::Exit((reason, address, return_data)) => {
				runtime.return_data_buffer = return_data;
				let create_address: H256 = address.map(|a| a.into()).unwrap_or_default();

				match reason {
					ExitReason::Succeed(_) => {
						push_h256!(machine, create_address);
						evm_core::Control::Continue(1)
					}
					ExitReason::Revert(_) => {
						push_h256!(machine, H256::default());
						evm_core::Control::Continue(1)
					}
					ExitReason::Error(_) => {
						push_h256!(machine, H256::default());
						evm_core::Control::Continue(1)
					}
					ExitReason::Fatal(e) => {
						push_h256!(machine, H256::default());
						evm_core::Control::Exit(e.into())
					}
				}
			}
			Capture::Trap(interrupt) => {
				push_h256!(machine, H256::default());
				evm_core::Control::Exit(Control::CreateInterrupt(interrupt).into())
			}
		}
	}
	fn create1<H: Handler>(
		machine: &mut Machine,
		position: usize,
		context: usize,
		handler: usize,
	) -> evm_core::Control {
		create(machine, position, context, handler, false)
	}
	fn create2<H: Handler>(
		machine: &mut Machine,
		position: usize,
		context: usize,
		handler: usize,
	) -> evm_core::Control {
		create(machine, position, context, handler, true)
	} */
	pub fn call<H: Handler>(
		machine: &mut Machine,
		_position: usize,
		context: usize,
		handler: usize,
		scheme: CallScheme,
	) -> evm_core::Control {
		let handler = from_handler!(handler, H);
		let runtime = from_context!(context);
		runtime.return_data_buffer = Vec::new();

		pop_u256!(machine, gas);
		pop_h256!(machine, to);
		let gas = if gas > U256::from(u64::MAX) {
			None
		} else {
			Some(gas.as_u64())
		};

		let value = match scheme {
			CallScheme::Call | CallScheme::CallCode => {
				pop_u256!(machine, value);
				value
			}
			CallScheme::DelegateCall | CallScheme::StaticCall => U256::zero(),
		};

		pop_u256!(machine, in_offset, in_len, out_offset, out_len);

		try_or_fail!(machine.memory_mut().resize_offset(in_offset, in_len));
		try_or_fail!(machine.memory_mut().resize_offset(out_offset, out_len));
		let input = if in_len == U256::zero() {
			Vec::new()
		} else {
			let in_offset = as_usize_or_fail!(in_offset);
			let in_len = as_usize_or_fail!(in_len);

			machine.memory().get(in_offset, in_len)
		};

		let context = match scheme {
			CallScheme::Call | CallScheme::StaticCall => Context {
				address: to.into(),
				caller: runtime.context.address,
				apparent_value: value,
			},
			CallScheme::CallCode => Context {
				address: runtime.context.address,
				caller: runtime.context.address,
				apparent_value: value,
			},
			CallScheme::DelegateCall => Context {
				address: runtime.context.address,
				caller: runtime.context.caller,
				apparent_value: runtime.context.apparent_value,
			},
		};

		let transfer = if scheme == CallScheme::Call {
			Some(Transfer {
				source: runtime.context.address,
				target: to.into(),
				value,
			})
		} else if scheme == CallScheme::CallCode {
			Some(Transfer {
				source: runtime.context.address,
				target: runtime.context.address,
				value,
			})
		} else {
			None
		};

		match handler.call(
			to.into(),
			transfer,
			input,
			gas,
			scheme == CallScheme::StaticCall,
			context,
		) {
			Capture::Exit((reason, return_data)) => {
				runtime.return_data_buffer = return_data;
				let target_len = min(out_len, U256::from(runtime.return_data_buffer.len()));

				match reason {
					ExitReason::Succeed(_) => {
						match runtime.machine.memory_mut().copy_large(
							out_offset,
							U256::zero(),
							target_len,
							&runtime.return_data_buffer[..],
						) {
							Ok(()) => {
								push_u256!(machine, U256::one());
								evm_core::Control::Continue(1)
							}
							Err(_) => {
								push_u256!(machine, U256::zero());
								evm_core::Control::Continue(1)
							}
						}
					}
					ExitReason::Revert(_) => {
						push_u256!(machine, U256::zero());

						let _ = machine.memory_mut().copy_large(
							out_offset,
							U256::zero(),
							target_len,
							&runtime.return_data_buffer[..],
						);
						evm_core::Control::Continue(1)
					}
					ExitReason::Error(_) => {
						push_u256!(machine, U256::zero());
						evm_core::Control::Continue(1)
					}
					ExitReason::Fatal(e) => {
						push_u256!(machine, U256::zero());
						evm_core::Control::Exit(e.into())
					}
				}
			}
			Capture::Trap(_interrupt) => {
				push_h256!(machine, H256::default());
				//evm_core::Control::Exit(Control::CallInterrupt(interrupt).into())
				unreachable!()
			}
		}
	}
	fn call_regular<H: Handler>(
		machine: &mut Machine,
		position: usize,
		context: usize,
		handler: usize,
	) -> evm_core::Control {
		call::<H>(machine, position, context, handler, CallScheme::Call)
	}
	fn call_code<H: Handler>(
		machine: &mut Machine,
		position: usize,
		context: usize,
		handler: usize,
	) -> evm_core::Control {
		call::<H>(machine, position, context, handler, CallScheme::CallCode)
	}
	fn static_call<H: Handler>(
		machine: &mut Machine,
		position: usize,
		context: usize,
		handler: usize,
	) -> evm_core::Control {
		call::<H>(machine, position, context, handler, CallScheme::StaticCall)
	}
	fn delegate_call<H: Handler>(
		machine: &mut Machine,
		position: usize,
		context: usize,
		handler: usize,
	) -> evm_core::Control {
		call::<H>(
			machine,
			position,
			context,
			handler,
			CallScheme::DelegateCall,
		)
	}
	table[Opcode::ADDRESS.as_usize()] = address;
	table[Opcode::SHA3.as_usize()] = sha3;
	table[Opcode::CHAINID.as_usize()] = chainid::<H>;
	table[Opcode::CALLER.as_usize()] = caller::<H>;
	table[Opcode::CALLVALUE.as_usize()] = callvalue;
	table[Opcode::RETURNDATASIZE.as_usize()] = returndatasize;
	table[Opcode::RETURNDATACOPY.as_usize()] = returndatacopy;
	table[Opcode::CHAINID.as_usize()] = chainid::<H>;
	table[Opcode::BALANCE.as_usize()] = balance::<H>;
	table[Opcode::SELFBALANCE.as_usize()] = selfbalance::<H>;
	table[Opcode::ORIGIN.as_usize()] = origin::<H>;
	table[Opcode::GASPRICE.as_usize()] = gasprice::<H>;
	table[Opcode::BASEFEE.as_usize()] = base_fee::<H>;
	table[Opcode::EXTCODEHASH.as_usize()] = extcodehash::<H>;
	table[Opcode::EXTCODECOPY.as_usize()] = extcodecopy::<H>;
	table[Opcode::EXTCODESIZE.as_usize()] = extcodesize::<H>;
	table[Opcode::BLOCKHASH.as_usize()] = blockhash::<H>;
	table[Opcode::COINBASE.as_usize()] = coinbase::<H>;
	table[Opcode::BLOCKHASH.as_usize()] = blockhash::<H>;
	table[Opcode::TIMESTAMP.as_usize()] = timestamp::<H>;
	table[Opcode::NUMBER.as_usize()] = number::<H>;
	table[Opcode::DIFFICULTY.as_usize()] = difficulty::<H>;
	table[Opcode::GASLIMIT.as_usize()] = gaslimit::<H>;
	table[Opcode::SLOAD.as_usize()] = sload::<H>;
	table[Opcode::SSTORE.as_usize()] = sstore::<H>;
	table[Opcode::GAS.as_usize()] = gas::<H>;
	table[Opcode::SUICIDE.as_usize()] = suicide::<H>;
	table[Opcode::LOG0.as_usize()] = log0::<H>;
	table[Opcode::LOG1.as_usize()] = log1::<H>;
	table[Opcode::LOG2.as_usize()] = log2::<H>;
	table[Opcode::LOG3.as_usize()] = log3::<H>;
	table[Opcode::LOG4.as_usize()] = log4::<H>;
	// table[Opcode::CREATE.as_usize()] = create1::<H>;
	// table[Opcode::CREATE2.as_usize()] = create2::<H>;
	table[Opcode::CALL.as_usize()] = call_regular::<H>;
	table[Opcode::CALLCODE.as_usize()] = call_code::<H>;
	table[Opcode::DELEGATECALL.as_usize()] = delegate_call::<H>;
	table[Opcode::STATICCALL.as_usize()] = static_call::<H>;
}
