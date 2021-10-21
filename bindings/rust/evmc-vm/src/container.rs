/* IVMC: Ethereum Client-VM Connector API.
 * Copyright 2019 The IVMC Authors.
 * Licensed under the Apache License, Version 2.0.
 */

use crate::EvmcVm;

use std::ops::Deref;

/// Container struct for IVMC instances and user-defined data.
pub struct EvmcContainer<T>
where
    T: EvmcVm + Sized,
{
    #[allow(dead_code)]
    instance: ::ivmc_sys::ivmc_vm,
    vm: T,
}

impl<T> EvmcContainer<T>
where
    T: EvmcVm + Sized,
{
    /// Basic constructor.
    pub fn new(_instance: ::ivmc_sys::ivmc_vm) -> Box<Self> {
        Box::new(Self {
            instance: _instance,
            vm: T::init(),
        })
    }

    /// Take ownership of the given pointer and return a box.
    ///
    /// # Safety
    /// This function expects a valid instance to be passed.
    pub unsafe fn from_ffi_pointer(instance: *mut ::ivmc_sys::ivmc_vm) -> Box<Self> {
        assert!(!instance.is_null(), "from_ffi_pointer received NULL");
        Box::from_raw(instance as *mut EvmcContainer<T>)
    }

    /// Convert boxed self into an FFI pointer, surrendering ownership of the heap data.
    ///
    /// # Safety
    /// This function will return a valid instance pointer.
    pub unsafe fn into_ffi_pointer(boxed: Box<Self>) -> *mut ::ivmc_sys::ivmc_vm {
        Box::into_raw(boxed) as *mut ::ivmc_sys::ivmc_vm
    }
}

impl<T> Deref for EvmcContainer<T>
where
    T: EvmcVm,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.vm
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use crate::{ExecutionContext, ExecutionMessage, ExecutionResult};

    struct TestVm {}

    impl EvmcVm for TestVm {
        fn init() -> Self {
            TestVm {}
        }
        fn execute(
            &self,
            _revision: ivmc_sys::ivmc_revision,
            _code: &[u8],
            _message: &ExecutionMessage,
            _context: Option<&mut ExecutionContext>,
        ) -> ExecutionResult {
            ExecutionResult::failure()
        }
    }

    unsafe extern "C" fn get_dummy_tx_context(
        _context: *mut ivmc_sys::ivmc_host_context,
    ) -> ivmc_sys::ivmc_tx_context {
        ivmc_sys::ivmc_tx_context {
            tx_gas_price: Uint256::default(),
            tx_origin: Address::default(),
            block_coinbase: Address::default(),
            block_number: 0,
            block_timestamp: 0,
            block_gas_limit: 0,
            block_difficulty: Uint256::default(),
            chain_id: Uint256::default(),
            block_base_fee: Uint256::default(),
        }
    }

    #[test]
    fn container_new() {
        let instance = ::ivmc_sys::ivmc_vm {
            abi_version: ::ivmc_sys::IVMC_ABI_VERSION as i32,
            name: std::ptr::null(),
            version: std::ptr::null(),
            destroy: None,
            execute: None,
            get_capabilities: None,
            set_option: None,
        };

        let code = [0u8; 0];

        let message = ::ivmc_sys::ivmc_message {
            kind: ::ivmc_sys::ivmc_call_kind::IVMC_CALL,
            flags: 0,
            depth: 0,
            gas: 0,
            recipient: ::ivmc_sys::ivmc_address::default(),
            sender: ::ivmc_sys::ivmc_address::default(),
            input_data: std::ptr::null(),
            input_size: 0,
            value: ::ivmc_sys::ivmc_uint256be::default(),
            create2_salt: ::ivmc_sys::ivmc_bytes32::default(),
            code_address: ::ivmc_sys::ivmc_address::default(),
        };
        let message: ExecutionMessage = (&message).into();

        let host = ::ivmc_sys::ivmc_host_interface {
            account_exists: None,
            get_storage: None,
            set_storage: None,
            get_balance: None,
            get_code_size: None,
            get_code_hash: None,
            copy_code: None,
            selfdestruct: None,
            call: None,
            get_tx_context: Some(get_dummy_tx_context),
            get_block_hash: None,
            emit_log: None,
            access_account: None,
            access_storage: None,
        };
        let host_context = std::ptr::null_mut();

        let mut context = ExecutionContext::new(&host, host_context);
        let container = EvmcContainer::<TestVm>::new(instance);
        assert_eq!(
            container
                .execute(
                    ivmc_sys::ivmc_revision::IVMC_PETERSBURG,
                    &code,
                    &message,
                    Some(&mut context)
                )
                .status_code(),
            ::ivmc_sys::ivmc_status_code::IVMC_FAILURE
        );

        let ptr = unsafe { EvmcContainer::into_ffi_pointer(container) };

        let mut context = ExecutionContext::new(&host, host_context);
        let container = unsafe { EvmcContainer::<TestVm>::from_ffi_pointer(ptr) };
        assert_eq!(
            container
                .execute(
                    ivmc_sys::ivmc_revision::IVMC_PETERSBURG,
                    &code,
                    &message,
                    Some(&mut context)
                )
                .status_code(),
            ::ivmc_sys::ivmc_status_code::IVMC_FAILURE
        );
    }
}
