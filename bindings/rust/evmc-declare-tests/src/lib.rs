/* IVMC: Ethereum Client-VM Connector API.
 * Copyright 2019 The IVMC Authors.
 * Licensed under the Apache License, Version 2.0.
 */

use ivmc_declare::ivmc_declare_vm;
use ivmc_vm::IvmcVm;
use ivmc_vm::ExecutionContext;
use ivmc_vm::ExecutionMessage;
use ivmc_vm::ExecutionResult;

#[ivmc_declare_vm("Foo VM", "ewasm, evm", "1.42-alpha.gamma.starship")]
pub struct FooVM {}

impl IvmcVm for FooVM {
    fn init() -> Self {
        FooVM {}
    }

    fn execute(
        &self,
        _revision: ivmc_sys::ivmc_revision,
        _code: &[u8],
        _message: &ExecutionMessage,
        _context: Option<&mut ExecutionContext>,
    ) -> ExecutionResult {
        ExecutionResult::success(1337, None)
    }
}
