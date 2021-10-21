# IVMC VM Implementation Guide {#vmguide}

> How to add IVMC interface to Your Ethereum VM implementation.

## An example

You can start with [the example implementation of IVMC VM interface in C++](@ref example_vm.cpp).

## VM instance

The VM instance is described by the ::ivmc_vm struct. It contains the
basic static information about the VM like name and version. The struct also
includes the VM methods (in form of function pointers) to allow the Host
to interact with the VM.

Some methods are optional. The VM must implement at least all mandatory ones.

The instance struct must also include the IVMC ABI version (::IVMC_ABI_VERSION)
it was build with. This allows the Host to check the ABI compatibility when
loading VMs dynamically.

The VM instance is created and returned as a pointer from a special "create"
function. The IVMC recommends to name the function by the VM codename,
e.g. ::ivmc_create_example_vm().

## VM methods implementation

Each VM methods takes the pointer to the ::ivmc_vm as the first argument.
The VM implementation can extend the ::ivmc_vm struct for storing internal
data. This allow implementing the VM in object-oriented manner.

The most important method is ::ivmc_vm::execute() because it executes EVM code.
Remember that the Host is allowed to invoke the execute method concurrently
so do not store data related to a particular execution context in the VM instance.

Before a client can actually execute a VM, it is important to implement the three
basic fields for querying name (::ivmc_vm::name), version (::ivmc_vm::version)
and capabilities (::ivmc_vm::get_capabilities()) as well as the ::ivmc_vm::destroy()
method to wind the VM down.

Other methods are optional.

## Resource management

All additional resources allocated when the VM instance is created must be
freed when the destroy method is invoked.

The VM implementation can also attach additional resources to the ::ivmc_result
of an execution. These resource must be freed when the ::ivmc_result::release()
method is invoked.


*Have fun!*
