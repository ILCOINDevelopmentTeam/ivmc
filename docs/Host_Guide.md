# IVMC Host Implementation Guide {#hostguide}

> How to bring IVMC support to Your Ethereum Client.

## Host interface

First of all, you have to implement the Host interface. The Host interface
allows VMs to query and modify Ethereum state during the execution.

The implementation can be done in object-oriented manner. 
The ::ivmc_host_interface lists the methods any Host must implement.

Moreover, each of the methods has a pointer to ::ivmc_host_context 
as a parameter. The context is owned entirely by the Host allowing a Host instance 
to behave as an object with data.

## VM usage

When Host implementation is ready it's time to start using IVMC VMs.

1. Firstly, create a VM instance. You need to know what is the name of the "create"
   function in particular VM implementation. The IVMC recommends to name the 
   function by the VM codename, e.g. ::ivmc_create_example_vm().
   Invoking the create function will give you the VM instance (::ivmc_vm). 
   It is recommended to create the VM instance once.
   
2. If you are interested in loading VMs dynamically (i.e. to use DLLs) 
   check out the [IVMC Loader](@ref loader) library.
   
3. The ::ivmc_vm contains information about the VM like 
   name (::ivmc_vm::name) or ABI version (::ivmc_vm::abi_version)
   and methods.
   
4. To execute code in the VM use the "execute()" method (::ivmc_vm::execute).
   You will need:
   - the code to execute,
   - the message (::ivmc_message) object that describes the execution context,
   - the Host instance, passed as ::ivmc_host_context pointer.
   
5. When execution finishes you will receive ::ivmc_result object that describes
   the results of the execution.
   
Have fun!