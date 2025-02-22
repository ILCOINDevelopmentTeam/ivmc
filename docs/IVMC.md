# IVMC – Ethereum Client-VM Connector API {#mainpage}

**ABI version 10**

The IVMC is the low-level ABI between Ethereum Virtual Machines (EVMs) and
Ethereum Clients. On the EVM-side it supports classic EVM1 and [ewasm].
On the Client-side it defines the interface for EVM implementations
to access Ethereum environment and state.


# Guides {#guides}

- [Host Implementation Guide](@ref hostguide)
- [VM Implementation Guide](@ref vmguide)


# Versioning {#versioning}

The IVMC project uses [Semantic Versioning](https://semver.org).
The version format is `MAJOR.MINOR.PATCH`.

The _MAJOR_ version number is also referenced as the **IVMC ABI version**.
This ABI version is available to VM and Host implementations by ::IVMC_ABI_VERSION.
For example IVMC 3.2.1 would have ABI version 3 and therefore this project release
can be referenced as IVMC ABIv3 or just IVMC 3.
Every C ABI breaking change requires increasing the _MAJOR_ version number.

The releases with _MINOR_ version change allow adding new API features
and modifying the language bindings API.
Backward incompatible API changes are allowed but should be avoided if possible.

The releases with _PATCH_ should only include bug fixes. Exceptionally,
API changes are allowed when required to fix a broken feature.


# Modules {#modules}

- [IVMC](@ref IVMC)
   – the main component that defines API for VMs and Clients (Hosts).
- [IVMC C++ API](@ref ivmc)
   – the wrappers and bindings for C++.
- [IVMC Loader](@ref loader)
   – the library for loading VMs implemented as Dynamically Loaded Libraries (DLLs, shared objects).
- [IVMC Helpers](@ref helpers)
   – a collection of utility functions for easier integration with IVMC.
- [EVM Instructions](@ref instructions)
   – the library with collection of metrics for EVM1 instruction set.
- [IVMC VM Tester](@ref vmtester)
   – the IVMC-compatibility testing tool for VM implementations.


# Language bindings {#bindings}

## Go

```go
import "github.com/ethereum/ivmc/bindings/go/ivmc"
```


[ewasm]: https://github.com/ewasm/design


@addtogroup IVMC

## Terms

1. **VM** – An Ethereum Virtual Machine instance/implementation.
2. **Host** – An entity controlling the VM.
   The Host requests code execution and responses to VM queries by callback
   functions. This usually represents an Ethereum Client.


## Responsibilities

### VM

- Executes the code (obviously).
- Calculates the running gas cost and manages the gas counter except the refund
  counter.
- Controls the call depth, including the exceptional termination of execution
  in case the maximum depth is reached.


### Host

- Provides access to State.
- Creates new accounts (with code being a result of VM execution).
- Handles refunds entirely.
- Manages the set of precompiled contracts and handles execution of messages
  coming to them.
