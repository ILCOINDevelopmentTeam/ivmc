# IVMC

[![chat: on gitter][gitter badge]][Gitter]
[![readme style: standard][readme style standard badge]][standard readme]

> Ethereum Client-VM Connector API

The IVMC is the low-level ABI between Ethereum Virtual Machines (EVMs) and
Ethereum Clients. On the EVM side it supports classic EVM1 and [ewasm].
On the Client-side it defines the interface for EVM implementations
to access Ethereum environment and state.


## Usage

### Documentation

Please visit the [documentation].

### Languages support

| Language                      | Supported Versions    | Supported Compilers            | Feature Support
| ----------------------------- | --------------------- | ------------------------------ | -------------------
| **C**                         | C99, C11              | GCC 7+, clang 5+, MSVC 2017+   | Host- and VM-side
| **C++**                       | C++17                 | GCC 7+, clang 5+, MSVC 2017+   | Host- and VM-side
| **Go** _(bindings)_           | 1.11 - 1.14 (modules) |                                | Host-side only
| **Rust** _(bindings)_[¹](#n1) | 2018 edition          | 1.37.0 and newer               | VM-side only
| **Java** _(bindings)_[²](#n2) | 11                    |                                | Host-side only

1. <sup id="n1">↑</sup> Rust support is limited and not complete yet, but it is mostly functional already. Breaking changes are possible at this stage.
2. <sup id="n2">↑</sup> Java support is in progress and the interface remains in flux. Breaking changes are possible at this stage.

### Testing tools

* **ivmc run** ([tools/ivmc]) — executes bytecode in any IVMC-compatible VM implementation.
* **ivmc-vmtester** ([tools/vmtester]) — can test any EVM implementation for compatibility with IVMC.
* **evm-test** ([ivmone → test/unittests]) — allows running the collection of [ivmone]'s unit tests on any IVMC-compatible EVM implementation.
* **ivmone-fuzzer** ([ivmone → test/fuzzer]) — differential fuzzer for IVMC-compatible EVM implementations. 


## Related projects

### EVMs

- [aleth-interpreter]
- [Daytona]
- [eip1962-ivmc] (EIP-2003 style precompile)
- [evmjit]
- [ivmone]
- [Hera]
- [Hera.rs]
- [ssvm-ivmc]

### Clients

- [aleth]
- [core-geth] (in progress)
- [ivmc-js]
- [go-ethereum] (in progress)
- [nim-ivmc]
- [pyevm] (in progress)
- [pyethereum] (abandoned)
- [rust-ssvm] (Rust Host-side)
- [silkworm]
- [Solidity] (for integration testing)
- [turbo-geth]

## Maintainers

- Alex Beregszaszi [@axic]
- Paweł Bylica [@chfast]

See also the list of [IVMC Authors](AUTHORS.md).

## Contributing

[![chat: on gitter][gitter badge]][Gitter]

Talk with us on the [IVMC Gitter chat][Gitter].

## License

[![license badge]][Apache License, Version 2.0]

Licensed under the [Apache License, Version 2.0].

## Internal

### Making new release

1. Update [CHANGELOG.md](CHANGELOG.md), put the release date, update release link.
2. `git add CHANGELOG.md`.
3. Tag new release: `bumpversion --allow-dirty prerel`.
4. Prepare CHANGELOG for next release: add unreleased section and link.
5. `git add CHANGELOG.md`.
6. Start new release series: `bumpversion --allow-dirty --no-tag minor`.


[@axic]: https://github.com/axic
[@chfast]: https://github.com/chfast
[Apache License, Version 2.0]: LICENSE
[documentation]: https://ethereum.github.io/ivmc
[ewasm]: https://github.com/ewasm/design
[evmjit]: https://github.com/ILCOINDevelopmentTeam/evmjit
[ivmone]: https://github.com/ILCOINDevelopmentTeam/ivmone
[ivmone → test/fuzzer]: https://github.com/ILCOINDevelopmentTeam/ivmone/tree/master/test/fuzzer
[ivmone → test/unittests]: https://github.com/ILCOINDevelopmentTeam/ivmone/tree/master/test/unittests
[Hera]: https://github.com/ewasm/hera
[Hera.rs]: https://github.com/ewasm/hera.rs
[Daytona]: https://github.com/axic/daytona
[eip1962-ivmc]: https://github.com/axic/eip1962-ivmc
[ssvm-ivmc]: https://github.com/second-state/ssvm-ivmc
[Gitter]: https://gitter.im/ethereum/ivmc
[aleth-interpreter]: https://github.com/ILCOINDevelopmentTeam/aleth/tree/master/libaleth-interpreter
[aleth]: https://github.com/ILCOINDevelopmentTeam/aleth
[Solidity]: https://github.com/ILCOINDevelopmentTeam/solidity
[nim-ivmc]: https://github.com/status-im/nim-ivmc
[go-ethereum]: https://github.com/ILCOINDevelopmentTeam/go-ethereum/pull/17954
[pyevm]: https://github.com/ILCOINDevelopmentTeam/py-evm
[pyethereum]: https://github.com/ILCOINDevelopmentTeam/pyethereum/pull/406
[silkworm]: https://github.com/torquem-ch/silkworm
[turbo-geth]: https://github.com/ledgerwatch/turbo-geth
[core-geth]: https://github.com/etclabscore/core-geth/issues/55
[ivmc-js]: https://github.com/RainBlock/ivmc-js
[rust-ssvm]: https://github.com/second-state/rust-ssvm
[standard readme]: https://github.com/RichardLitt/standard-readme
[tools/ivmc]: https://github.com/ILCOINDevelopmentTeam/ivmc/tree/master/tools/ivmc
[tools/vmtester]: https://github.com/ILCOINDevelopmentTeam/ivmc/tree/master/tools/vmtester

[gitter badge]: https://img.shields.io/gitter/room/ethereum/ivmc.svg
[license badge]: https://img.shields.io/github/license/ethereum/ivmc.svg?logo=apache
[readme style standard badge]: https://img.shields.io/badge/readme%20style-standard-brightgreen.svg
