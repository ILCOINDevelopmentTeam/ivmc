# IVMC VM Tester {#vmtester}

The IVMC project contains a IVMC-compatibility testing tool for VM implementations.

The tool is called `ivmc-vmtester` and to include it in the IVMC build
add `-DIVMC_TESTING=ON` CMake option to the project configuration step.

Usage is simple as

```sh
ivmc-vmtester [vm]
```

where `[vm]` is a path to a shared library with VM implementation.

For more information check `ivmc-vmtester --help`.
