/* IVMC: Ethereum Client-VM Connector API.
 * Copyright 2019 The IVMC Authors.
 * Licensed under the Apache License, Version 2.0.
 */

extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn gen_bindings() {
    let bindings = bindgen::Builder::default()
        .header("ivmc.h")
        .generate_comments(true)
        // do not generate an empty enum for IVMC_ABI_VERSION
        .constified_enum("")
        // generate Rust enums for each ivmc enum
        .rustified_enum("*")
        // force deriving the Hash trait on basic types (address, bytes32)
        .derive_hash(true)
        // force deriving the PratialEq trait on basic types (address, bytes32)
        .derive_partialeq(true)
        .opaque_type("ivmc_host_context")
        .whitelist_type("ivmc_.*")
        .whitelist_function("ivmc_.*")
        .whitelist_var("IVMC_ABI_VERSION")
        // TODO: consider removing this
        .size_t_is_usize(true)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

fn main() {
    gen_bindings();
}
