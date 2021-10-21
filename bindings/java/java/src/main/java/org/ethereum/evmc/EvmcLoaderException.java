// IVMC: Ethereum Client-VM Connector API.
// Copyright 2019-2020 The IVMC Authors.
// Licensed under the Apache License, Version 2.0.
package org.ethereum.ivmc;

/** Exception thrown when the IVMC binding or VM fails to load. */
public class EvmcLoaderException extends Exception {
  public EvmcLoaderException(String message) {
    super(message);
  }

  public EvmcLoaderException(String message, Throwable cause) {
    super(message, cause);
  }
}
