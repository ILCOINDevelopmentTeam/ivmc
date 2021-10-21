// IVMC: Ethereum Client-VM Connector API.
// Copyright 2019-2020 The IVMC Authors.
// Licensed under the Apache License, Version 2.0.
package org.ethereum.ivmc;

/** Exception thrown when the IVMC binding or VM fails to load. */
public class IvmcLoaderException extends Exception {
  public IvmcLoaderException(String message) {
    super(message);
  }

  public IvmcLoaderException(String message, Throwable cause) {
    super(message, cause);
  }
}
