# IVMC: Ethereum Client-VM Connector API.
# Copyright 2020 The IVMC Authors.
# Licensed under the Apache License, Version 2.0.

set(PREFIX ${PROJECT_NAME}/examples)

add_test(NAME ${PREFIX}/example-static COMMAND ivmc-example-static)
add_test(NAME ${PREFIX}/example-dynamic-load COMMAND ivmc-example $<TARGET_FILE:ivmc::example-vm>)
