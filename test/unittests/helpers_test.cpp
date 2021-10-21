// IVMC: Ethereum Client-VM Connector API.
// Copyright 2018-2019 The IVMC Authors.
// Licensed under the Apache License, Version 2.0.

#include <ivmc/helpers.h>

#include <gtest/gtest.h>

// Compile time checks:

static_assert(sizeof(ivmc_bytes32) == 32, "ivmc_bytes32 is too big");
static_assert(sizeof(ivmc_address) == 20, "ivmc_address is too big");
static_assert(sizeof(ivmc_result) <= 64, "ivmc_result does not fit cache line");
static_assert(sizeof(ivmc_vm) <= 64, "ivmc_vm does not fit cache line");
static_assert(offsetof(ivmc_message, value) % sizeof(size_t) == 0,
              "ivmc_message.value not aligned");

// Check enums match int size.
// On GCC/clang the underlying type should be unsigned int, on MSVC int
static_assert(sizeof(ivmc_call_kind) == sizeof(int),
              "Enum `ivmc_call_kind` is not the size of int");
static_assert(sizeof(ivmc_revision) == sizeof(int), "Enum `ivmc_revision` is not the size of int");

static constexpr size_t optionalDataSize =
    sizeof(ivmc_result) - offsetof(ivmc_result, create_address);
static_assert(optionalDataSize >= sizeof(ivmc_result_optional_storage),
              "ivmc_result's optional data space is too small");

TEST(helpers, release_result)
{
    auto r1 = ivmc_result{};
    ivmc_release_result(&r1);

    static ivmc_result r2;
    static bool e;

    e = false;
    r2 = ivmc_result{};
    r2.release = [](const ivmc_result* r) { e = r == &r2; };
    EXPECT_FALSE(e);
    ivmc_release_result(&r2);
    EXPECT_TRUE(e);
}
