// IVMC: Ethereum Client-VM Connector API.
// Copyright 2018-2020 The IVMC Authors.
// Licensed under the Apache License, Version 2.0.

package ivmc

/*
#cgo CFLAGS: -I${SRCDIR}/../../../include -Wall -Wextra
#cgo !windows LDFLAGS: -ldl

#include <ivmc/ivmc.h>
#include <ivmc/helpers.h>
#include <ivmc/loader.h>

#include <stdlib.h>
#include <string.h>

static inline enum ivmc_set_option_result set_option(struct ivmc_vm* vm, char* name, char* value)
{
	enum ivmc_set_option_result ret = ivmc_set_option(vm, name, value);
	free(name);
	free(value);
	return ret;
}

extern const struct ivmc_host_interface ivmc_go_host;

static struct ivmc_result execute_wrapper(struct ivmc_vm* vm,
	uintptr_t context_index, enum ivmc_revision rev,
	enum ivmc_call_kind kind, uint32_t flags, int32_t depth, int64_t gas,
	const ivmc_address* recipient, const ivmc_address* sender,
	const uint8_t* input_data, size_t input_size, const ivmc_uint256be* value,
	const uint8_t* code, size_t code_size)
{
	struct ivmc_message msg = {
		kind,
		flags,
		depth,
		gas,
		*recipient,
		*sender,
		input_data,
		input_size,
		*value,
		{{0}}, // create2_salt: not required for execution
		{{0}}, // code_address: not required for execution
	};

	struct ivmc_host_context* context = (struct ivmc_host_context*)context_index;
	return ivmc_execute(vm, &ivmc_go_host, context, rev, &msg, code, code_size);
}
*/
import "C"

import (
	"fmt"
	"sync"
	"unsafe"
)

// Hash represents the 32 bytes of arbitrary data (e.g. the result of Keccak256
// hash). It occasionally is used to represent 256-bit unsigned integer values
// stored in big-endian byte order.
type Hash [32]byte

// Address represents the 160-bit (20 bytes) address of an Ethereum account.
type Address [20]byte

// Static asserts.
const (
	// The size of ivmc_bytes32 equals the size of Hash.
	_ = uint(len(Hash{}) - C.sizeof_ivmc_bytes32)
	_ = uint(C.sizeof_ivmc_bytes32 - len(Hash{}))

	// The size of ivmc_address equals the size of Address.
	_ = uint(len(Address{}) - C.sizeof_ivmc_address)
	_ = uint(C.sizeof_ivmc_address - len(Address{}))
)

type Error int32

func (err Error) IsInternalError() bool {
	return err < 0
}

func (err Error) Error() string {
	return C.GoString(C.ivmc_status_code_to_string(C.enum_ivmc_status_code(err)))
}

const (
	Failure = Error(C.IVMC_FAILURE)
	Revert  = Error(C.IVMC_REVERT)
)

type Revision int32

const (
	Frontier             Revision = C.IVMC_FRONTIER
	Homestead            Revision = C.IVMC_HOMESTEAD
	TangerineWhistle     Revision = C.IVMC_TANGERINE_WHISTLE
	SpuriousDragon       Revision = C.IVMC_SPURIOUS_DRAGON
	Byzantium            Revision = C.IVMC_BYZANTIUM
	Constantinople       Revision = C.IVMC_CONSTANTINOPLE
	Petersburg           Revision = C.IVMC_PETERSBURG
	Istanbul             Revision = C.IVMC_ISTANBUL
	Berlin               Revision = C.IVMC_BERLIN
	London               Revision = C.IVMC_LONDON
	Shanghai             Revision = C.IVMC_SHANGHAI
	MaxRevision          Revision = C.IVMC_MAX_REVISION
	LatestStableRevision Revision = C.IVMC_LATEST_STABLE_REVISION
)

type VM struct {
	handle *C.struct_ivmc_vm
}

func Load(filename string) (vm *VM, err error) {
	cfilename := C.CString(filename)
	var loaderErr C.enum_ivmc_loader_error_code
	handle := C.ivmc_load_and_create(cfilename, &loaderErr)
	C.free(unsafe.Pointer(cfilename))

	if loaderErr == C.IVMC_LOADER_SUCCESS {
		vm = &VM{handle}
	} else {
		errMsg := C.ivmc_last_error_msg()
		if errMsg != nil {
			err = fmt.Errorf("IVMC loading error: %s", C.GoString(errMsg))
		} else {
			err = fmt.Errorf("IVMC loading error %d", int(loaderErr))
		}
	}

	return vm, err
}

func LoadAndConfigure(config string) (vm *VM, err error) {
	cconfig := C.CString(config)
	var loaderErr C.enum_ivmc_loader_error_code
	handle := C.ivmc_load_and_configure(cconfig, &loaderErr)
	C.free(unsafe.Pointer(cconfig))

	if loaderErr == C.IVMC_LOADER_SUCCESS {
		vm = &VM{handle}
	} else {
		errMsg := C.ivmc_last_error_msg()
		if errMsg != nil {
			err = fmt.Errorf("IVMC loading error: %s", C.GoString(errMsg))
		} else {
			err = fmt.Errorf("IVMC loading error %d", int(loaderErr))
		}
	}

	return vm, err
}

func (vm *VM) Destroy() {
	C.ivmc_destroy(vm.handle)
}

func (vm *VM) Name() string {
	// TODO: consider using C.ivmc_vm_name(vm.handle)
	return C.GoString(vm.handle.name)
}

func (vm *VM) Version() string {
	// TODO: consider using C.ivmc_vm_version(vm.handle)
	return C.GoString(vm.handle.version)
}

type Capability uint32

const (
	CapabilityEVM1  Capability = C.IVMC_CAPABILITY_EVM1
	CapabilityEWASM Capability = C.IVMC_CAPABILITY_EWASM
)

func (vm *VM) HasCapability(capability Capability) bool {
	return bool(C.ivmc_vm_has_capability(vm.handle, uint32(capability)))
}

func (vm *VM) SetOption(name string, value string) (err error) {

	r := C.set_option(vm.handle, C.CString(name), C.CString(value))
	switch r {
	case C.IVMC_SET_OPTION_INVALID_NAME:
		err = fmt.Errorf("ivmc: option '%s' not accepted", name)
	case C.IVMC_SET_OPTION_INVALID_VALUE:
		err = fmt.Errorf("ivmc: option '%s' has invalid value", name)
	case C.IVMC_SET_OPTION_SUCCESS:
	}
	return err
}

func (vm *VM) Execute(ctx HostContext, rev Revision,
	kind CallKind, static bool, depth int, gas int64,
	recipient Address, sender Address, input []byte, value Hash,
	code []byte) (output []byte, gasLeft int64, err error) {

	flags := C.uint32_t(0)
	if static {
		flags |= C.IVMC_STATIC
	}

	ctxId := addHostContext(ctx)
	// FIXME: Clarify passing by pointer vs passing by value.
	ivmcRecipient := ivmcAddress(recipient)
	ivmcSender := ivmcAddress(sender)
	ivmcValue := ivmcBytes32(value)
	result := C.execute_wrapper(vm.handle, C.uintptr_t(ctxId), uint32(rev),
		C.enum_ivmc_call_kind(kind), flags, C.int32_t(depth), C.int64_t(gas),
		&ivmcRecipient, &ivmcSender, bytesPtr(input), C.size_t(len(input)), &ivmcValue,
		bytesPtr(code), C.size_t(len(code)))
	removeHostContext(ctxId)

	output = C.GoBytes(unsafe.Pointer(result.output_data), C.int(result.output_size))
	gasLeft = int64(result.gas_left)
	if result.status_code != C.IVMC_SUCCESS {
		err = Error(result.status_code)
	}

	if result.release != nil {
		C.ivmc_release_result(&result)
	}

	return output, gasLeft, err
}

var (
	hostContextCounter uintptr
	hostContextMap     = map[uintptr]HostContext{}
	hostContextMapMu   sync.Mutex
)

func addHostContext(ctx HostContext) uintptr {
	hostContextMapMu.Lock()
	id := hostContextCounter
	hostContextCounter++
	hostContextMap[id] = ctx
	hostContextMapMu.Unlock()
	return id
}

func removeHostContext(id uintptr) {
	hostContextMapMu.Lock()
	delete(hostContextMap, id)
	hostContextMapMu.Unlock()
}

func getHostContext(idx uintptr) HostContext {
	hostContextMapMu.Lock()
	ctx := hostContextMap[idx]
	hostContextMapMu.Unlock()
	return ctx
}

func ivmcBytes32(in Hash) C.ivmc_bytes32 {
	out := C.ivmc_bytes32{}
	for i := 0; i < len(in); i++ {
		out.bytes[i] = C.uint8_t(in[i])
	}
	return out
}

func ivmcAddress(address Address) C.ivmc_address {
	r := C.ivmc_address{}
	for i := 0; i < len(address); i++ {
		r.bytes[i] = C.uint8_t(address[i])
	}
	return r
}

func bytesPtr(bytes []byte) *C.uint8_t {
	if len(bytes) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&bytes[0]))
}
