package ivmc_use

import (
	"github.com/ethereum/ivmc/v10/bindings/go/ivmc"
	"testing"
)

var exampleVmPath = "./example-vm.so"

func TestGetVmName(t *testing.T) {
	vm, err := ivmc.Load(exampleVmPath)
	if err != nil {
		t.Fatalf("%v", err)
	}

	expectedName := "example_vm"
	if name := vm.Name(); name != expectedName {
		t.Errorf("wrong VM name: %s, expected %s", name, expectedName)
	}
}
