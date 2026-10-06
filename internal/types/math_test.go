package types

import (
	"math"
	"testing"
)

func TestAddUint64Overflow(t *testing.T) {
	sum, overflow := AddUint64(1, 2)
	if overflow || sum != 3 {
		t.Fatalf("got (%d, %v), want (3, false)", sum, overflow)
	}
	_, overflow = AddUint64(math.MaxUint64, 1)
	if !overflow {
		t.Fatal("expected overflow adding 1 to max uint64")
	}
}

func TestSubUint64Underflow(t *testing.T) {
	diff, underflow := SubUint64(10, 3)
	if underflow || diff != 7 {
		t.Fatalf("got (%d, %v), want (7, false)", diff, underflow)
	}
	_, underflow = SubUint64(3, 10)
	if !underflow {
		t.Fatal("expected underflow subtracting a larger value")
	}
}
