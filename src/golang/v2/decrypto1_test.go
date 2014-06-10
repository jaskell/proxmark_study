package main

import (
	"fmt"
	"math/rand"
	"testing"
)

func Test_pick_bit(t *testing.T) {
	var val uint64 = 0x12345678
	if pick_bit(val, 0) != 0 {
		t.Error("pick_bit function 0 test failed!")
	}
	if pick_bit(val, 1) != 0 {
		t.Error("pick_bit function 1 test failed!")
	}
	if pick_bit(val, 2) != 0 {
		t.Error("pick_bit function 2 test failed!")
	}
	if pick_bit(val, 3) != 1 {
		t.Error("pick_bit function 3 test failed!")
	}
	if pick_bit(val, 0) != 0 {
		t.Error("pick_bit function 0 test failed!")
	}
}

func Test_xor_bits(t *testing.T) {
	var val uint64 = 0x07
	ntbl0 := []uint{1, 2, 3}
	ntbl1 := []uint{0, 1, 2}
	if xor_bits(val, ntbl0) != 0 {
		t.Error("xor_bits function 0 test failed!")
	}
	if xor_bits(val, ntbl1) != 1 {
		t.Error("xor_bits function 1 test failed!")
	}
}

func assert_forward_feedback(t *testing.T, value uint64, okret bit, err string) {
	if forward_feedback(value) != okret {
		t.Error(err)
	}
}

func Test_forward_feedback(t *testing.T) {
	assert_forward_feedback(t, 0xFFFFFFFFFFFF, 0, "forward_feedback 00 test failed!")
	assert_forward_feedback(t, 0x7FFFFFFFFFFF, 0, "forward_feedback 01 test failed!")
	assert_forward_feedback(t, 0xBFFFFFFFFFFF, 0, "forward_feedback 02 test failed!")
	assert_forward_feedback(t, 0xDFFFFFFFFFFF, 0, "forward_feedback 03 test failed!")
	assert_forward_feedback(t, 0xEFFFFFFFFFFF, 0, "forward_feedback 04 test failed!")
	assert_forward_feedback(t, 0xF7FFFFFFFFFF, 1, "forward_feedback 05 test failed!")
	assert_forward_feedback(t, 0xFBFFFFFFFFFF, 1, "forward_feedback 06 test failed!")
	assert_forward_feedback(t, 0xFDFFFFFFFFFF, 1, "forward_feedback 07 test failed!")
	assert_forward_feedback(t, 0xFEFFFFFFFFFF, 0, "forward_feedback 08 test failed!")
	assert_forward_feedback(t, 0xFF7FFFFFFFFF, 1, "forward_feedback 09 test failed!")
	assert_forward_feedback(t, 0xFFBFFFFFFFFF, 0, "forward_feedback 10 test failed!")
	assert_forward_feedback(t, 0xFFDFFFFFFFFF, 0, "forward_feedback 11 test failed!")
	assert_forward_feedback(t, 0xFFEFFFFFFFFF, 0, "forward_feedback 12 test failed!")
	assert_forward_feedback(t, 0xFFF7FFFFFFFF, 1, "forward_feedback 13 test failed!")
	assert_forward_feedback(t, 0x7FFBFFFFFFFF, 0, "forward_feedback 14 test failed!")
	assert_forward_feedback(t, 0xBFFDFFFFFFFF, 0, "forward_feedback 15 test failed!")
	assert_forward_feedback(t, 0xDFFEFFFFFFFF, 0, "forward_feedback 16 test failed!")
	assert_forward_feedback(t, 0xEFFF7FFFFFFF, 0, "forward_feedback 17 test failed!")
	assert_forward_feedback(t, 0x77FFBFFFFFFF, 1, "forward_feedback 18 test failed!")
	assert_forward_feedback(t, 0x3BFFDFFFFFFF, 0, "forward_feedback 19 test failed!")
	assert_forward_feedback(t, 0x9DFFEFFFFFFF, 1, "forward_feedback 20 test failed!")
	assert_forward_feedback(t, 0xCEFFF7FFFFFF, 1, "forward_feedback 21 test failed!")
	assert_forward_feedback(t, 0xE77FFBFFFFFF, 0, "forward_feedback 22 test failed!")
	assert_forward_feedback(t, 0x73BFFDFFFFFF, 1, "forward_feedback 23 test failed!")
	assert_forward_feedback(t, 0x39DFFEFFFFFF, 1, "forward_feedback 24 test failed!")
	assert_forward_feedback(t, 0x9CEFFF7FFFFF, 1, "forward_feedback 25 test failed!")
	assert_forward_feedback(t, 0x4E77FFBFFFFF, 0, "forward_feedback 26 test failed!")
	assert_forward_feedback(t, 0xA73BFFDFFFFF, 0, "forward_feedback 27 test failed!")
	assert_forward_feedback(t, 0xD39DFFEFFFFF, 0, "forward_feedback 28 test failed!")
	assert_forward_feedback(t, 0xE9CEFFF7FFFF, 1, "forward_feedback 29 test failed!")
	assert_forward_feedback(t, 0xF4E77FFBFFFF, 1, "forward_feedback 30 test failed!")
	assert_forward_feedback(t, 0x7A73BFFDFFFF, 0, "forward_feedback 31 test failed!")
}

func Test_filter_ksbit(t *testing.T) {
	for i := 0; i < 100; i++ {
		value := uint64(rand.Int63())
		if filter_ksbit(value) != filter_ksbit_(value) {
			t.Error(fmt.Sprintf("filter_ksbit %d %llx test failed!", i, value))
		}
	}
}

func assert_rollforward_bit(t *testing.T, state uint64, inbit bit, result uint64, err string) {
	if lfsr_rollforward_bit(state, inbit) != result {
		t.Error(err)
	}
}

func Test_lfsr_rollforward_bit(t *testing.T) {
	assert_rollforward_bit(t, 0xFFFFFFFFFFFF, 0, 0x7FFFFFFFFFFF, "lfsr_rollforward_bit 00 test failed!")
	assert_rollforward_bit(t, 0x7FFFFFFFFFFF, 1, 0xBFFFFFFFFFFF, "lfsr_rollforward_bit 01 test failed!")
	assert_rollforward_bit(t, 0xBFFFFFFFFFFF, 1, 0xDFFFFFFFFFFF, "lfsr_rollforward_bit 02 test failed!")
	assert_rollforward_bit(t, 0xDFFFFFFFFFFF, 1, 0xEFFFFFFFFFFF, "lfsr_rollforward_bit 03 test failed!")
	assert_rollforward_bit(t, 0xEFFFFFFFFFFF, 1, 0xF7FFFFFFFFFF, "lfsr_rollforward_bit 04 test failed!")
	assert_rollforward_bit(t, 0xF7FFFFFFFFFF, 0, 0xFBFFFFFFFFFF, "lfsr_rollforward_bit 05 test failed!")
	assert_rollforward_bit(t, 0xFBFFFFFFFFFF, 0, 0xFDFFFFFFFFFF, "lfsr_rollforward_bit 06 test failed!")
	assert_rollforward_bit(t, 0xFDFFFFFFFFFF, 0, 0xFEFFFFFFFFFF, "lfsr_rollforward_bit 07 test failed!")
	assert_rollforward_bit(t, 0xFEFFFFFFFFFF, 1, 0xFF7FFFFFFFFF, "lfsr_rollforward_bit 08 test failed!")
	assert_rollforward_bit(t, 0xFF7FFFFFFFFF, 0, 0xFFBFFFFFFFFF, "lfsr_rollforward_bit 09 test failed!")
	assert_rollforward_bit(t, 0xFFBFFFFFFFFF, 1, 0xFFDFFFFFFFFF, "lfsr_rollforward_bit 10 test failed!")
	assert_rollforward_bit(t, 0xFFDFFFFFFFFF, 1, 0xFFEFFFFFFFFF, "lfsr_rollforward_bit 11 test failed!")
	assert_rollforward_bit(t, 0xFFEFFFFFFFFF, 1, 0xFFF7FFFFFFFF, "lfsr_rollforward_bit 12 test failed!")
	assert_rollforward_bit(t, 0xFFF7FFFFFFFF, 1, 0x7FFBFFFFFFFF, "lfsr_rollforward_bit 13 test failed!")
	assert_rollforward_bit(t, 0x7FFBFFFFFFFF, 1, 0xBFFDFFFFFFFF, "lfsr_rollforward_bit 14 test failed!")
	assert_rollforward_bit(t, 0xBFFDFFFFFFFF, 1, 0xDFFEFFFFFFFF, "lfsr_rollforward_bit 15 test failed!")
	assert_rollforward_bit(t, 0xDFFEFFFFFFFF, 1, 0xEFFF7FFFFFFF, "lfsr_rollforward_bit 16 test failed!")
	assert_rollforward_bit(t, 0xEFFF7FFFFFFF, 0, 0x77FFBFFFFFFF, "lfsr_rollforward_bit 17 test failed!")
	assert_rollforward_bit(t, 0x77FFBFFFFFFF, 1, 0x3BFFDFFFFFFF, "lfsr_rollforward_bit 18 test failed!")
	assert_rollforward_bit(t, 0x3BFFDFFFFFFF, 1, 0x9DFFEFFFFFFF, "lfsr_rollforward_bit 19 test failed!")
	assert_rollforward_bit(t, 0x9DFFEFFFFFFF, 0, 0xCEFFF7FFFFFF, "lfsr_rollforward_bit 20 test failed!")
	assert_rollforward_bit(t, 0xCEFFF7FFFFFF, 0, 0xE77FFBFFFFFF, "lfsr_rollforward_bit 21 test failed!")
	assert_rollforward_bit(t, 0xE77FFBFFFFFF, 0, 0x73BFFDFFFFFF, "lfsr_rollforward_bit 22 test failed!")
	assert_rollforward_bit(t, 0x73BFFDFFFFFF, 1, 0x39DFFEFFFFFF, "lfsr_rollforward_bit 23 test failed!")
	assert_rollforward_bit(t, 0x39DFFEFFFFFF, 0, 0x9CEFFF7FFFFF, "lfsr_rollforward_bit 24 test failed!")
	assert_rollforward_bit(t, 0x9CEFFF7FFFFF, 1, 0x4E77FFBFFFFF, "lfsr_rollforward_bit 25 test failed!")
	assert_rollforward_bit(t, 0x4E77FFBFFFFF, 1, 0xA73BFFDFFFFF, "lfsr_rollforward_bit 26 test failed!")
	assert_rollforward_bit(t, 0xA73BFFDFFFFF, 1, 0xD39DFFEFFFFF, "lfsr_rollforward_bit 27 test failed!")
	assert_rollforward_bit(t, 0xD39DFFEFFFFF, 1, 0xE9CEFFF7FFFF, "lfsr_rollforward_bit 28 test failed!")
	assert_rollforward_bit(t, 0xE9CEFFF7FFFF, 0, 0xF4E77FFBFFFF, "lfsr_rollforward_bit 29 test failed!")
	assert_rollforward_bit(t, 0xF4E77FFBFFFF, 1, 0x7A73BFFDFFFF, "lfsr_rollforward_bit 30 test failed!")
	assert_rollforward_bit(t, 0x7A73BFFDFFFF, 0, 0x3D39DFFEFFFF, "lfsr_rollforward_bit 31 test failed!")
}

func Test_lfsr_rollforward_multi_bit(t *testing.T) {
	var state uint64 = 0xFFFFFFFFFFFF
	state, _ = lfsr_rollforward_multi_bit(state, 0x5e8dfd1e, 32, false)
	if state != 0x3d39dffeffff {
		t.Error("lfsr_rollforward_multi_bit test failed!")
	}
}

func Test_lfsr_rollback_multi_bit(t *testing.T) {
	var state uint64 = 0x51e2fac83d39
	var val32 uint64 = 0xce58e4a1
	state = lfsr_rollback_multi_bit(state, val32, 32, true)
	if state != 0x3d39dffeffff {
		t.Error("lfsr_rollback_multi_bit test failed!")
	}
}

func Test_get_next_nonce(t *testing.T) {
	var nonce uint32 = 0x6c16a482
	nextnonce := get_nonce_successor(nonce, 2)
	if nextnonce != 0x4b73658d {
		t.Error("get_nonce_successor test failed!")
	}
}

func Test_lfsr_assemble(t *testing.T) {
	ret := lfsr_assemble(0x1111, 0x0000)
	if ret != 0x01010101 {
		t.Error("lfsr_assemble test failed!")
	}
	ret = lfsr_assemble(0xFFFF, 0x0000)
	if ret != 0x55555555 {
		t.Error("lfsr_assemble test failed!")
	}
}

func Test_lfsr_unassemble(t *testing.T) {
	even, odd := lfsr_unassemble(0x01010101)
	if even != 0x1111 {
		t.Error("lfsr_unassemble test failed!")
	}
	if odd != 0x0000 {
		t.Error("lfsr_unassemble test failed!")
	}
	even, odd = lfsr_unassemble(0x55555555)
	if even != 0xFFFF {
		t.Error("lfsr_unassemble test failed!")
	}
	if odd != 0x0000 {
		t.Error("lfsr_unassemble test failed!")
	}
}
