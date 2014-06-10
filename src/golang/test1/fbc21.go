package main

import (
	"fmt"
)

type bit int8

func pick_bit(val uint64, n uint) bit {
	return bit((val >> n) & 1)
}

func xor_bits(value uint64, ntbl []uint) bit {
	var ret bit = 0
	for _, n := range ntbl {
		ret ^= pick_bit(value, n)
	}
	return ret
}

func fbc21_bit(value uint64) bit {
	FBC21_TABLE := []uint{2, 4, 7, 8, 9, 12, 13, 14, 17, 19, 20, 21}
	bit := xor_bits(value, FBC21_TABLE)
	return bit
}

func fbc24_bit(value uint64) bit {
	FBC24_TABLE := []uint{0, 5, 6, 7, 12, 21, 24}
	bit := xor_bits(value, FBC24_TABLE)
	return bit
}

func main1() {
	var value uint64 = 0x00079597c8302914
	var fbc21 uint32 = 0
	var fbc24 uint32 = 0
	var shift uint32 = 0
	for i := 0; i < 64/2-4; i++ {
		fbc21 |= uint32(fbc21_bit(value)) << shift
		fbc24 |= uint32(fbc24_bit(value)) << shift
		value = value >> 1
		shift += 1
	}
	var okfbc21 uint32 = 0x0079597
	var okfbc24 uint32 = 0x24be44c
	fmt.Printf("fbc21: %x, %64b\n", fbc21, fbc21)
	fmt.Printf("fbc24: %x, %64b\n", fbc24, fbc24)
	fmt.Printf("okfbc21: %x, %64b\n", okfbc21, okfbc21)
	fmt.Printf("okfbc24: %x, %64b\n", okfbc24, okfbc24)
}

type SemiState struct {
	value uint64
	fbc21 uint32
	fbc24 uint32
}

func update_fbc21_fbc24(semi *SemiState, shiftcnt uint, delta uint) {
	value := (semi.value >> shiftcnt)
	semi.fbc21 = (semi.fbc21 << 1) | uint32(fbc21_bit(value>>delta))
	semi.fbc24 = (semi.fbc24 << 1) | uint32(fbc24_bit(value))
}

func main() {
	var value uint64 = 0xffd2f
	var extcnt uint = 5
	semi := &SemiState{value, 0, 0}
	for i := 0; i < 1; i++ {
		update_fbc21_fbc24(semi, extcnt-5, 0)
	}
	fmt.Printf("value: %x, %064b\n", semi.value, semi.value)
	fmt.Printf("fbc21: %x, %032b\n", semi.fbc21, semi.fbc21)
	fmt.Printf("fbc24: %x, %032b\n", semi.fbc24, semi.fbc24)
}
