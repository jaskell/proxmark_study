package main

import (
	//"container/heap"
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

func forward_feedback(state uint64) bit {
	FORWARD_NTBL := []uint{0, 5, 9, 10, 12, 14, 15, 17, 19, 24, 25, 27, 29, 35, 39, 41, 42, 43}
	return xor_bits(state, FORWARD_NTBL)
}

func recover_feedback(state uint64) bit {
	BACKWARD_NTBL := []uint{48, 5, 9, 10, 12, 14, 15, 17, 19, 24, 25, 27, 29, 35, 39, 41, 42, 43}
	return xor_bits(state, BACKWARD_NTBL)
}

func f4a(y0, y1, y2, y3 bit) bit {
	return ((y0 | y1) ^ (y0 & y3)) ^ (y2 & ((y0 ^ y1) | y3))
}

func f4b(y0, y1, y2, y3 bit) bit {
	return ((y0 & y1) | y2) ^ ((y0 ^ y1) & (y2 | y3))
}

func f5c(y0, y1, y2, y3, y4 bit) bit {
	return (y0 | ((y1 | y4) & (y3 ^ y4))) ^ ((y0 ^ (y1 & y3)) & ((y2 ^ y3) | (y1 & y4)))
}

func i4bit(x uint64, a, b, c, d uint) uint {
	ret := ((x >> a) & 1) << 0
	ret |= ((x >> b) & 1) << 1
	ret |= ((x >> c) & 1) << 2
	ret |= ((x >> d) & 1) << 3
	return uint(ret)
}

func sf20(s uint64) bit {
	var f2_f4b uint = 0x9E98
	var f2_f4a uint = 0xB48E
	var f2_f5c uint = 0xEC57E80A
	var i5 uint
	i5 = ((f2_f4a >> i4bit(s, 0, 1, 2, 3)) & 1) << 0
	i5 |= ((f2_f4b >> i4bit(s, 4, 5, 6, 7)) & 1) << 1
	i5 |= ((f2_f4b >> i4bit(s, 8, 9, 10, 11)) & 1) << 2
	i5 |= ((f2_f4a >> i4bit(s, 12, 13, 14, 15)) & 1) << 3
	i5 |= ((f2_f4b >> i4bit(s, 16, 17, 18, 19)) & 1) << 4
	return bit((f2_f5c >> i5) & 1)
}

func filter_ksbit(s uint64) bit {
	var f2_f4b uint = 0x9E98
	var f2_f4a uint = 0xB48E
	var f2_f5c uint = 0xEC57E80A
	var i5 uint
	i5 = ((f2_f4a >> i4bit(s, 9, 11, 13, 15)) & 1) << 0
	i5 |= ((f2_f4b >> i4bit(s, 17, 19, 21, 23)) & 1) << 1
	i5 |= ((f2_f4b >> i4bit(s, 25, 27, 29, 31)) & 1) << 2
	i5 |= ((f2_f4a >> i4bit(s, 33, 35, 37, 39)) & 1) << 3
	i5 |= ((f2_f4b >> i4bit(s, 41, 43, 45, 47)) & 1) << 4
	return bit((f2_f5c >> i5) & 1)
}

func filter_ksbit_(s uint64) bit {
	b := f5c(f4a(pick_bit(s, 9), pick_bit(s, 11), pick_bit(s, 13), pick_bit(s, 15)),
		f4b(pick_bit(s, 17), pick_bit(s, 19), pick_bit(s, 21), pick_bit(s, 23)),
		f4b(pick_bit(s, 25), pick_bit(s, 27), pick_bit(s, 29), pick_bit(s, 31)),
		f4a(pick_bit(s, 33), pick_bit(s, 35), pick_bit(s, 37), pick_bit(s, 39)),
		f4b(pick_bit(s, 41), pick_bit(s, 43), pick_bit(s, 45), pick_bit(s, 47)))
	return b
}

func lfsr_rollforward_bit(state uint64, inbit bit) uint64 {
	return (state >> 1) | (uint64(forward_feedback(state)^inbit) << 47)
}

func lfsr_rollforward_multi_bit(state uint64, inputval uint64, rollcount int, isfeedback bool) (uint64, uint64) {
	var keystream uint64 = 0
	for i := 0; i < rollcount; i++ {
		keybit := filter_ksbit(state)
		keystream = (keystream >> 1) | (uint64(keybit) << uint(rollcount-1))
		inputbit := pick_bit(inputval, uint(i))
		inbit := inputbit
		if isfeedback {
			inbit ^= keybit
		}
		state = lfsr_rollforward_bit(state, inbit)
	}
	return state, keystream
}

func lfsr_rollback_bit(state uint64, inbit bit, isfeedback bool) uint64 {
	state = state << 1
	var keybit bit = 0
	if isfeedback {
		keybit = filter_ksbit(state)
	}
	state = (state | uint64((recover_feedback(state)^inbit^keybit)&1)) & 0x0000FFFFFFFFFFFF
	return state
}

func lfsr_rollback_multi_bit(state uint64, inputval uint64, rollcount int, isfeedback bool) uint64 {
	for i := 0; i < rollcount; i++ {
		inputbit := pick_bit(inputval, uint(rollcount-i-1))
		state = lfsr_rollback_bit(state, inputbit, isfeedback)
	}
	return state
}

func get_nonce_successor(nonce uint32, n int) uint32 {
	NONCE_TABLE := []uint{16, 18, 19, 21}
	for i := 0; i < n*32; i++ {
		fb := xor_bits(uint64(nonce), NONCE_TABLE)
		nonce = (nonce >> 1) | (uint32(fb) << 31)
	}
	return nonce
}

func lfsr_unassemble(value uint64) (int32, int32) {
	var s int32 = 0
	var t int32 = 0
	var i uint = 0
	for i = 0; i < 24; i++ {
		s |= int32(pick_bit(value, i*2+0)) << i
		t |= int32(pick_bit(value, i*2+1)) << i
	}
	return s, t
}

func lfsr_assemble(s int32, t int32) uint64 {
	var value uint64 = 0
	var i uint = 0
	for i = 0; i < 24; i++ {
		value |= uint64(pick_bit(uint64(s), i)) << (i * 2)
		value |= uint64(pick_bit(uint64(t), i)) << (i*2 + 1)
	}
	return value
}

type SemiState struct {
	value uint64
	fbc21 int
	fbc24 int
}

type SemiStateTable []*SemiState
type SemiStateHeap []*SemiState

func (ssh SemiStateHeap) Len() int { return len(ssh) }

func (ssh SemiStateHeap) Less(i, j int) bool {
	// We want Pop to give us the highest, not lowest, priority so we use greater than here.
	return ssh[i].fbc21 > ssh[j].fbc21
}

func (ssh SemiStateHeap) Swap(i, j int) {
	ssh[i], ssh[j] = ssh[j], ssh[i]
}

func (ssh *SemiStateHeap) Push(x interface{}) {
	// Push and Pop use pointer receivers because they modify the slice's length,
	// not just its contents.
	// To simplify indexing expressions in these methods, we save a copy of the
	// slice object. We could instead write (*pq)[i].
	a := *ssh
	n := len(a)
	a = a[0 : n+1]
	item := x.(*SemiState)
	a[n] = item
	*ssh = a
}

func (ssh *SemiStateHeap) Pop() interface{} {
	a := *ssh
	n := len(a)
	item := a[n-1]
	*ssh = a[0 : n-1]
	return item
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

func update_fbc21_fbc24(table SemiStateTable, i int, shiftcnt uint) {
	semi := table[i]
	value := (semi.value >> shiftcnt)
	semi.fbc21 = (semi.fbc21 << 1) | int(fbc21_bit(value))
	semi.fbc24 = (semi.fbc24 << 1) | int(fbc24_bit(value))
}

func init_table(table SemiStateTable, b0 bit) SemiStateTable {
	const VAL2POWER20 uint64 = 2 << 19
	var i uint64 = 0
	for i = 0; i < VAL2POWER20; i++ {
		if sf20(i) == b0 {
			semi := &SemiState{i, 0, 0}
			table = append(table, semi)
		}
	}
	return table
}

func insert_table_item(table SemiStateTable, i int, item *SemiState) SemiStateTable {
	table = append(table, nil)
	copy(table[i+1:], table[i:])
	table[i] = item
	return table
}

func extend_table(table SemiStateTable, b bit, extcnt uint) SemiStateTable {
	//i := len(table) - 1 //?
	//for i >= 0 {
	i := 0
	for i < len(table) {
		cur := table[i]
		value := cur.value
		newval1 := (value >> extcnt) | (1 << 19)
		newval2 := (value >> extcnt) | (0 << 19)
		extval1 := value | (1 << (19 + extcnt))
		extval2 := value | (0 << (19 + extcnt))
		flag := 0
		if sf20(newval1) == b {
			flag |= 1
		}
		if sf20(newval2) == b {
			flag |= 2
		}
		//fmt.Printf("i:%d, ", i)
		if flag == 0 {
			table = append(table[:i], table[i+1:]...) //delete_table_item(table, i)
		} else if flag == 1 {
			cur.value = extval1
			if extcnt > 4 {
				update_fbc21_fbc24(table, i, extcnt-4)
			}
			i += 1
			//i --
		} else if flag == 2 {
			cur.value = extval2
			if extcnt > 4 {
				update_fbc21_fbc24(table, i, extcnt-4)
			}
			i += 1
			//i --
		} else if flag == 3 {
			cur.value = extval1
			semi := &SemiState{extval2, cur.fbc21, cur.fbc24}
			table = insert_table_item(table, i, semi)
			if extcnt > 4 {
				update_fbc21_fbc24(table, i+0, extcnt-4)
				update_fbc21_fbc24(table, i+1, extcnt-4)
			}
			i += 2
			//i -= 2
		}
	}
	return table
}

func init_heap(tbl SemiStateTable) SemiStateHeap {
	sheap := make(SemiStateHeap, len(tbl))
	for item := range tbl {
		sheap.Push(item)
	}
	return sheap
}

func get_table_result_fbc(evntbl SemiStateTable, oddtbl SemiStateTable, rewindbitcount int) []uint64 {
	evnheap := init_heap(evntbl)
	oddheap := init_heap(oddtbl)
	result := make([]uint64, 1000)
	evn := evnheap.Pop().(*SemiState)
	odd := oddheap.Pop().(*SemiState)
	for (evn != nil) && (odd != nil) {
		if evn.fbc21 > odd.fbc24 {
			odd = oddheap.Pop().(*SemiState)
		} else if evn.fbc21 < odd.fbc24 {
			evn = evnheap.Pop().(*SemiState)
		} else if evn.fbc24 > odd.fbc21 {
			odd = oddheap.Pop().(*SemiState)
		} else if evn.fbc21 < odd.fbc24 {
			evn = evnheap.Pop().(*SemiState)
		} else {
			value := lfsr_assemble(int32(evn.value), int32(odd.value))
			state := lfsr_rollback_multi_bit(value, 0, 9+rewindbitcount, false)
			result = append(result, state)
		}
	}
	return result
}

func recover_lfsr_state(keystream uint64, length int, rewindbitcount int) []uint64 {
	const VAL2POWER20 int = 2 << 19
	fmt.Print("=== Decrypto1 ===\r\n")
	fmt.Print("Init Tables....\n")
	evntbl := make(SemiStateTable, 0)
	oddtbl := make(SemiStateTable, 0)
	evntbl = init_table(evntbl, pick_bit(keystream, 0))
	oddtbl = init_table(oddtbl, pick_bit(keystream, 1))
	fmt.Printf("Done init_table(even table: %d, odd table: %d)\n", len(evntbl), len(oddtbl))
	fmt.Print("Extending Tables...\n")
	var extcnt uint = 1
	for i := 2; i < length; i += 2 {
		evntbl = extend_table(evntbl, pick_bit(keystream, uint(i+0)), extcnt)
		oddtbl = extend_table(oddtbl, pick_bit(keystream, uint(i+1)), extcnt)
		fmt.Printf("i: %d, extend_table(even table: %d, odd table: %d)\n", i, len(evntbl), len(oddtbl))
		extcnt += 1
	}
	fmt.Printf("Done (even table: %d, odd table: %d)\n", cap(evntbl), cap(oddtbl))
	fmt.Print("Getting Results...\n")
	result := get_table_result_fbc(evntbl, oddtbl, rewindbitcount)
	fmt.Print("Done (%d results)\n", cap(result))
	return result
}

func main() {
	var keystream uint64 = 0xDE32C3A5F4C842FC
	result := recover_lfsr_state(keystream, 64, 0)
	if result == nil {
		return
	}
	for item := range result {
		fmt.Printf("%08x", item)
	}
	fmt.Print("game over!")
}
