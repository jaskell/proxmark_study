package main

import (
	"container/heap"
	"container/list"
	"fmt"
	"math/rand"
)

type SemiState struct {
	value uint64
	fbc21 uint32
	fbc24 uint32
}

type SemiStateTable struct{ list.List }
type EvnStateHeap []*SemiState

func (ssh *EvnStateHeap) Len() int { return len(*ssh) }

func (ssh *EvnStateHeap) Less(i, j int) bool {
	a := *ssh
	semi1 := a[i]
	semi2 := a[j]
	key1 := (semi1.fbc21 << 32) | semi1.fbc24
	key2 := (semi2.fbc21 << 32) | semi2.fbc24
	return key1 < key2
}

func (ssh *EvnStateHeap) Swap(i, j int) {
	a := *ssh
	a[i], a[j] = a[j], a[i]
}

func (ssh *EvnStateHeap) Push(x interface{}) {
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
	/***
	a := *ssh
	n := len(a)
	item := x.(*SemiState)
	a[n] = item
	/***/
}

func (ssh *EvnStateHeap) Pop() interface{} {
	a := *ssh
	n := len(a)
	item := a[n-1]
	*ssh = a[0 : n-1]
	return item
	/***
	a := *ssh
	n := len(a)
	item := a[n-1]
	a[n-1] = nil
	return item
	/****/
}

//type OddStateHeap struct{ EvnStateHeap }
type OddStateHeap []*SemiState

func (ssh *OddStateHeap) Len() int { return len(*ssh) }

func (ssh *OddStateHeap) Less(i, j int) bool {
	a := *ssh
	semi1 := a[i]
	semi2 := a[j]
	key1 := (semi1.fbc24 << 32) | semi1.fbc21
	key2 := (semi2.fbc24 << 32) | semi2.fbc21
	return key1 < key2
}

func (ssh *OddStateHeap) Swap(i, j int) {
	a := *ssh
	a[i], a[j] = a[j], a[i]
}

func (ssh *OddStateHeap) Push(x interface{}) {
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
	/***
	a := *ssh
	n := len(a)
	item := x.(*SemiState)
	a[n] = item
	/***/
}

func (ssh *OddStateHeap) Pop() interface{} {
	a := *ssh
	n := len(a)
	item := a[n-1]
	*ssh = a[0 : n-1]
	return item
	/***
	a := *ssh
	n := len(a)
	item := a[n-1]
	a[n-1] = nil
	return item
	/****/
}

func init_evnheap(tbl *SemiStateTable) *EvnStateHeap {
	sheap := make(EvnStateHeap, 0, tbl.Len())
	for elem := tbl.Front(); elem != nil; elem = elem.Next() {
		semi := elem.Value.(*SemiState)
		heap.Push(&sheap, semi)
	}
	return &sheap
}

func init_oddheap(tbl *SemiStateTable) *OddStateHeap {
	sheap := make(OddStateHeap, 0, tbl.Len())
	for elem := tbl.Front(); elem != nil; elem = elem.Next() {
		semi := elem.Value.(*SemiState)
		heap.Push(&sheap, semi)
	}
	return &sheap
}

func main1() {
	oddtbl := new(SemiStateTable)
	var i uint64
	for i = 0; i < 100; i++ {
		value := rand.Int63()
		semi := &SemiState{uint64(i), uint32(value), 0}
		fmt.Printf("push: value: %d, fbc21: %d, fbc24: %d\n", int(semi.value), semi.fbc21, semi.fbc24)
		oddtbl.PushBack(semi)
	}
	fmt.Print("---------------\n")
	oddheap := init_oddheap(oddtbl)
	for oddheap.Len() > 0 {
		cur := heap.Pop(oddheap)
		semi := cur.(*SemiState)
		value := semi.value
		fbc21 := semi.fbc21
		fbc24 := semi.fbc24
		fmt.Printf("pop: value: %d, fbc21: %d, fbc24: %d\n", int(value), fbc21, fbc24)
	}
	fmt.Print("game over!")
}

func main() {
	evntbl := new(SemiStateTable)
	var i uint64
	for i = 0; i < 100; i++ {
		value := rand.Int63()
		semi := &SemiState{uint64(i), uint32(value), 0}
		fmt.Printf("push: value: %d, fbc21: %d, fbc24: %d\n", int(semi.value), semi.fbc21, semi.fbc24)
		evntbl.PushBack(semi)
	}
	fmt.Print("---------------\n")
	semi := evntbl.Front().Value.(*SemiState)
	fmt.Printf("evntbl first value: %016x, fbc21: %08x, fbc24: %08x\n", semi.value, semi.fbc21, semi.fbc24)

	evnheap := init_evnheap(evntbl)
	for evnheap.Len() > 0 {
		cur := heap.Pop(evnheap)
		semi := cur.(*SemiState)
		value := semi.value
		fbc21 := semi.fbc21
		fbc24 := semi.fbc24
		fmt.Printf("pop: value: %d, fbc21: %d, fbc24: %d\n", int(value), fbc21, fbc24)
	}
	fmt.Print("game over!")
}
