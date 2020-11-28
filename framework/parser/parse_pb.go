// parse_pb.go
package main

import "C"

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"sync"
)

var count int
var mtx sync.Mutex

//export Add
func Add(a, b int) int {
	return a + b
}

//export Cosine
func Cosine(x float64) float64 {
	return math.Cos(x)
}

//export Sort
func Sort(vals []int) {
	sort.Ints(vals)
}

//export Logs
func Logs(msg string) int {
	mtx.Lock()
	defer mtx.Unlock()

	user := &UserInfo{
		Message: "hello",
		Length:  100,
		Cnt:     50,
	}
	if data, err := json.Marshal(user); err == nil {
		fmt.Println(string(data))
	} else {
		fmt.Println("err:", err)
	}
	fmt.Println(msg)
	count++
	return count
}

func main() {
}
