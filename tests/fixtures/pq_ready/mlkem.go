package main

import (
	"crypto/mlkem"
	"fmt"
)

func main() {
	dk, _ := mlkem.GenerateKey768()
	fmt.Println(dk.EncapsulationKey().Bytes())
}
