package main

import (
	"fmt"
	"time"
)

func main() {
	// This is the simplest possible diagnostic test.
	// It prints "Hello, World!" and waits, to confirm that a basic Go
	// executable can run and produce output in the CI environment.
	fmt.Println("Hello, World!")
	time.Sleep(5 * time.Second)
}
