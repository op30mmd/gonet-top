package main

import (
	"fmt"
	"os"
)

// isAdmin checks for administrator privileges by attempting to open a handle
// to the physical drive, which is only accessible to administrators.
func isAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	return err == nil
}

func main() {
	// This is a minimal diagnostic test.
	// It checks for admin privileges and prints the result to standard output.
	// This will help determine the behavior of the isAdmin() function in the CI environment.
	isAdminResult := isAdmin()
	fmt.Printf("isAdmin: %v\n", isAdminResult)
}
