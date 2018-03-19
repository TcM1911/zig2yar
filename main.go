/*
Copyright 2018 Joakim Kennedy

This file is part of Zig2Yar.

Zig2Yar is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Zig2Yar is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Zig2Yar.  If not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

const (
	buildVersion = "0.1.0-dev"
)

func main() {
	// Parsing flags
	fileOffset := flag.String("o", "", "offset of the function.")
	displayVersion := flag.Bool("version", false, "display version")
	flag.Parse()

	if *displayVersion {
		fmt.Printf("Zig2Yar version %s\n", buildVersion)
		return
	}

	// Parsing arguments
	file := flag.Arg(0)

	// Need to provide a file or executed from with Radare2
	inR2 := checkIfInRadare()
	if file == "" && !inR2 {
		fmt.Println("You need to provide a file as an argument or execute from with Radare2")
		os.Exit(1)
	}
	if inR2 {
		// Ensure locations is taken from the pipe.
		file = ""
		*fileOffset = ""
	}

	// If we are given a file, we also need an offset.
	if file != "" && *fileOffset == "" {
		fmt.Println("An offset is needed too.")
		os.Exit(1)
	}

	yara, err := generateYara(getFilePath(file), *fileOffset)
	fmt.Println(yara)
	if err != nil {
		os.Exit(1)
	}
}

func getFilePath(file string) string {
	if file == "" {
		return ""
	}
	if file[0] == '/' {
		return file
	}
	// Get full path.
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("Error when getting current directory: %s\n", err.Error())
		os.Exit(1)
	}
	return filepath.Join(cwd, file)
}
