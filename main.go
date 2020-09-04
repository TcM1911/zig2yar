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

	"github.com/TcM1911/r2g2"
)

const (
	buildVersion = "0.1.0-dev"
)

type options struct {
	offset      uint64
	reduce      bool
	scale       float64
	inr2        bool
	file        string
	funcSection bool
}

func main() {
	// Parsing flags
	fileOffset := flag.Uint64("o", 0, "Offset of the function.")
	displayVersion := flag.Bool("version", false, "Display version.")
	reduceSig := flag.Bool("r", false, "Reduce and use bounds instead of wildcards.")
	scale := flag.Float64("s", 0, "Set upper bound using scaling factor.")
	// Only generate signature from a section of the function.
	funcSection := false

	// Functionality only supported when executed within radare before parse.
	if r2g2.CheckForR2Pipe() {
		yank := flag.Bool("y", false, "Generate signature from yanked bytes.")
		flag.Parse()

		funcSection = *yank
	} else {
		flag.Parse()
	}

	if *displayVersion {
		fmt.Printf("Zig2Yar version %s\n", buildVersion)
		return
	}

	// Parsing arguments
	file := flag.Arg(0)

	// Need to provide a file or executed from with Radare2
	inR2 := r2g2.CheckForR2Pipe()
	if file == "" && !inR2 {
		fmt.Println("You need to provide a file as an argument or execute from with Radare2")
		os.Exit(1)
	}

	// Get a client.
	var c *r2g2.Client
	if inR2 {
		pipe, err := r2g2.OpenPipe()
		if err != nil {
			fmt.Printf("Failed to open pipe to radare: %s\n", err)
			os.Exit(1)
		}
		c = pipe
	} else {
		f, err := r2g2.New(file)
		if err != nil {
			fmt.Printf("Failed to open a handler to the file %s: %s\n", file, err)
			os.Exit(1)
		}
		c = f
	}

	// If we are given a file, we also need an offset.
	if file != "" && *fileOffset == 0 {
		fmt.Println("An offset is needed too.")
		os.Exit(1)
	}

	opts := &options{
		offset:      *fileOffset,
		reduce:      *reduceSig,
		scale:       *scale,
		inr2:        inR2,
		file:        file,
		funcSection: funcSection,
	}

	run(c, opts)
}
