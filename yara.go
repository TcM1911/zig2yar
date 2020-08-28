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
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/TcM1911/r2g2"
)

func run(c *r2g2.Client, opts *options) {
	zig, err := generateZig(c, opts)
	if err != nil {
		fmt.Printf("Operation failed: %s.\n", err)
		os.Exit(1)
	}

	yar := convertToYara(zig.Bytes, zig.Mask)

	if opts.reduce {
		yar = reduceSignature(yar, opts.scale)
	}

	fmt.Println(yar)
}

func convertToYara(bs, mask string) string {
	yarb := make([]byte, 0)
	for i, c := range mask {
		// 0x30 is 0 in ASCII.
		if c == '0' {
			yarb = append(yarb, byte('?'))
		} else {
			yarb = append(yarb, byte(bs[i]))
		}

		// Add space if needed.
		if (i+1)%2 == 0 {
			yarb = append(yarb, byte(' '))
		}
	}

	// Trim whildcard bytes at the end.
	yarb = bytes.TrimRight(yarb, "? ")

	return "{ " + strings.Trim(string(yarb), " ") + " }"
}

func generateZig(r2 *r2g2.Client, opts *options) (*r2g2.Zignature, error) {
	if !opts.inr2 {
		r2.AnalyzeAll()
		z, err := r2.ZignatureFunctionOffset(opts.offset)
		if err != nil {
			return nil, fmt.Errorf("failed to generate a zignature: %w", err)
		}
		return z, nil
	}

	f, err := r2.GetCurrentFunction()
	if err != nil {
		return nil, fmt.Errorf("failed to get current function: %w", err)
	}

	z, err := r2.ZignatureFunction(f.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to generate a zignature for symbol %s: %w", f.Name, err)
	}
	return z, nil
}

// reduceSignature shrinks the signature by replacing ?? for {#}.
// It will ignore single "?" and a single "??" since it does not
// reduce the number of characters in the signature.
// The scale factor can be used generate a more relaxed signature.
// For example 7 "??" with a scaling factor of 1.5 will be converted
// to "[7-10]".
func reduceSignature(signature string, scale float64) string {
	buf := make([]string, 0, len(signature))
	arr := strings.Split(signature, " ")
	for i := 0; i < len(arr); i++ {
		if arr[i] == "??" {
			var end int
			for j, a := range arr[i:] {
				if a != "??" {
					end = j - 1
					break
				}
			}
			if end != 0 {
				n := end + 1
				if scale != 0 {
					n = int(float64(n) * scale)
					buf = append(buf, fmt.Sprintf("[%d-%d]", end+1, n))
				} else {
					buf = append(buf, fmt.Sprintf("[%d]", n))
				}
				i += end
				continue
			}
		}
		buf = append(buf, arr[i])
	}

	return strings.Join(buf, " ")
}
