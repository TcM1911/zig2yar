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
	"fmt"
	"strings"

	r2pipe "github.com/radare/r2pipe-go"
)

func convertToYara(bytes string) string {
	yarb := []byte{}
	for i, c := range bytes {
		if c == 0x2e {
			yarb = append(yarb, byte('?'))
		} else {
			yarb = append(yarb, byte(c))
		}
		if (i+1)%2 == 0 {
			yarb = append(yarb, byte(' '))
		}
	}
	return "{ " + strings.Trim(string(yarb), " ") + " }"
}

func generateYara(path, funcOffset string) (string, error) {
	r2, err := r2pipe.NewPipe(path)
	if err != nil {
		fmt.Println("Error when opening the pipe" + err.Error())
		return "", err
	}
	if path != "" {
		r2.Cmd(Analyze)
	}
	if funcOffset != "" {
		r2.Cmd(SeekTo + funcOffset)
	}
	offset, err := r2.Cmd(Seek)
	var function fcn
	err = cmdJSONHelper(r2, DisassembleFunctionJSONAt+offset, &function)
	if err != nil {
		fmt.Println("Error when disassembling the function:" + err.Error())
		return "", err
	}

	fname := function.Name
	zigname := "zig2yar-" + fname

	r2.Cmd(GenerateZignatureForFunction + fname + Space + zigname)
	var zs []zignature
	err = cmdJSONHelper(r2, GetZignatures, &zs)
	r2.Cmd(RemoveFunctionZignature + zigname)
	if err != nil {
		fmt.Println("Error when retriving zignatures:" + err.Error())
		return "", err
	}
	var bytes string
	for _, z := range zs {
		if z.Name == zigname {
			bytes = z.Bytes
			break
		}
	}
	return convertToYara(bytes), nil
}

// ReduceSignature shrinks the signature by replacing ?? for {#}.
// It will ignore single "?" and a single "??" since it does not
// reduce the number of characters in the signature.
// The scale factor can be used generate a more relaxed signature.
// For example 7 "??" with a scaling factor of 1.5 will be converted
// to "[7-10]".
func ReduceSignature(signature string, scale float32) string {
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
				if scale != float32(0) {
					n = int(float32(n) * scale)
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
