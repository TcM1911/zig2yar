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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReduceSignature(t *testing.T) {
	assert := assert.New(t)
	tests := []struct {
		name      string
		signature string
		expected  string
		scale     float64
	}{
		{"reduce", "{ 65 48 ?? ?? ?? ?? ?? ?? ?? 48 }", "{ 65 48 [7] 48 }", 0},
		{"reduce_twice", "{ 65 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? 76 }", "{ 65 48 [7] 48 [3] 76 }", 0},
		{"skip_one", "{ 65 48 ?? 48 }", "{ 65 48 ?? 48 }", 0},
		{"do_two", "{ 65 48 ?? ?? 48 }", "{ 65 48 [2] 48 }", 0},
		{"scale_int", "{ 65 48 ?? ?? ?? ?? ?? ?? ?? 48 }", "{ 65 48 [7-14] 48 }", float64(2)},
		{"scale_float", "{ 65 48 ?? ?? ?? ?? ?? ?? ?? 48 }", "{ 65 48 [7-10] 48 }", float64(1.5)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := reduceSignature(test.signature, test.scale)
			assert.Equal(test.expected, actual, test.name+" failed")
		})
	}
}
