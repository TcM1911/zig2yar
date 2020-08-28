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
	"os"
	"path/filepath"
	"testing"

	"github.com/TcM1911/r2g2"
	"github.com/stretchr/testify/assert"
)

const (
	expectedYara = "{ 65 48 8b 0c 25 a0 08 00 00 48 3b 61 10 76 ?? 48 83 ec 48 48 89 6c 24 40 48 8d 6c 24 40 0f 57 c0 0f 11 44 24 30 48 ?? ?? ?? ?? ?? ?? 48 89 44 24 30 48 ?? ?? ?? ?? ?? ?? 48 89 44 24 38 48 8d 44 24 30 48 89 04 24 48 c7 44 24 08 01 00 00 00 48 c7 44 24 10 01 00 00 00 e8 ?? ?? ?? ?? 48 8b 6c 24 40 48 83 c4 48 c3 e8 ?? ?? ?? ?? eb }"
)

func TestCreateYaraSignature(t *testing.T) {
	assert := assert.New(t)
	cwd, _ := os.Getwd()
	fullPath := filepath.Join(cwd, "test_resources", "hello.gold")
	c, err := r2g2.New(fullPath)
	assert.NoError(err)

	opts := &options{
		file:   fullPath,
		offset: 0x0108e760,
	}

	zig, err := generateZig(c, opts)
	assert.NoError(err, "Should not return an error")

	yara := convertToYara(zig.Bytes, zig.Mask)
	assert.Equal(expectedYara, yara, "Wrong signature")
}
