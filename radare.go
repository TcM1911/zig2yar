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
	"encoding/json"
	"os"
	"strings"

	"github.com/radare/r2pipe-go"
)

const (
	Seek                         = "s"
	SeekTo                       = Seek + Space
	DisassembleFunctionJSONAt    = "pdfj @ "
	Space                        = " "
	GenerateZignatureForFunction = "zaf "
	GetZignatures                = "zj"
	RemoveFunctionZignature      = "z-"
	Analyze                      = "aa"
)

type fcn struct {
	Name string `json:"name"`
	Size int    `json:"size"`
	Addr int    `json:"addr"`
	//Ops  []Op   `json:"ops"`
}

/*type Op struct {
	"offset": 4294971872,
        "esil": "rbp,8,rsp,-=,rsp,=[8]",
        "refptr": false,
        "fcn_addr": 4294971872,
        "fcn_last": 4294974003,
        "size": 1,
        "opcode": "push rbp",
        "disasm": "push rbp",
        "bytes": "55",
        "family": "cpu",
        "type": "upush",
        "type_num": 12,
        "type2_num": 0,
        "flags": ["entry0", "entry0", "sym.func.1000011e0", "rip"]
} */

/*
[{
        "name": "zig2yar-entry0",
        "bytes": "554889e54157415641554154534881ec280600004889f34189fe48............48............4585f67f..e8........48............31ffe8........bf01000000e8........85c074..c7..................48............e8........4885c074..80....74..4889c7e8........eb..48......bf01000000be........31c0e8........83f8ff74..0fb7....85c074..89..........c7..................eb..c6............48............e8........4885c074..4889c7e8........89..........e8........41..........85c075..c6............eb..c6............c7..................48............4489f74889dee8........8d....83....0f87........48............48......4801c1ffe1c6............31c089..........89..........eb..c7..................c7..................eb..48............48............ba01000000e8........eb..31c089..........89..........c7..................e9........c6............48............48............e8........84c00f84........e9........48............48............e8........84c00f84........b80100000089..........e9........c7..................e9........c6053f410000",
        "graph": {
            "cc": "36",
            "nbbs": "68",
            "edges": "102",
            "ebbs": "2"
        },
        "offset": 4294971872,
        "refs": ["sym.imp.setlocale", "sym.imp.isatty", "sym.imp.getenv",
                "sym.imp.getuid", "sym.imp.getopt", "sym.imp.getenv", "sym.func.100001b54", "sym.imp.getbsize", "sym.im
                p.signal ","
                sym.imp.signal ","
                sym.imp.getenv ","
                sym.func .100003 a4d ","
                sym.imp.isatty ","
                sym.imp.getenv ","
                sym.imp.tgetent ","
                sym.imp.tgetstr ","
                sym.imp.tgetstr ","
                sym.imp.tgetstr ","
                sym.imp.tgetstr ","
                sym.imp.tgetstr ","
                sym.imp.tgetstr ","
                sym.imp.getenv ","
                sym.func .1000043 f1 ","
                sym.imp.atoi ","
                sym.imp.getenv ","
                sym.imp.ioctl ","
                sym.imp.atoi ","
                sym.func .1000043 f1 "]}]
*/
type zignature struct {
	Name  string `json:"name"`
	Bytes string `json:"bytes"`
}

func cmdJSONHelper(r2 *r2pipe.Pipe, cmd string, output interface{}) error {
	outputStr, err := r2.Cmd(cmd)
	if err != nil {
		return err
	}
	return json.NewDecoder(strings.NewReader(outputStr)).Decode(&output)
}

func checkIfInRadare() bool {
	return (os.Getenv("R2PIPE_IN") != "") && (os.Getenv("R2PIPE_OUT") != "")
}
