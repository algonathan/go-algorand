// Copyright (C) 2019-2022 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package libgoal

import (
	"github.com/algorand/go-algorand/crypto/cryptbase"
)

// Compile compiles the given program and returned the compiled program
func (c *Client) Compile(program []byte) (compiledProgram []byte, compiledProgramHash cryptbase.Digest, err error) {
	algod, err2 := c.ensureAlgodClient()
	if err2 != nil {
		return nil, cryptbase.Digest{}, err2
	}
	return algod.Compile(program)
}
