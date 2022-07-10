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

package agreement

import (
	"github.com/algorand/go-algorand/crypto/cryptbase"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/protocol"
)

var poolAddr = basics.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

func BenchmarkVoteDecoding(b *testing.B) {
	oneTimeSecrets := crypto.GenerateOneTimeSignatureSecrets(300, 1000)
	id := crypto.OneTimeSignatureIdentifier{
		Batch: 1000,

		// Avoid generating the last few offsets (in a batch size of 256), so we can increment correctly
		Offset: cryptbase.RandUint64() % 250,
	}
	proposal := unauthenticatedProposal{
		OriginalPeriod: period(cryptbase.RandUint64() % 250),
	}

	var vrfProof crypto.VRFProof
	cryptbase.SystemRNG.RandBytes(vrfProof[:])

	var sendAddr basics.Address
	cryptbase.SystemRNG.RandBytes(sendAddr[:])

	uv := unauthenticatedVote{
		R: rawVote{
			Sender: sendAddr,
			Round:  basics.Round(356),
			Period: period(4),
			Step:   step(3),
			Proposal: proposalValue{
				OriginalPeriod:   period(3),
				OriginalProposer: poolAddr,
				BlockDigest:      cryptbase.Hash([]byte{1, 2, 3}),
				EncodingDigest:   cryptbase.Hash([]byte{5, 6, 7}),
			},
		},
		Cred: committee.UnauthenticatedCredential{
			Proof: vrfProof,
		},
		Sig: oneTimeSecrets.Sign(id, proposal),
	}

	msgBytes := protocol.Encode(&uv)

	// make sure we know how to decode this correctly.
	iVote, err := decodeVote(msgBytes)
	require.Nil(b, err)
	decodedVote := iVote.(unauthenticatedVote)
	require.Equal(b, uv.R.Period, decodedVote.R.Period)

	// and now, let's measure the performance.
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decodeVote(msgBytes)
	}
}
