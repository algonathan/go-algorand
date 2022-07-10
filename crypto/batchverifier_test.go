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

package crypto

import (
	"github.com/algorand/go-algorand/crypto/cryptbase"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestBatchVerifierSingle(t *testing.T) {
	partitiontest.PartitionTest(t)
	// test expected success
	bv := MakeBatchVerifier()
	msg := randString()
	var s Seed
	cryptbase.RandBytes(s[:])
	sigSecrets := GenerateSignatureSecrets(s)
	sig := sigSecrets.Sign(msg)
	bv.EnqueueSignature(sigSecrets.SignatureVerifier, msg, sig)
	require.NoError(t, bv.Verify())

	// test expected failure
	bv = MakeBatchVerifier()
	msg = randString()
	cryptbase.RandBytes(s[:])
	sigSecrets = GenerateSignatureSecrets(s)
	sig = sigSecrets.Sign(msg)
	// break the signature:
	sig[0] = sig[0] + 1
	bv.EnqueueSignature(sigSecrets.SignatureVerifier, msg, sig)
	require.Error(t, bv.Verify())
}

func TestBatchVerifierBulk(t *testing.T) {
	partitiontest.PartitionTest(t)
	for i := 1; i < 64*2+3; i++ {
		n := i
		bv := MakeBatchVerifierWithHint(n)
		var s Seed

		for i := 0; i < n; i++ {
			msg := randString()
			cryptbase.RandBytes(s[:])
			sigSecrets := GenerateSignatureSecrets(s)
			sig := sigSecrets.Sign(msg)
			bv.EnqueueSignature(sigSecrets.SignatureVerifier, msg, sig)
		}
		require.Equal(t, n, bv.GetNumberOfEnqueuedSignatures())
		require.NoError(t, bv.Verify())
	}

}

func TestBatchVerifierBulkWithExpand(t *testing.T) {
	partitiontest.PartitionTest(t)
	n := 64
	bv := MakeBatchVerifier()
	var s Seed
	cryptbase.RandBytes(s[:])

	for i := 0; i < n; i++ {
		msg := randString()
		sigSecrets := GenerateSignatureSecrets(s)
		sig := sigSecrets.Sign(msg)
		bv.EnqueueSignature(sigSecrets.SignatureVerifier, msg, sig)
	}
	require.NoError(t, bv.Verify())
}

func TestBatchVerifierWithInvalidSiganture(t *testing.T) {
	partitiontest.PartitionTest(t)
	n := 64
	bv := MakeBatchVerifier()
	var s Seed
	cryptbase.RandBytes(s[:])

	for i := 0; i < n-1; i++ {
		msg := randString()
		sigSecrets := GenerateSignatureSecrets(s)
		sig := sigSecrets.Sign(msg)
		bv.EnqueueSignature(sigSecrets.SignatureVerifier, msg, sig)
	}

	msg := randString()
	sigSecrets := GenerateSignatureSecrets(s)
	sig := sigSecrets.Sign(msg)
	sig[0] = sig[0] + 1
	bv.EnqueueSignature(sigSecrets.SignatureVerifier, msg, sig)

	require.Error(t, bv.Verify())
}

func BenchmarkBatchVerifier(b *testing.B) {
	c := makeCurve25519Secret()
	bv := MakeBatchVerifierWithHint(1)
	for i := 0; i < b.N; i++ {
		str := randString()
		bv.EnqueueSignature(c.SignatureVerifier, str, c.Sign(str))
	}

	b.ResetTimer()
	require.NoError(b, bv.Verify())
}

func TestEmpty(t *testing.T) {
	partitiontest.PartitionTest(t)
	bv := MakeBatchVerifier()
	require.Error(t, bv.Verify())
}
