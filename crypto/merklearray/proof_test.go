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

package merklearray

import (
	"github.com/algorand/go-algorand/crypto/cryptbase"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestProofSerialization(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	array := make(TestArray, 3)
	for i := uint64(0); i < 3; i++ {
		cryptbase.RandBytes(array[i][:])
	}

	tree, err := Build(array, cryptbase.HashFactory{HashType: cryptbase.Sha512_256})
	a.NoError(err)

	// creates a proof with missing child
	p, err := tree.ProveSingleLeaf(2)
	a.NoError(err)

	data := p.GetFixedLengthHashableRepresentation()
	a.Equal(len(data), 1+(MaxEncodedTreeDepth*cryptbase.Sha512_256Size))

	// check the padded results
	zeroDigest := make([]byte, cryptbase.Sha512_256Size)
	i := 0
	proofData := data[1:]
	for ; i < (MaxEncodedTreeDepth - 2); i++ {
		a.Equal(zeroDigest, proofData[cryptbase.Sha512_256Size*i:cryptbase.Sha512_256Size*(i+1)])
	}

	// first proof digest is nil -> so the HashableRepresentation is zeros
	a.Equal(cryptbase.GenericDigest(nil), p.Path[0])
	a.Equal(zeroDigest, proofData[cryptbase.Sha512_256Size*i:cryptbase.Sha512_256Size*(i+1)])
	i++

	a.Equal([]byte(p.Path[1]), proofData[cryptbase.Sha512_256Size*i:cryptbase.Sha512_256Size*(i+1)])

	//VC
	tree, err = BuildVectorCommitmentTree(array, cryptbase.HashFactory{HashType: cryptbase.Sha512_256})
	a.NoError(err)

	// creates a proof with missing child
	p, err = tree.ProveSingleLeaf(2)
	a.NoError(err)

	data = p.GetFixedLengthHashableRepresentation()
	a.Equal(len(data), 1+(MaxEncodedTreeDepth*cryptbase.Sha512_256Size))

	// check the padded results
	zeroDigest = make([]byte, cryptbase.Sha512_256Size)
	i = 0
	proofData = data[1:]
	for ; i < (MaxEncodedTreeDepth - 2); i++ {
		a.Equal(zeroDigest, proofData[cryptbase.Sha512_256Size*i:cryptbase.Sha512_256Size*(i+1)])
	}

	a.Equal([]byte(p.Path[0]), proofData[cryptbase.Sha512_256Size*i:cryptbase.Sha512_256Size*(i+1)])
	i++
	a.Equal([]byte(p.Path[1]), proofData[cryptbase.Sha512_256Size*i:cryptbase.Sha512_256Size*(i+1)])

}

func TestProofSerializationMaxTree(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	array := make(TestArray, MaxNumLeavesOnEncodedTree)
	for i := uint64(0); i < MaxNumLeavesOnEncodedTree; i++ {
		cryptbase.RandBytes(array[i][:])
	}

	tree, err := BuildVectorCommitmentTree(array, cryptbase.HashFactory{HashType: cryptbase.Sha512_256})
	a.NoError(err)

	p, err := tree.ProveSingleLeaf(2)
	a.NoError(err)

	data := p.GetFixedLengthHashableRepresentation()
	a.Equal(len(data), 1+(MaxEncodedTreeDepth*cryptbase.Sha512_256Size))

	proofData := data[1:]
	for i := 0; i < MaxEncodedTreeDepth; i++ {
		a.Equal([]byte(p.Path[i]), proofData[cryptbase.Sha512_256Size*i:cryptbase.Sha512_256Size*(i+1)])
	}
}

func TestProofSerializationOneLeafTree(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	array := make(TestArray, 1)
	cryptbase.RandBytes(array[0][:])

	tree, err := BuildVectorCommitmentTree(array, cryptbase.HashFactory{HashType: cryptbase.Sha512_256})
	a.NoError(err)

	p, err := tree.ProveSingleLeaf(0)
	a.NoError(err)

	data := p.GetFixedLengthHashableRepresentation()
	a.Equal(len(data), 1+(MaxEncodedTreeDepth*cryptbase.Sha512_256Size))

	zeroDigest := make([]byte, cryptbase.Sha512_256Size)

	proofData := data[1:]
	for i := 0; i < MaxEncodedTreeDepth; i++ {
		a.Equal(zeroDigest, proofData[cryptbase.Sha512_256Size*i:cryptbase.Sha512_256Size*(i+1)])
	}

}

func TestConcatenatedProofsMissingChild(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	array := make(TestArray, 7)
	for i := 0; i < 7; i++ {
		cryptbase.RandBytes(array[i][:])
	}

	tree, err := Build(array, cryptbase.HashFactory{HashType: cryptbase.Sha512_256})
	a.NoError(err)

	p, err := tree.ProveSingleLeaf(6)
	a.NoError(err)

	newP := SingleLeafProof{Proof: Proof{TreeDepth: p.TreeDepth, Path: []cryptbase.GenericDigest{}, HashFactory: p.HashFactory}}

	computedPath := recomputePath(p)

	newP.Path = computedPath
	err = Verify(tree.Root(), map[uint64]cryptbase.Hashable{6: array[6]}, newP.ToProof())
	a.NoError(err)
}

func TestConcatenatedProofsFullTree(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	array := make(TestArray, 8)
	for i := 0; i < 8; i++ {
		cryptbase.RandBytes(array[i][:])
	}

	tree, err := Build(array, cryptbase.HashFactory{HashType: cryptbase.Sha512_256})
	a.NoError(err)

	p, err := tree.ProveSingleLeaf(6)
	a.NoError(err)

	newP := SingleLeafProof{Proof: Proof{TreeDepth: p.TreeDepth, Path: []cryptbase.GenericDigest{}, HashFactory: p.HashFactory}}

	computedPath := recomputePath(p)

	newP.Path = computedPath
	err = Verify(tree.Root(), map[uint64]cryptbase.Hashable{6: array[6]}, newP.ToProof())
	a.NoError(err)
}

func TestConcatenatedProofsOneLeaf(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	array := make(TestArray, 1)
	cryptbase.RandBytes(array[0][:])

	tree, err := Build(array, cryptbase.HashFactory{HashType: cryptbase.Sha512_256})
	a.NoError(err)

	p, err := tree.ProveSingleLeaf(0)
	a.NoError(err)

	newP := SingleLeafProof{Proof: Proof{TreeDepth: p.TreeDepth, Path: []cryptbase.GenericDigest{}, HashFactory: p.HashFactory}}

	computedPath := recomputePath(p)

	newP.Path = computedPath
	err = Verify(tree.Root(), map[uint64]cryptbase.Hashable{0: array[0]}, newP.ToProof())
	a.NoError(err)
}

func TestProofDeserializationError(t *testing.T) {
	partitiontest.PartitionTest(t)
	a := require.New(t)

	_, err := ProofDataToSingleLeafProof(cryptbase.Sha256.String(), 1, []byte{1})
	a.ErrorIs(err, ErrProofLengthDigestSizeMismatch)
}

func recomputePath(p *SingleLeafProof) []cryptbase.GenericDigest {
	var computedPath []cryptbase.GenericDigest
	proofconcat := p.GetConcatenatedProof()
	for len(proofconcat) > 0 {
		var d cryptbase.Digest
		copy(d[:], proofconcat)
		computedPath = append(computedPath, d[:])
		proofconcat = proofconcat[len(d):]
	}
	return computedPath
}
