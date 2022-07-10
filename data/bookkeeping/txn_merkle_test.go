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

package bookkeeping

import (
	"github.com/algorand/go-algorand/crypto/cryptbase"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto/merklearray"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/test/partitiontest"
)

func TestTxnMerkleElemHash(t *testing.T) {
	partitiontest.PartitionTest(t)

	var tme txnMerkleElem
	cryptbase.RandBytes(tme.stib.SignedTxn.Txn.Header.Sender[:])
	require.Equal(t, cryptbase.HashObj(&tme), tme.Hash())
}

func TestTxnMerkle(t *testing.T) {
	partitiontest.PartitionTest(t)

	for ntxn := uint64(0); ntxn < 128; ntxn++ {
		var b Block
		b.CurrentProtocol = protocol.ConsensusCurrentVersion
		cryptbase.RandBytes(b.BlockHeader.GenesisHash[:])

		var elems []txnMerkleElem

		for i := uint64(0); i < ntxn; i++ {
			txn := transactions.Transaction{
				Type: protocol.PaymentTx,
				Header: transactions.Header{
					GenesisHash: b.BlockHeader.GenesisHash,
				},
				PaymentTxnFields: transactions.PaymentTxnFields{
					Amount: basics.MicroAlgos{Raw: i},
				},
			}

			sigtxn := transactions.SignedTxn{Txn: txn}
			ad := transactions.ApplyData{}

			stib, err := b.BlockHeader.EncodeSignedTxn(sigtxn, ad)
			require.NoError(t, err)

			b.Payset = append(b.Payset, stib)

			var e txnMerkleElem
			e.hashType = cryptbase.Sha512_256
			e.txn = txn
			e.stib = stib
			elems = append(elems, e)
		}

		tree, err := b.TxnMerkleTree()
		require.NoError(t, err)

		root := tree.Root()
		for i := uint64(0); i < ntxn; i++ {
			proof, err := tree.Prove([]uint64{i})
			require.NoError(t, err)
			elemVerif := make(map[uint64]cryptbase.Hashable)
			elemVerif[i] = &elems[i]
			err = merklearray.Verify(root, elemVerif, proof)
			require.NoError(t, err)
		}
	}
}

func TestBlock_TxnMerkleTreeSHA256(t *testing.T) {
	partitiontest.PartitionTest(t)

	for ntxn := uint64(0); ntxn < 128; ntxn++ {
		var b Block
		b.CurrentProtocol = protocol.ConsensusFuture
		cryptbase.RandBytes(b.BlockHeader.GenesisHash[:])

		var elems []txnMerkleElem

		for i := uint64(0); i < ntxn; i++ {
			txn := transactions.Transaction{
				Type: protocol.PaymentTx,
				Header: transactions.Header{
					GenesisHash: b.BlockHeader.GenesisHash,
				},
				PaymentTxnFields: transactions.PaymentTxnFields{
					Amount: basics.MicroAlgos{Raw: i},
				},
			}

			sigtxn := transactions.SignedTxn{Txn: txn}
			ad := transactions.ApplyData{}

			stib, err := b.BlockHeader.EncodeSignedTxn(sigtxn, ad)
			require.NoError(t, err)

			b.Payset = append(b.Payset, stib)

			var e txnMerkleElem
			e.hashType = cryptbase.Sha256
			e.txn = txn
			e.stib = stib
			elems = append(elems, e)
		}

		tree, err := b.TxnMerkleTreeSHA256()
		require.NoError(t, err)

		root := tree.Root()
		for i := uint64(0); i < ntxn; i++ {
			proof, err := tree.Prove([]uint64{i})
			require.NoError(t, err)
			elemVerif := make(map[uint64]cryptbase.Hashable)
			elemVerif[i] = &elems[i]
			err = merklearray.VerifyVectorCommitment(root, elemVerif, proof)
			require.NoError(t, err)
		}
	}
}

func BenchmarkTxnRoots(b *testing.B) {
	var blk Block
	blk.CurrentProtocol = protocol.ConsensusCurrentVersion
	cryptbase.RandBytes(blk.BlockHeader.GenesisHash[:])

	proto := config.Consensus[blk.CurrentProtocol]

	for i := 0; true; i++ {
		txn := transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				GenesisHash: blk.BlockHeader.GenesisHash,
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Amount: basics.MicroAlgos{Raw: cryptbase.RandUint64()},
			},
		}

		cryptbase.RandBytes(txn.Sender[:])
		cryptbase.RandBytes(txn.PaymentTxnFields.Receiver[:])

		sigtxn := transactions.SignedTxn{Txn: txn}
		ad := transactions.ApplyData{}

		stib, err := blk.BlockHeader.EncodeSignedTxn(sigtxn, ad)
		require.NoError(b, err)

		blk.Payset = append(blk.Payset, stib)

		if (i%1024 == 0) && len(protocol.Encode(blk.Payset)) >= proto.MaxTxnBytesPerBlock {
			break
		}
	}

	var r cryptbase.Digest

	b.Run("FlatCommit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var err error
			r, err = blk.paysetCommit(config.PaysetCommitFlat)
			require.NoError(b, err)
		}
	})

	b.Run("MerkleCommit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var err error
			r, err = blk.paysetCommit(config.PaysetCommitMerkle)
			require.NoError(b, err)
		}
	})

	_ = r
}

func txnMerkleToRawAppend(txid [cryptbase.DigestSize]byte, stib [cryptbase.DigestSize]byte) []byte {
	buf := make([]byte, 0, 2*cryptbase.DigestSize)
	buf = append(buf, txid[:]...)
	return append(buf, stib[:]...)
}
func BenchmarkTxnMerkleToRaw(b *testing.B) {
	digest1 := cryptbase.Hash([]byte{1, 2, 3})
	digest2 := cryptbase.Hash([]byte{4, 5, 6})

	b.Run("copy", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			txnMerkleToRaw(digest1, digest2)
		}
	})
	b.Run("append", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			txnMerkleToRawAppend(digest1, digest2)
		}
	})
}
