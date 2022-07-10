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

package falcon

import (
	cfalcon "github.com/algorand/falcon"
	"github.com/algorand/go-algorand/crypto/cryptbase"
)

const (
	// FalconSeedSize Represents the size in bytes of the random bytes used to generate Falcon keys
	FalconSeedSize = 48

	// FalconMaxSignatureSize Represents the max possible size in bytes of a falcon signature
	FalconMaxSignatureSize = cfalcon.CTSignatureSize
)

type (
	// PublicKey is a wrapper for cfalcon.PublicKeySizey (used for packing)
	PublicKey [cfalcon.PublicKeySize]byte
	// PrivateKey is a wrapper for cfalcon.PrivateKeySize (used for packing)
	PrivateKey [cfalcon.PrivateKeySize]byte
	// Seed represents the seed which is being used to generate Falcon keys
	Seed [FalconSeedSize]byte
	// Signature represents a Falcon signature in a compressed-form
	//msgp:allocbound Signature FalconMaxSignatureSize
	Signature []byte
)

// Signer is the implementation of Signer for the Falcon signature scheme.
type Signer struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	PublicKey  PublicKey  `codec:"pk"`
	PrivateKey PrivateKey `codec:"sk"`
}

// GenerateFalconSigner Generates a Falcon Signer.
func GenerateFalconSigner(seed Seed) (Signer, error) {
	pk, sk, err := cfalcon.GenerateKey(seed[:])
	return Signer{
		PublicKey:  PublicKey(pk),
		PrivateKey: PrivateKey(sk),
	}, err
}

// Sign receives a message and generates a signature over that message.
func (d *Signer) Sign(message cryptbase.Hashable) (Signature, error) {
	hs := cryptbase.Hash(cryptbase.HashRep(message))
	return d.SignBytes(hs[:])
}

// SignBytes receives bytes and signs over them.
func (d *Signer) SignBytes(data []byte) (Signature, error) {
	signedData, err := (*cfalcon.PrivateKey)(&d.PrivateKey).SignCompressed(data)
	return Signature(signedData), err
}

// GetVerifyingKey Outputs a verifying key object which is serializable.
func (d *Signer) GetVerifyingKey() *Verifier {
	return &Verifier{
		PublicKey: d.PublicKey,
	}
}

// Verifier implements the type Verifier interface for the falcon signature scheme.
type Verifier struct {
	_struct struct{} `codec:",omitempty,omitemptyarray"`

	PublicKey PublicKey `codec:"k"`
}

// Verify follows falcon algorithm to verify a signature.
func (d *Verifier) Verify(message cryptbase.Hashable, sig Signature) error {
	hs := cryptbase.Hash(cryptbase.HashRep(message))
	return d.VerifyBytes(hs[:], sig)
}

// VerifyBytes follows falcon algorithm to verify a signature.
func (d *Verifier) VerifyBytes(data []byte, sig Signature) error {
	// The wrapper, currently, support only the compress form signature. so we can
	// assume that the signature given is in a compress form
	falconSig := cfalcon.CompressedSignature(sig)
	return (*cfalcon.PublicKey)(&d.PublicKey).Verify(falconSig, data)
}

// GetFixedLengthHashableRepresentation is used to fetch a plain serialized version of the public data (without the use of the msgpack).
func (d *Verifier) GetFixedLengthHashableRepresentation() []byte {
	return d.PublicKey[:]
}

// NewFalconSigner creates a falconSigner that is used to sign and verify falcon signatures
func NewFalconSigner() (*Signer, error) {
	var seed Seed
	cryptbase.RandBytes(seed[:])
	signer, err := GenerateFalconSigner(seed)
	if err != nil {
		return &Signer{}, err
	}
	return &signer, nil
}

// GetFixedLengthHashableRepresentation returns a serialized version of the signature
func (s Signature) GetFixedLengthHashableRepresentation() ([]byte, error) {
	compressedSignature := cfalcon.CompressedSignature(s)
	ctSignature, err := compressedSignature.ConvertToCT()
	return ctSignature[:], err
}

// IsSaltVersionEqual of the signature matches the given version
func (s Signature) IsSaltVersionEqual(version byte) bool {
	return (*cfalcon.CompressedSignature)(&s).SaltVersion() == version
}
