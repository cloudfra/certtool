// Copyright 2022 Jeremy Edwards
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certtool

import (
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"software.sslmate.com/src/go-pkcs12"
)

func TestToPFX_Modern(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}
	assert := assert.New(t)

	kp, err := GenerateKeyPair(&Args{KeyType: &KeyType{Algorithm: ecdsaAlgorithm, KeyLength: 256}})
	assert.Nil(err)

	cert, privKey, err := ReadKeyPair(kp.PublicCertificate, kp.PrivateKey)
	assert.Nil(err)

	pfxData, err := toPFX(cert, privKey, "", false)
	assert.Nil(err)
	assert.NotEmpty(pfxData)

	decodedKey, decodedCert, err := pkcs12.Decode(pfxData, "")
	assert.Nil(err)
	assert.NotNil(decodedCert)
	assert.NotNil(decodedKey)
}

func TestToPFX_Legacy(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}
	assert := assert.New(t)

	kp, err := GenerateKeyPair(&Args{KeyType: &KeyType{Algorithm: rsaAlgorithm, KeyLength: 2048}})
	assert.Nil(err)

	cert, privKey, err := ReadKeyPair(kp.PublicCertificate, kp.PrivateKey)
	assert.Nil(err)

	pfxData, err := toPFX(cert, privKey, "testpass", true)
	assert.Nil(err)
	assert.NotEmpty(pfxData)

	decodedKey, decodedCert, err := pkcs12.Decode(pfxData, "testpass")
	assert.Nil(err)
	assert.NotNil(decodedCert)
	_, ok := decodedKey.(*rsa.PrivateKey)
	assert.True(ok, "expected *rsa.PrivateKey")
}
