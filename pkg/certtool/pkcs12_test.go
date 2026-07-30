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

	"software.sslmate.com/src/go-pkcs12"
)

func TestToPFX_Modern(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	kp, err := GenerateKeyPair(&Args{KeyType: &KeyType{Algorithm: ecdsaAlgorithm, KeyLength: 256}})
	if err != nil {
		t.Fatalf("GenerateKeyPair() err = %v, want nil", err)
	}

	cert, privKey, err := ReadKeyPair(kp.PublicCertificate, kp.PrivateKey)
	if err != nil {
		t.Fatalf("ReadKeyPair() err = %v, want nil", err)
	}

	pfxData, err := toPFX(cert, privKey, "", false)
	if err != nil {
		t.Fatalf("toPFX() err = %v, want nil", err)
	}
	if len(pfxData) == 0 {
		t.Fatal("toPFX() returned empty PFX data")
	}

	decodedKey, decodedCert, err := pkcs12.Decode(pfxData, "")
	if err != nil {
		t.Fatalf("pkcs12.Decode() err = %v, want nil", err)
	}
	if decodedCert == nil {
		t.Error("decoded cert is nil")
	}
	if decodedKey == nil {
		t.Error("decoded key is nil")
	}
}

func TestToPFX_Legacy(t *testing.T) {
	if testing.Short() {
		t.Skip("certificate generation takes a long time")
	}

	kp, err := GenerateKeyPair(&Args{KeyType: &KeyType{Algorithm: rsaAlgorithm, KeyLength: 2048}})
	if err != nil {
		t.Fatalf("GenerateKeyPair() err = %v, want nil", err)
	}

	cert, privKey, err := ReadKeyPair(kp.PublicCertificate, kp.PrivateKey)
	if err != nil {
		t.Fatalf("ReadKeyPair() err = %v, want nil", err)
	}

	pfxData, err := toPFX(cert, privKey, "testpass", true)
	if err != nil {
		t.Fatalf("toPFX() err = %v, want nil", err)
	}
	if len(pfxData) == 0 {
		t.Fatal("toPFX() returned empty PFX data")
	}

	decodedKey, decodedCert, err := pkcs12.Decode(pfxData, "testpass")
	if err != nil {
		t.Fatalf("pkcs12.Decode() err = %v, want nil", err)
	}
	if decodedCert == nil {
		t.Error("decoded cert is nil")
	}
	if _, ok := decodedKey.(*rsa.PrivateKey); !ok {
		t.Errorf("decoded key is %T, want *rsa.PrivateKey", decodedKey)
	}
}
