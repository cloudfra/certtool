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
	"crypto/x509"

	"software.sslmate.com/src/go-pkcs12"
)

func toPFX(cert *x509.Certificate, privateKey interface{}, password string, legacy bool) ([]byte, error) {
	if legacy {
		return pkcs12.LegacyDES.Encode(privateKey, cert, nil, password)
	}
	return pkcs12.Modern.Encode(privateKey, cert, nil, password)
}
