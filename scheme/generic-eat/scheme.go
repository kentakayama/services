// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package generic_eat

const (
	SchemeName = "GENERIC_EAT"
)

var EndorsementMediaTypes = []string{
	// Unsigned CoRIM profile
	`application/corim-unsigned+cbor; profile="http://example.com/corim/profile"`,
	// Signed CoRIM profile
	`application/rim+cose; profile="http://example.com/corim/profile"`,
}

var EvidenceMediaTypes = []string{
	`application/eat+cwt; eat_profile="urn:ietf:rfc:rfc9711"`,
}
