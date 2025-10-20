// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package generic_eat

const SchemeName = "generic-eat"

var EndorsementMediaTypes = []string{
	// Unsigned CoRIM profile
	`application/corim-unsigned+cbor; profile=http://example.com`,
	// Signed CoRIM profile
	`application/rim+cose; profile=http://example.com`,
}

var EvidenceMediaTypes = []string{
	`application/eat-cwt; profile="urn:ietf:rfc:rfc9711"`,
}
