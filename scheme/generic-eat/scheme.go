// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package generic_eat

const SchemeName = "generic-eat"

var EndorsementMediaTypes = []string{
	// Unsigned CoRIM profile
	`application/corim-unsigned+cbor`,
	// Signed CoRIM profile
	`application/rim+cose`,
}

var EvidenceMediaTypes = []string{
	`application/eat-cwt; profile="urn:ietf:rfc:rfc9711"`,
}
