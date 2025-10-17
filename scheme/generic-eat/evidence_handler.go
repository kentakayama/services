// Copyright 2021-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package generic_eat

import (
	"github.com/veraison/ear"

	"github.com/veraison/services/handler"
	"github.com/veraison/services/proto"
)

type EvidenceHandler struct {
}

func (s EvidenceHandler) GetName() string {
	return "generic-eat-evidence-handler"
}

func (s EvidenceHandler) GetAttestationScheme() string {
	return SchemeName
}

func (s EvidenceHandler) GetSupportedMediaTypes() []string {
	return EvidenceMediaTypes
}

func (s EvidenceHandler) ExtractClaims(
	token *proto.AttestationToken,
	trustAnchors []string,
) (map[string]interface{}, error) {
	/*
		// check the media type
		supported := false
		for _, mt := range EvidenceMediaTypes {
			if token.MediaType == mt {
				supported = true
				break
			}
		}

		if !supported {
			return nil, handler.BadEvidence("wrong media type: expect %q, but found %q",
				strings.Join(EvidenceMediaTypes, ", "),
				token.MediaType,
			)
		}

		message := cose.NewSign1Message()
		err := message.UnmarshalCBOR(token.Data)
		if err != nil {
			return nil, handler.BadEvidence(fmt.Errorf("failed CBOR decoding for CWT: %w", err))
		}
	*/
	claims := make(map[string]interface{})

	return claims, nil
}

func (s EvidenceHandler) ValidateEvidenceIntegrity(
	token *proto.AttestationToken,
	trustAnchors []string,
	endorsements []string,
) error {
	/*
		pemKey := "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMKBCTNIcKUSDii11ySs3526iDZ8A\niTo7Tu6KPAqv7D7gS2XpJFbZiItSs3m9+9Ue6GnvHw/GW2ZZaVtszggXIw==\n-----END PUBLIC KEY-----"
		pubKey, err := common.DecodePemSubjectPubKeyInfo([]byte(pemKey))
		if err != nil {
			return err
		}
		ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return handler.BadEvidence(fmt.Errorf("could not extract EC public key; got [%T]: %v", pubKey, err))
		}
		verifier, err := cose.NewVerifier(cose.AlgorithmES256, ecdsaPubKey)
		if err != nil {
			return handler.BadEvidence(fmt.Errorf("could not construct verifier for ES256: %v", err))
		}

		var msg cose.Sign1Message
		if err = msg.UnmarshalCBOR(token.Data); err != nil {
			return handler.BadEvidence(fmt.Errorf("could not unmarshal cbor: %v", err))
		}
		if err = msg.Verify(nil, verifier); err != nil {
			return handler.BadEvidence(fmt.Errorf("could not verifies with hard coded key: %v", err))
		}
	*/
	return nil
}

func (s EvidenceHandler) AppraiseEvidence(
	ec *proto.EvidenceContext,
	endorsementsString []string,
) (*ear.AttestationResult, error) {
	result := handler.CreateAttestationResult(SchemeName)

	// always "affirming"
	appraisal := result.Submods[SchemeName]
	*appraisal.Status = ear.TrustTierAffirming

	return result, nil
}
