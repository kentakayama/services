// Copyright 2021-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package generic_eat

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/veraison/ear"
	"github.com/veraison/go-cose"

	"github.com/veraison/services/handler"
	"github.com/veraison/services/proto"
	"github.com/veraison/services/scheme/common"
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
	/* extract uuid-typed ueid from token*/
	message := cose.NewSign1Message()
	err := message.UnmarshalCBOR(token.Data)
	if err != nil {
		return fmt.Errorf("failed CBOR decoding for CWT: %w", err)
	}
	var claims map[int]interface{}
	err = cbor.Unmarshal(message.Payload, &claims)
	if err != nil {
		return fmt.Errorf("failed CBOR decoding for payload: %w", err)
	}
	u, ok := claims[256].([]byte)
	if !ok {
		return fmt.Errorf("failed to get ueid")
	}
	uuidValue, err := uuid.FromBytes(u)
	if err != nil {
		return fmt.Errorf("generic-eat requires the ueid value as UUID")
	}

	/* find trust anchor */
	akPub := func() string {
		for _, trustAnchor := range trustAnchors {
			var ta map[string]interface{}
			err = json.Unmarshal([]byte(trustAnchor), &ta)
			if err != nil {
				continue
			}
			attr, ok := ta["attributes"].(map[string]interface{})
			if !ok {
				continue
			}
			instanceID, ok := attr["instance-id"].(string)
			if !ok {
				continue
			}
			if uuidValue.String() == instanceID {
				akPub, ok := attr["ak-pub"].(string)
				if !ok {
					continue
				}
				return akPub
			}
		}
		return ""
	}()
	if akPub == "" {
		return handler.BadEvidence(fmt.Errorf("no trust anchor found for ueid: %s", uuidValue.String()))
	}

	/* verify the signature in the evidence with akPub */
	pubKey, err := common.DecodePemSubjectPubKeyInfo([]byte(akPub))
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

	err = message.Verify(nil, verifier)
	if err != nil {
		return handler.BadEvidence(fmt.Errorf("could not verifies with hard coded key: %v", err))
	}

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
