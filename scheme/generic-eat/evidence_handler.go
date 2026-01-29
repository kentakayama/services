// Copyright 2021-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package generic_eat

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/ear"
	"github.com/veraison/eat"
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
	/* do not check the media type */
	message := cose.NewSign1Message()
	err := message.UnmarshalCBOR(token.Data)
	if err != nil {
		return nil, handler.BadEvidence(fmt.Errorf("failed CBOR decoding for CWT: %w", err))
	}

	var eat eat.Eat
	err = eat.FromCBOR(message.Payload)
	if err != nil {
		return nil, handler.BadEvidence(fmt.Errorf("failed CBOR decoding for payload: %w", err))
	}

	jsonData, err := eat.ToJSON()
	if err != nil {
		return nil, handler.BadEvidence(fmt.Errorf("failed to extract EAT ClaimsSet: %w", err))
	}

	var claimsSet map[string]interface{}
	if err := json.Unmarshal(jsonData, &claimsSet); err != nil {
		return nil, handler.BadEvidence(fmt.Errorf("failed to convert EAT ClaimsSet to internal type: %w %#v", err, eat))
	}

	return claimsSet, nil
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
	ueidValue := eat.UEID(u)

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
			if base64.StdEncoding.EncodeToString(ueidValue) == instanceID {
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
		return handler.BadEvidence(fmt.Errorf("no trust anchor found for ueid: %s", base64.StdEncoding.EncodeToString(ueidValue)))
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
		return handler.BadEvidence(fmt.Errorf("could not verifies with key: %#v %w", ecdsaPubKey, err))
	}

	return nil
}

func (s EvidenceHandler) AppraiseEvidence(
	ec *proto.EvidenceContext,
	endorsementsStrings []string,
) (*ear.AttestationResult, error) {
	result := handler.CreateAttestationResult(SchemeName)
	*result.Submods[SchemeName].Status = ear.TrustTierContraindicated

	/* extract uuid-typed ueid from evidence */
	evidence := ec.Evidence.AsMap()
	if evidence["ueid"] == nil {
		return result, fmt.Errorf("could not get ueid from evidence")
	}
	ueidBase64, ok := evidence["ueid"].(string)
	if !ok {
		return result, fmt.Errorf("could not get ueid as string")
	}
	ueidValue, err := base64.StdEncoding.DecodeString(ueidBase64)
	if err != nil {
		return result, fmt.Errorf("could not get ueid as base64 encoded string: %w", err)
	}
	ueid := eat.UEID(ueidValue)

	for i, e := range endorsementsStrings {
		var endorsement handler.Endorsement
		if err := json.Unmarshal([]byte(e), &endorsement); err != nil {
			return result, fmt.Errorf("could not decode endorsement at index %d: %w", i, err)
		}

		var attr map[string]interface{}
		if err := json.Unmarshal(endorsement.Attributes, &attr); err != nil {
			return result, fmt.Errorf("could not decode attributes: %w", err)
		}

		if attr["instance-id"] == base64.StdEncoding.EncodeToString(ueid) {
			/* this set of Reference Values is for this evidence */
			*result.Submods[SchemeName].Status = ear.TrustTierWarning
			allReferenceValueOK := true

			// extract measured-component from measurements
			if evidence["measurements"] == nil {
				return nil, handler.BadEvidence(fmt.Errorf("generic-eat requires measurements claim"))
			}
			jsonBytes, err := json.Marshal(evidence["measurements"])
			if err != nil {
				return nil, fmt.Errorf("failed to handle measurements: %w", err)
			}
			var ms []eat.Measurement
			if err := json.Unmarshal(jsonBytes, &ms); err != nil {
				return nil, fmt.Errorf("failed to handle measurements: %w", err)
			}

			if len(ms) == 0 {
				return result, handler.BadEvidence(fmt.Errorf("no measurement claim found: %#v for %#v", jsonBytes, evidence["measurements"]))
			}
			m := ms[0]
			var mc eat.MeasuredComponent
			// XXX: only MeasuredComponents are in evidence["measurements"] due to poor implementation
			switch m.Type {
			case 600: // TBD1, measured-component
				if err := cbor.Unmarshal(m.Format, &mc); err != nil {
					return result, handler.BadEvidence(fmt.Errorf("failed to extract measured-component: %#v", m.Format))
				}
			default:
				return result, handler.BadEvidence(fmt.Errorf("coap-content-format %d is not supported: %#v", m.Type, m.Format))
			}

			// need to check measured-component.id.version?
			version, necessary := attr["version"].(map[string]interface{})
			if necessary {
				// need to compare with version in Evidence
				if mc.Id.Version == nil {
					return result, fmt.Errorf("cannot get version: %#v", mc)
				}

				if mc.Id.Version.Version != version["value"] {
					allReferenceValueOK = false
				}
			}

			// need to check measured-component.measurement?
			digests, necessary := attr["digests"].([]interface{})
			if necessary {
				// need to compare with digest in Evidence
				digest, ok := digests[0].(string)
				if !ok {
					return result, fmt.Errorf("cannot get digest from index 0: %#v", digests)
				}

				if mc.Measurement.HashAlgID != 1 {
					return result, handler.BadEvidence(fmt.Errorf("not supported hash algorithm: %v", mc.Measurement.HashAlgID))
				}
				base64Val := base64.StdEncoding.EncodeToString(mc.Measurement.HashValue)
				comparedDigest := "sha-256;" + base64Val

				if comparedDigest != digest {
					allReferenceValueOK = false
				}
			}

			if allReferenceValueOK {
				*result.Submods[SchemeName].Status = ear.TrustTierAffirming
			}
			return result, nil
		}
	}

	return nil, fmt.Errorf("no endorsements nor no reference values are found")
}
