// Copyright 2021-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package generic_eat

import (
	"crypto/ecdsa"
	"encoding/base64"
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

func (s EvidenceHandler) ExtractVersion(
	value []interface{},
) (*common.VersionType, error) {
	if len(value) < 1 || 2 < len(value) {
		return nil, fmt.Errorf("invalid length for type version: %#v", value)
	}

	var h common.VersionType
	ok := false
	h.Version, ok = value[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid type of version: %#v (%T)", value[0], value[0])
	}
	if len(value) == 2 {
		h.Scheme, ok = value[1].(uint64)
		if !ok {
			return nil, fmt.Errorf("invalid type of scheme in value claim: %#v (%T)", value[1], value[1])
		}
	} else {
		h.Scheme = 0 // not specified
	}

	return &h, nil
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

	var rawClaims map[int]cbor.RawMessage
	err = cbor.Unmarshal(message.Payload, &rawClaims)
	if err != nil {
		return nil, handler.BadEvidence(fmt.Errorf("failed CBOR decoding for payload: %w", err))
	}

	/* extract int => any claims from COSE payload, see RFC 9711: EAT */
	claims := make(map[string]interface{})
	for key, claim := range rawClaims {
		switch key {
		case 1:
			var iss string
			if err := cbor.Unmarshal(claim, &iss); err != nil {
				return nil, handler.BadEvidence(fmt.Errorf("invalid type of iss claim: %#v", claim))
			}
			claims["iss"] = iss
		case 2:
			var sub string
			if err := cbor.Unmarshal(claim, &sub); err != nil {
				return nil, handler.BadEvidence(fmt.Errorf("invalid type of sub claim: %#v", claim))
			}
			claims["sub"] = sub
		case 3:
			var aud string
			if err := cbor.Unmarshal(claim, &aud); err != nil {
				return nil, handler.BadEvidence(fmt.Errorf("invalid type of aud claim: %#v", claim))
			}
			claims["aud"] = aud
		case 4:
			var exp int
			if err := cbor.Unmarshal(claim, &exp); err != nil {
				return nil, handler.BadEvidence(fmt.Errorf("invalid type of exp claim: %#v", claim))
			}
			claims["exp"] = exp
		case 5:
			var nbf int
			if err := cbor.Unmarshal(claim, &nbf); err != nil {
				return nil, handler.BadEvidence(fmt.Errorf("invalid type of nbf claim: %#v", claim))
			}
			claims["nbf"] = nbf
		case 6:
			var iat int
			if err := cbor.Unmarshal(claim, &iat); err != nil {
				return nil, handler.BadEvidence(fmt.Errorf("invalid type of iat claim: %#v", claim))
			}
			claims["iat"] = iat
		case 7:
			var cti []byte
			if err := cbor.Unmarshal(claim, &cti); err != nil {
				return nil, handler.BadEvidence(fmt.Errorf("invalid type of cti claim: %#v", claim))
			}
			claims["cti"] = base64.StdEncoding.EncodeToString(cti)
		case 8:
			// TODO?: do not handle
			claims["cnf"] = base64.StdEncoding.EncodeToString(claim)
		case 10:
			var eatNonce []byte
			if err := cbor.Unmarshal(claim, &eatNonce); err != nil {
				return nil, handler.BadEvidence(fmt.Errorf("invalid type of eat_nonce claim: %#v", claim))
			}
			claims["eat_nonce"] = base64.StdEncoding.EncodeToString(eatNonce)
		case 256:
			var ueid []byte
			if err := cbor.Unmarshal(claim, &ueid); err != nil {
				return nil, handler.BadEvidence(fmt.Errorf("invalid type of ueid claim: %#v", claim))
			}
			uuidValue, err := uuid.FromBytes(ueid)
			if err != nil {
				return nil, handler.BadEvidence(fmt.Errorf("generic-eat requires the ueid value as UUID"))
			}
			claims["ueid"] = uuidValue.String()
		case 257:
			// TODO: do not handle
			claims["sueids"] = claim
		case 258:
			var oemid []byte
			if err := cbor.Unmarshal(claim, &oemid); err != nil {
				return nil, handler.BadEvidence(fmt.Errorf("invalid type of oemid claim: %#v", claim))
			}
			claims["oemid"] = base64.StdEncoding.EncodeToString(oemid)
		case 259:
			var hwmodel []byte
			if err := cbor.Unmarshal(claim, &hwmodel); err != nil {
				return nil, handler.BadEvidence(fmt.Errorf("invalid type of hwmodel claim: %#v", claim))
			}
			claims["hwmodel"] = base64.StdEncoding.EncodeToString(hwmodel)
		case 260:
			var hwversion []interface{}
			if err := cbor.Unmarshal(claim, &hwversion); err != nil {
				return nil, handler.BadEvidence(fmt.Errorf("invalid type of hwversion claim: %#v", claim))
			}
			h, err := s.ExtractVersion(hwversion)
			if err != nil {
				return nil, handler.BadEvidence(fmt.Errorf("invalid value for hwversion claim: %w", err))
			}
			claims["hwversion"] = h
		case 261:
			claims["uptime"] = claim
		case 262:
			claims["oemboot"] = claim
		case 263:
			claims["dbgstat"] = claim
		case 264:
			claims["location"] = claim
		case 265:
			var eatProfile string
			if err := cbor.Unmarshal(claim, &eatProfile); err != nil {
				// TODO: support oid
				return nil, handler.BadEvidence(fmt.Errorf("invalid type of eat_profile claim: %#v", claim))
			}
			claims["eat_profile"] = eatProfile
		case 267:
			claims["bootcount"] = claim
		case 268:
			claims["bootseed"] = claim
		case 269:
			claims["dloas"] = claim
		case 270:
			claims["swname"] = claim
		case 271:
			claims["swversion"] = claim
		case 272:
			claims["manifests"] = claim
		case 273:
			var measurements []common.Measurement
			if err := cbor.Unmarshal(claim, &measurements); err != nil {
				return nil, handler.BadEvidence(fmt.Errorf("invalid type of measurements claim: %#v, %w", claim, err))
			}
			mcs := make([]common.MeasuredComponent, 0)
			for _, m := range measurements {
				switch m.Type {
				case 600:
					// TBD1, application/measured-component+cbor
					var mc common.MeasuredComponent
					var kv map[int]cbor.RawMessage
					if err := cbor.Unmarshal(m.Format, &kv); err != nil {
						return nil, handler.BadEvidence(fmt.Errorf("not measured-component: %#v, %w", m.Format, err))
					}
					for k, v := range kv {
						switch k {
						case 1: // ID
							var id []interface{}
							if err := cbor.Unmarshal(v, &id); err != nil {
								return nil, handler.BadEvidence(fmt.Errorf("not measured-component.component-id: %#v, %w", m.Format, err))
							}
							if len(id) < 1 || 2 < len(id) {
								return nil, handler.BadEvidence(fmt.Errorf("length of component-id must be 1 or 2, not %d", len(id)))
							}
							mcName, ok := id[0].(string)
							if !ok {
								return nil, handler.BadEvidence(fmt.Errorf("invalid type of measured-component.component-id.name: %#v, %w", m.Format, err))
							}
							mc.Name = mcName
							if len(id) == 2 {
								// component-id.version exists
								mcVersion, ok := id[1].([]interface{})
								if !ok {
									return nil, handler.BadEvidence(fmt.Errorf("invalid value for measured-component.component-id.version %#v (%T)", id[1], id[1]))
								}
								v, err := s.ExtractVersion(mcVersion)
								if err != nil {
									return nil, handler.BadEvidence(fmt.Errorf("invalid value for measured-component.component-id.version: %w", err))
								}
								mc.Version = *v
							} else {
								mc.Version.Version = ""
								mc.Version.Scheme = 0
							}
						case 2: // measurement
							var digest common.Digest
							if err := cbor.Unmarshal(v, &digest); err != nil {
								return nil, handler.BadEvidence(fmt.Errorf("not measured-component.measurement: %#v, %w", m.Format, err))
							}
							mc.Measurement = digest
						}
					}
					// TODO: check required members for measured-component
					mcs = append(mcs, mc)
				}
			}
			claims["measurements"] = mcs
			// claims["measurements"] = claim
		case 274:
			claims["measres"] = claim
		case 275:
			claims["intuse"] = claim
		default:
			// NOTE: you may extend claims above not to cause this error
			return nil, handler.BadEvidence(fmt.Errorf("unknown claim: %d => %#v", key, claim))
		}
	}

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
	endorsementsStrings []string,
) (*ear.AttestationResult, error) {
	result := handler.CreateAttestationResult(SchemeName)
	*result.Submods[SchemeName].Status = ear.TrustTierContraindicated

	/* extract uuid-typed ueid from evidence */
	evidence := ec.Evidence.AsMap()
	if evidence["ueid"] == nil {
		return result, fmt.Errorf("could not get ueid from evidence")
	}

	for i, e := range endorsementsStrings {
		var endorsement handler.Endorsement
		if err := json.Unmarshal([]byte(e), &endorsement); err != nil {
			return result, fmt.Errorf("could not decode endorsement at index %d: %w", i, err)
		}

		var attr map[string]interface{}
		if err := json.Unmarshal(endorsement.Attributes, &attr); err != nil {
			return result, err
		}

		if attr["instance-id"] == evidence["ueid"] {
			/* this set of Reference Values is for this evidence */
			*result.Submods[SchemeName].Status = ear.TrustTierWarning
			allReferenceValueOK := true

			// extract measured-component from measurements
			// XXX: only MeasuredComponents are in evidence["measurements"] due to poor implementation
			mcs, ok := evidence["measurements"].([]interface{})
			if !ok {
				return result, handler.BadEvidence(fmt.Errorf("cannot get evidence measurements: %#v %T", evidence["measurements"], evidence["measurements"]))
			}
			mc, ok := mcs[0].(map[string]interface{})
			if !ok {
				return result, handler.BadEvidence(fmt.Errorf("cannot get evidence measurements[0]: %#v %T", mcs[0], mcs[0]))
			}

			// need to check measured-component.id.version?
			version, necessary := attr["version"].(map[string]interface{})
			if necessary {
				// need to compare with version in Evidence
				mcVersion, ok := mc["Version"].(map[string]interface{})
				if !ok {
					return result, fmt.Errorf("cannot get version: %#v", mc["Version"])
				}

				mcVersionVersion, ok := mcVersion["Version"].(string)
				if !ok {
					return result, handler.BadEvidence(fmt.Errorf("cannot get version tstr: %#v", mcVersion["Version"]))
				}

				if mcVersionVersion != version["value"] {
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

				mcMeasurement, ok := mc["Measurement"].(map[string]interface{})
				if !ok {
					return result, handler.BadEvidence(fmt.Errorf("measurement not found: %#v", mc))
				}
				// json Number is treated as float64?
				algVal, ok := mcMeasurement["Alg"].(float64)
				if !ok {
					return result, handler.BadEvidence(fmt.Errorf("[DEBUG] alg %#v %T", mcMeasurement["Alg"], mcMeasurement["Alg"]))
				}
				alg := uint64(algVal)
				if alg != 1 {
					return result, handler.BadEvidence(fmt.Errorf("not supported hash algorithm: %v", algVal))
				}
				base64Val, ok := mcMeasurement["Val"].(string)
				if !ok {
					return result, handler.BadEvidence(fmt.Errorf("digest[Val] is not []byte: %#v", mcMeasurement["Val"]))
				}
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
