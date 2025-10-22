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
			if len(hwversion) < 1 || 2 < len(hwversion) {
				return nil, handler.BadEvidence(fmt.Errorf("invalid length of hwversion claim: %#v", claim))
			}
			var h common.VersionType
			ok := false
			h.Version, ok = hwversion[0].(string)
			if !ok {
				return nil, handler.BadEvidence(fmt.Errorf("invalid type of version in hwversion claim: %#v", hwversion[0]))
			}
			if len(hwversion) == 2 {
				h.Scheme, ok = hwversion[1].(uint64)
				if !ok {
					return nil, handler.BadEvidence(fmt.Errorf("invalid type of scheme in hwversion claim: %#v", hwversion[1]))
				}
			} else {
				h.Scheme = 0
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
			claims["measurements"] = claim
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

			// return nil, fmt.Errorf("ok version is %#v, hwversion is %#v", attr["version"], evidence["hwversion"])
			version, ok := attr["version"].(map[string]interface{})
			if !ok {
				return result, fmt.Errorf("cannot get reference value version: %#v", attr["version"])
			}
			hwversion, ok := evidence["hwversion"].(map[string]interface{})
			if !ok {
				return result, fmt.Errorf("cannot get evidence hwversion: %#v", evidence["hwversion"])
			}
			if version["value"].(string) == hwversion["Version"].(string) {
				*result.Submods[SchemeName].Status = ear.TrustTierAffirming
				return result, nil
			}
		}
	}

	return nil, fmt.Errorf("no endorsements nor no reference values are found")
}
