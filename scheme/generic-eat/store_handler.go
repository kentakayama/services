// Copyright 2021-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package generic_eat

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/veraison/go-cose"
	"github.com/veraison/services/handler"
	"github.com/veraison/services/log"
	"github.com/veraison/services/proto"
)

type StoreHandler struct {
}

func (s StoreHandler) GetName() string {
	return "generic-eat-store-handler"
}

func (s StoreHandler) GetAttestationScheme() string {
	return SchemeName
}

func (s StoreHandler) GetSupportedMediaTypes() []string {
	return nil
}

func (s StoreHandler) GetTrustAnchorIDs(token *proto.AttestationToken) ([]string, error) {
	message := cose.NewSign1Message()
	err := message.UnmarshalCBOR(token.Data)
	if err != nil {
		return nil, fmt.Errorf("failed CBOR decoding for CWT: %w", err)
	}
	var claims map[int]interface{}
	err = cbor.Unmarshal(message.Payload, &claims)
	if err != nil {
		return nil, fmt.Errorf("failed CBOR decoding for payload: %w", err)
	}
	uuidValue, ok := claims[256].([]byte)
	if !ok {
		return nil, fmt.Errorf("failed to get ueid")
	}
	u, err := uuid.FromBytes(uuidValue)
	if err != nil {
		return nil, fmt.Errorf("generic-eat requires the ueid value as UUID")
	}
	// TODO: how to get tenantID from token?
	lookupKey, err := s.keyToLookupKey("0", u.String(), "ta")
	if err != nil {
		return nil, err
	}
	return []string{lookupKey}, nil
}

func (s StoreHandler) GetRefValueIDs(
	tenantID string,
	trustAnchors []string,
	claims map[string]interface{},
) ([]string, error) {
	var instanceID string
	// TODO: should iterate trustAnchors?
	trustAnchor := trustAnchors[0]
	var ta map[string]interface{}
	err := json.Unmarshal([]byte(trustAnchor), &ta)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trustAnchor as JSON: %s", trustAnchor)
	}
	attr, ok := ta["attributes"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to get attributes: %#v", ta)
	}
	instanceID, ok = attr["instance-id"].(string)
	if !ok {
		return nil, fmt.Errorf("failed to get instance-id: %#v", attr)
	}
	lookupKey, err := s.keyToLookupKey(tenantID, instanceID, "refval")
	if err != nil {
		return nil, err
	}
	return []string{lookupKey}, nil
}

func (s StoreHandler) SynthKeysFromRefValue(
	tenantID string,
	refValue *handler.Endorsement,
) ([]string, error) {
	key, err := s.attributesToKey(refValue)
	if err != nil {
		return nil, err
	}
	lookupKey, err := s.keyToLookupKey(tenantID, key, "refval")
	if err != nil {
		return nil, err
	}
	log.Debugf("Scheme %s Plugin Reference Value Look Up Key= %s\n", tenantID, lookupKey)
	return []string{lookupKey}, nil
}

func (s StoreHandler) SynthKeysFromTrustAnchor(
	tenantID string,
	ta *handler.Endorsement,
) ([]string, error) {
	key, err := s.attributesToKey(ta)
	if err != nil {
		return nil, err
	}
	lookupKey, err := s.keyToLookupKey(tenantID, key, "ta")
	if err != nil {
		return nil, err
	}
	log.Debugf("Scheme %s Plugin TA Look Up Key= %s\n", tenantID, lookupKey)
	return []string{lookupKey}, nil
}

func (s StoreHandler) attributesToKey(endorsement *handler.Endorsement) (string, error) {
	var at map[string]interface{}
	err := json.Unmarshal(endorsement.Attributes, &at)
	if err != nil {
		return "", fmt.Errorf("unable to unmarshal the reference value for attribute: %w %s", err, endorsement.Attributes)
	}

	// we use ueid as key for finding reference value
	// see also RefValExtractor() in corim_extractor.go
	key := "instance-id"
	instanceID, ok := at[key].(string)
	if !ok {
		return "", fmt.Errorf("unable to get instance id for attribute: %#v", at)
	}
	return instanceID, nil
}

func (s StoreHandler) keyToLookupKey(
	tenantID string,
	key string,
	pathType string,
) (string, error) {
	if pathType != "refval" && pathType != "ta" {
		return "", fmt.Errorf("illegal path for lookupKey: %s", pathType)
	}

	u := url.URL{
		Scheme: "GENERIC_EAT",
		Host:   tenantID,
		Path:   key + "/" + pathType,
	}
	lookupKey := u.String()
	return lookupKey, nil
}
