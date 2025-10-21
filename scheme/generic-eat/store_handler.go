// Copyright 2021-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package generic_eat

import (
	"encoding/json"
	"fmt"
	"net/url"

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
	return []string{"GENERIC_EAT://"}, nil
}

func (s StoreHandler) GetRefValueIDs(
	tenantID string,
	trustAnchors []string,
	claims map[string]interface{},
) ([]string, error) {
	return []string{"GENERIC_EAT://"}, nil
}

func (s StoreHandler) SynthKeysFromRefValue(
	tenantID string,
	refValue *handler.Endorsement,
) ([]string, error) {
	lookupKey, err := s.endorsementToLookupKey(tenantID, refValue, "refval")
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
	lookupKey, err := s.endorsementToLookupKey(tenantID, ta, "ta")
	if err != nil {
		return nil, err
	}
	log.Debugf("Scheme %s Plugin TA Look Up Key= %s\n", tenantID, lookupKey)
	return []string{lookupKey}, nil
}

func (s StoreHandler) endorsementToLookupKey(
	tenantID string,
	endorsement *handler.Endorsement,
	pathType string,
) (string, error) {
	if pathType != "refval" && pathType != "ta" {
		return "", fmt.Errorf("illegal path for lookupKey: %s", pathType)
	}

	var at map[string]interface{}
	err := json.Unmarshal(endorsement.Attributes, &at)
	if err != nil {
		return "", fmt.Errorf("unable to unmarshal the reference value for tenantID: %s %w %s", tenantID, err, endorsement.Attributes)
	}

	// we use ueid as key for finding reference value
	// see also RefValExtractor() in corim_extractor.go
	key := "instance-id"
	instanceID, ok := at[key].(string)
	if !ok {
		return "", fmt.Errorf("unable to get instance id for tenantID: %s %#v", tenantID, at)
	}
	u := url.URL{
		Scheme: "GENERIC_EAT",
		Host:   tenantID,
		Path:   instanceID + "/" + pathType,
	}
	lookupKey := u.String()
	return lookupKey, nil
}
