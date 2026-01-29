// Copyright 2022-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package generic_eat

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/veraison/corim/comid"
	"github.com/veraison/services/handler"
)

type CorimExtractor struct {
	Profile string
}

func (o CorimExtractor) RefValExtractor(
	rvs comid.ValueTriples,
) ([]*handler.Endorsement, error) {
	refVals := make([]*handler.Endorsement, 0, len(rvs.Values))

	for _, rv := range rvs.Values {
		// var classAttrs platform.ClassAttributes
		// var refVal *handler.Endorsement
		// var err error

		if o.Profile != "http://example.com/corim/profile" {
			return nil, fmt.Errorf(
				"incorrect profile: %s for Scheme GENERIC_EAT",
				o.Profile,
			)
		}

		// class is not defined
		/*
			if err := classAttrs.FromEnvironment(rv.Environment); err != nil {
				return nil, fmt.Errorf("could not extract PSA class attributes: %w", err)
			}
		*/

		attrs := map[string]interface{}{}

		/* treated as key to find the reference value */
		instanceID, err := rv.Environment.Instance.GetUEID()
		if err != nil {
			return nil, fmt.Errorf("unable to get instance ueid: %w", err)
		}
		attrs["instance-id"] = base64.StdEncoding.EncodeToString(instanceID)

		/* to be compared values, or reference values */
		for _, m := range rv.Measurements.Values {
			if m.Val.Ver != nil {
				// TODO: CoRIM itself doesn't specify the version is for hardware or software
				attrs["version"] = m.Val.Ver
			}
			if m.Val.Digests != nil {
				attrs["digests"] = m.Val.Digests
			}
			// XXX: no member 'name' in Mval
			// if m.Val.Name != nil {
			// 	attrs["name"] = m.Val.Name
			// }
		}

		jsonAttrs, err := json.Marshal(attrs)
		if err != nil {
			return nil, err
		}
		refVal := &handler.Endorsement{
			Scheme:     "GENERIC_EAT",
			Type:       handler.EndorsementType_REFERENCE_VALUE,
			Attributes: jsonAttrs,
		}
		refVals = append(refVals, refVal)
	}

	if len(refVals) == 0 {
		return nil, fmt.Errorf("no software components found")
	}

	return refVals, nil
}

func (o CorimExtractor) TaExtractor(avk comid.KeyTriple) (*handler.Endorsement, error) {
	// extract AK pub
	if len(avk.VerifKeys) != 1 {
		return nil, errors.New("expecting exactly one AK public key")
	}

	akPub := avk.VerifKeys[0]
	if _, ok := akPub.Value.(*comid.TaggedPKIXBase64Key); !ok {
		return nil, fmt.Errorf("AK does not appear to be a PEM key (%T)", akPub.Value)
	}

	instanceID, err := avk.Environment.Instance.GetUEID()
	if err != nil {
		return nil, fmt.Errorf("unable to get instance id: %w", err)
	}

	taAttrsJson := map[string]interface{}{
		"instance-id": instanceID,
		"ak-pub":      akPub.String(),
	}

	taAttrs, err := json.Marshal(taAttrsJson)
	if err != nil {
		return nil, err
	}
	ta := &handler.Endorsement{
		Scheme:     "GENERIC_EAT",
		Type:       handler.EndorsementType_VERIFICATION_KEY,
		Attributes: taAttrs,
	}

	return ta, nil
}

func (o *CorimExtractor) SetProfile(profile string) {
	o.Profile = profile
}
