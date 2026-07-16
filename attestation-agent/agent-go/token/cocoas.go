// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

package token

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	attester "github.com/confidential-containers/guest-components/attestation-agent/attester-go"

	"github.com/confidential-containers/guest-components/attestation-agent/agent-go/config"
)

// CoCoASTokenGetter obtains an attestation token from a CoCo Attestation
// Service.
type CoCoASTokenGetter struct {
	asURI  string
	client *http.Client
}

// NewCoCoAS builds a CoCoASTokenGetter from config, mirroring the Rust
// CoCoASTokenGetter::new: the TRUSTEE_URL environment variable takes precedence
// over the config URL and, when set, points at the trustee gateway (the
// `/attestation-service` path is appended).
func NewCoCoAS(cfg *config.CoCoASConfig) *CoCoASTokenGetter {
	asURI := cfg.URL
	if envURL, ok := os.LookupEnv("TRUSTEE_URL"); ok {
		asURI = envURL + "/attestation-service"
	}
	return &CoCoASTokenGetter{asURI: asURI, client: http.DefaultClient}
}

type verificationRequest struct {
	Tee            string  `json:"tee"`
	Evidence       string  `json:"evidence"`
	AdditionalData *string `json:"additional_data"`
}

type attestationRequest struct {
	VerificationRequests []verificationRequest `json:"verification_requests"`
	PolicyIDs            []string              `json:"policy_ids"`
}

// GetToken collects evidence from the detected TEE and posts it to the
// Attestation Service, returning the token bytes on success. additionalData is
// optional (pass nil for none).
func (g *CoCoASTokenGetter) GetToken(additionalData *string) ([]byte, error) {
	primaryTee := attester.DetectTeeType()
	att, err := attester.New(primaryTee)
	if err != nil {
		return nil, err
	}
	evidence, err := att.GetEvidence(nil)
	if err != nil {
		return nil, err
	}

	request := attestationRequest{
		VerificationRequests: []verificationRequest{{
			Tee:            string(primaryTee),
			Evidence:       base64.RawURLEncoding.EncodeToString(evidence),
			AdditionalData: additionalData,
		}},
		PolicyIDs: policyIDs(),
	}
	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, g.asURI+"/attestation", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey, ok := os.LookupEnv("TRUSTEE_API_KEY"); ok {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Remote Attestation Failed, AS Response: %q", string(respBody))
	}
	return respBody, nil
}

// policyIDs parses COCO_AS_POLICY_ID (comma-separated) into a trimmed,
// non-empty list, matching the Rust behaviour.
func policyIDs() []string {
	raw := os.Getenv("COCO_AS_POLICY_ID")
	ids := []string{}
	for _, s := range strings.Split(raw, ",") {
		if s == "" {
			continue
		}
		ids = append(ids, strings.TrimSpace(s))
	}
	return ids
}
