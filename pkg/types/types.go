// Copyright 2025 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package types

import (
	"fmt"
)

// SBOMFormat represents the logical SBOM schema (not file extension).
type SBOMFormat string

const (
	SBOMFormatCycloneDX SBOMFormat = "cyclonedx"
	SBOMFormatSPDX      SBOMFormat = "spdx"
)

type VulnFormat string

const (
	VulnFormatTrivy VulnFormat = "trivy"
	VulnFormatGrype VulnFormat = "grype"
)

func ParseSBOMFormat(s string) (SBOMFormat, error) {
	switch s {
	case "cyclonedx", "cdx":
		return SBOMFormatCycloneDX, nil
	case "spdx":
		return SBOMFormatSPDX, nil
	default:
		return "", fmt.Errorf("unsupported SBOM format %q (expected cyclonedx or spdx)", s)
	}
}

func ParseVulnFormat(s string) (VulnFormat, error) {
	switch s {
	case "trivy":
		return VulnFormatTrivy, nil
	case "grype":
		return VulnFormatGrype, nil
	default:
		return "", fmt.Errorf("unsupported vuln format %q (expected trivy or grype)", s)
	}
}

// Config holds all user inputs for a single delta evaluation run.
type Config struct {
	UpstreamSBOMPath   string
	UpstreamSBOMFormat SBOMFormat

	HardenedSBOMPath   string
	HardenedSBOMFormat SBOMFormat

	UpstreamVulnPath   string
	UpstreamVulnFormat VulnFormat

	HardenedVulnPath   string
	HardenedVulnFormat VulnFormat

	BackportVulnPath   string
	BackportVulnFormat VulnFormat
}
