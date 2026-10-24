package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
)

// SPDX 2.3 SBOM 構造体 (抜粋)
type SPDXDocument struct {
	SPDXVersion string        `json:"spdxVersion"`
	Name        string        `json:"name"`
	Packages    []SPDXPackage `json:"packages"`
}

type SPDXPackage struct {
	Name             string `json:"name"`
	VersionInfo      string `json:"versionInfo"`
	LicenseConcluded string `json:"licenseConcluded"`
	LicenseDeclared  string `json:"licenseDeclared"`
	ExternalRefs     []struct {
		ReferenceCategory string `json:"referenceCategory"`
		ReferenceType     string `json:"referenceType"`
		ReferenceLocator  string `json:"referenceLocator"`
	} `json:"externalRefs"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run sbom_inspector.go <path-to-sbom.spdx.json>")
		os.Exit(1)
	}

	filePath := os.Args[1]
	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading SBOM file: %v\n", err)
		os.Exit(1)
	}

	var doc SPDXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing SPDX JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("================================================================================")
	fmt.Printf("📦 SBOM Software Bill of Materials Inspection Report\n")
	fmt.Printf("   Specification : %s\n", doc.SPDXVersion)
	fmt.Printf("   Target Image  : %s\n", doc.Name)
	fmt.Printf("   Total Packages: %d\n", len(doc.Packages))
	fmt.Println("================================================================================")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "PACKAGE NAME\tVERSION\tLICENSE\tPACKAGE URL (PURL)")
	fmt.Fprintln(w, "------------\t-------\t-------\t------------------")

	for _, pkg := range doc.Packages {
		license := pkg.LicenseConcluded
		if license == "" || license == "NOASSERTION" {
			license = pkg.LicenseDeclared
		}
		if license == "" || license == "NOASSERTION" {
			license = "UNKNOWN"
		}

		purl := "N/A"
		for _, ref := range pkg.ExternalRefs {
			if strings.EqualFold(ref.ReferenceType, "purl") {
				purl = ref.ReferenceLocator
				break
			}
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", pkg.Name, pkg.VersionInfo, license, purl)
	}
	_ = w.Flush()
	fmt.Println("================================================================================")
}
