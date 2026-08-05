// Copyright 2022 Jeremy Edwards
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

package certtool

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// HierarchyNode defines a single certificate in a hierarchy tree.
type HierarchyNode struct {
	CN                 string          `yaml:"commonName"`
	CA                 bool            `yaml:"certificateAuthority,omitempty"`
	KeyType            string          `yaml:"keyType,omitempty"`
	Validity           string          `yaml:"validity,omitempty"`
	Organization       string          `yaml:"organization,omitempty"`
	OrganizationalUnit string          `yaml:"organizationalUnit,omitempty"`
	Country            string          `yaml:"country,omitempty"`
	Locality           string          `yaml:"locality,omitempty"`
	Province           string          `yaml:"province,omitempty"`
	Hostnames          []string        `yaml:"hostnames,omitempty"`
	Ports              []int           `yaml:"ports,omitempty"`
	Filename           string          `yaml:"filename,omitempty"`
	Children           []HierarchyNode `yaml:"children,omitempty"`
}

// HierarchyOutput is the result of generating a single certificate in a hierarchy.
type HierarchyOutput struct {
	CN       string
	KeyPair  *KeyPair
	CertPath string
	KeyPath  string
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func slugify(s string) string {
	s = strings.ToLower(s)
	s = slugRe.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	return s
}

func buildFilename(ancestorCNs []string, node *HierarchyNode) string {
	if node.Filename != "" {
		return node.Filename
	}
	parts := make([]string, 0, len(ancestorCNs)+1)
	for _, cn := range ancestorCNs {
		parts = append(parts, slugify(cn))
	}
	parts = append(parts, slugify(node.CN))
	return strings.Join(parts, "-")
}

// ParseHierarchyFile reads and validates a YAML hierarchy definition.
func ParseHierarchyFile(path string) ([]HierarchyNode, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("cannot read hierarchy file (%s): %w", path, err)
	}
	return ParseHierarchy(data)
}

// ParseHierarchy parses and validates a YAML hierarchy definition from bytes.
func ParseHierarchy(data []byte) ([]HierarchyNode, error) {
	var nodes []HierarchyNode
	if err := yaml.Unmarshal(data, &nodes); err != nil {
		return nil, fmt.Errorf("cannot parse hierarchy YAML: %w", err)
	}

	if len(nodes) != 1 {
		return nil, fmt.Errorf("hierarchy must have exactly one root node, got %d", len(nodes))
	}
	if !nodes[0].CA {
		return nil, fmt.Errorf("root node %q must have certificateAuthority: true", nodes[0].CN)
	}

	if err := validateNode(&nodes[0]); err != nil {
		return nil, err
	}

	return nodes, nil
}

func validateNode(node *HierarchyNode) error {
	if node.CN == "" {
		return fmt.Errorf("every hierarchy node must have a commonName field")
	}
	if len(node.Children) > 0 && !node.CA {
		return fmt.Errorf("node %q has children but certificateAuthority is not true", node.CN)
	}
	for i := range node.Children {
		if err := validateNode(&node.Children[i]); err != nil {
			return err
		}
	}
	return nil
}

// ApplyDefaults fills empty fields on all nodes from the provided defaults.
func ApplyDefaults(nodes []HierarchyNode, defaults *Args) []HierarchyNode {
	if defaults == nil {
		return nodes
	}
	result := make([]HierarchyNode, len(nodes))
	copy(result, nodes)
	for i := range result {
		applyDefaultsToNode(&result[i], defaults)
	}
	return result
}

func applyDefaultsToNode(node *HierarchyNode, defaults *Args) {
	if node.Organization == "" {
		node.Organization = defaults.Organization
	}
	if node.Country == "" {
		node.Country = defaults.Country
	}
	if node.OrganizationalUnit == "" {
		node.OrganizationalUnit = defaults.OrganizationalUnit
	}
	if node.Locality == "" {
		node.Locality = defaults.Locality
	}
	if node.Province == "" {
		node.Province = defaults.Province
	}
	if node.Validity == "" && defaults.Validity > 0 {
		node.Validity = defaults.Validity.String()
	}
	if node.KeyType == "" && defaults.KeyType != nil {
		node.KeyType = fmt.Sprintf("%s-%d", defaults.KeyType.Algorithm, defaults.KeyType.KeyLength)
	}
	for i := range node.Children {
		applyDefaultsToNode(&node.Children[i], defaults)
	}
}

// MarshalSpec serializes hierarchy nodes to YAML.
func MarshalSpec(nodes []HierarchyNode) ([]byte, error) {
	return yaml.Marshal(nodes)
}

// GenerateHierarchy generates certificates for all nodes in the hierarchy tree.
func GenerateHierarchy(nodes []HierarchyNode, outputDir string, parentKP *KeyPair) ([]HierarchyOutput, error) {
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		return nil, fmt.Errorf("cannot create output directory (%s): %w", outputDir, err)
	}

	filenames := map[string]string{}
	var results []HierarchyOutput

	for i := range nodes {
		out, err := generateNode(&nodes[i], parentKP, outputDir, nil, filenames)
		if err != nil {
			return nil, err
		}
		results = append(results, out...)
	}
	return results, nil
}

func generateNode(node *HierarchyNode, parentKP *KeyPair, outputDir string, ancestorCNs []string, filenames map[string]string) ([]HierarchyOutput, error) {
	args := nodeToArgs(node)
	args.ParentKeyPair = parentKP

	kp, err := GenerateKeyPair(args)
	if err != nil {
		return nil, fmt.Errorf("cannot generate certificate for %q: %w", node.CN, err)
	}

	basename := buildFilename(ancestorCNs, node)
	certPath := filepath.Join(outputDir, basename+".cert")
	keyPath := filepath.Join(outputDir, basename+".key")

	if existingCN, ok := filenames[basename]; ok {
		return nil, fmt.Errorf("filename collision: %q and %q both resolve to %q", existingCN, node.CN, basename)
	}
	filenames[basename] = node.CN

	if err := WriteKeyPair(kp, certPath, keyPath); err != nil {
		return nil, fmt.Errorf("cannot write certificate for %q: %w", node.CN, err)
	}

	results := []HierarchyOutput{{
		CN:       node.CN,
		KeyPair:  kp,
		CertPath: certPath,
		KeyPath:  keyPath,
	}}

	childAncestors := append(append([]string{}, ancestorCNs...), node.CN)
	for i := range node.Children {
		childResults, err := generateNode(&node.Children[i], kp, outputDir, childAncestors, filenames)
		if err != nil {
			return nil, err
		}
		results = append(results, childResults...)
	}

	return results, nil
}

func nodeToArgs(node *HierarchyNode) *Args {
	args := &Args{
		CA:                 node.CA,
		CommonName:         node.CN,
		Organization:       node.Organization,
		OrganizationalUnit: node.OrganizationalUnit,
		Country:            node.Country,
		Locality:           node.Locality,
		Province:           node.Province,
		Hostnames:          node.Hostnames,
		Ports:              node.Ports,
	}

	if node.Validity != "" {
		if d, err := time.ParseDuration(node.Validity); err == nil {
			args.Validity = d
		}
	}

	if node.KeyType != "" {
		parts := strings.SplitN(strings.ToUpper(node.KeyType), "-", 2)
		if len(parts) == 2 {
			var keyLen int
			if _, err := fmt.Sscanf(parts[1], "%d", &keyLen); err == nil {
				args.KeyType = &KeyType{Algorithm: parts[0], KeyLength: keyLen}
			}
		} else if len(parts) == 1 {
			args.KeyType = &KeyType{Algorithm: parts[0]}
		}
	}

	return args
}

// ChainToHierarchy converts a --chain N invocation into a hierarchy tree.
func ChainToHierarchy(depth int, args *Args) ([]HierarchyNode, error) {
	if depth < 2 {
		return nil, fmt.Errorf("--chain must be at least 2 (root CA + leaf), got %d", depth)
	}

	org := args.Organization
	if org == "" {
		org = defaultOrganization
	}

	leaf := HierarchyNode{
		CN:        args.CommonName,
		CA:        false,
		Hostnames: args.Hostnames,
		Ports:     args.Ports,
	}
	if leaf.CN == "" {
		leaf.CN = org
	}

	current := leaf
	for i := depth - 2; i >= 1; i-- {
		current = HierarchyNode{
			CN:       fmt.Sprintf("%s Intermediate CA %d", org, i),
			CA:       true,
			Children: []HierarchyNode{current},
		}
	}

	root := HierarchyNode{
		CN:       fmt.Sprintf("%s Root CA", org),
		CA:       true,
		Children: []HierarchyNode{current},
	}

	return []HierarchyNode{root}, nil
}
