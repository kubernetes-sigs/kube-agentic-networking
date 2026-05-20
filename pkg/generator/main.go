/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"fmt"
	"os"
	"path/filepath"

	v1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-tools/pkg/crd"
	"sigs.k8s.io/controller-tools/pkg/loader"
	"sigs.k8s.io/controller-tools/pkg/markers"
	"sigs.k8s.io/yaml"

	"sigs.k8s.io/kube-agentic-networking/version"
)

func main() {
	roots, err := loader.LoadRoots("./api/...")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load roots: %v\n", err)
		os.Exit(1)
	}

	registry := &markers.Registry{}
	if err := (crd.Generator{}).RegisterMarkers(registry); err != nil {
		fmt.Fprintf(os.Stderr, "failed to register markers: %v\n", err)
		os.Exit(1)
	}

	parser := &crd.Parser{
		Collector: &markers.Collector{
			Registry: registry,
		},
		Checker: &loader.TypeChecker{},
	}

	for _, pkg := range roots {
		parser.NeedPackage(pkg)
	}

	gks := []schema.GroupKind{
		{Group: "agentic.networking.x-k8s.io", Kind: "XAccessPolicy"},
		{Group: "agentic.networking.x-k8s.io", Kind: "XBackend"},
	}

	for _, gk := range gks {
		parser.NeedCRDFor(gk, nil)
	}

	crds := parser.CustomResourceDefinitions
	if len(crds) == 0 {
		fmt.Println("No CRDs generated.")
		return
	}

	outDir := "k8s/crds"
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	for gk, obj := range crds {
		if obj.Annotations == nil {
			obj.Annotations = make(map[string]string)
		}
		if gk.Group == "agentic.networking.x-k8s.io" && gk.Kind == "XAccessPolicy" {
			obj.Annotations["agentic.networking.x-k8s.io/bundle-version"] = version.BundleVersion
		}

		// Fix top level metadata to be compliant with K8s structural schema
		crd.FixTopLevelMetadata(obj)

		// Fix date-time fields in schema
		for i := range obj.Spec.Versions {
			v := &obj.Spec.Versions[i]
			if v.Schema != nil && v.Schema.OpenAPIV3Schema != nil {
				fixDateTime(v.Schema.OpenAPIV3Schema)
			}
		}

		yamlData, err := yaml.Marshal(obj)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to marshal CRD %v: %v\n", gk, err)
			os.Exit(1)
		}

		plural := obj.Spec.Names.Plural
		fileName := fmt.Sprintf("%s_%s.yaml", gk.Group, plural)

		filePath := filepath.Join(outDir, fileName)
		err = os.WriteFile(filePath, yamlData, 0o600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to write CRD file %s: %v\n", filePath, err)
			os.Exit(1)
		}
		fmt.Printf("Generated %s\n", filePath)
	}
}

func fixDateTime(schema *v1.JSONSchemaProps) {
	if schema == nil {
		return
	}
	if schema.Format == "date-time" {
		// TODO(liorlieberman): Figure out why crdgen switched this to "object"
		schema.Type = "string"
	}
	for k, v := range schema.Properties {
		fixDateTime(&v)
		schema.Properties[k] = v
	}
	if schema.Items != nil {
		if schema.Items.Schema != nil {
			fixDateTime(schema.Items.Schema)
		}
		for i, v := range schema.Items.JSONSchemas {
			fixDateTime(&v)
			schema.Items.JSONSchemas[i] = v
		}
	}
}
