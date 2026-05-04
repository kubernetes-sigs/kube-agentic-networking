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

package crd_test

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"

	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	"sigs.k8s.io/kube-agentic-networking/api/v1alpha1"
)

func TestCRDValidation(t *testing.T) {
	scheme := runtime.NewScheme()
	var testEnv *envtest.Environment
	var err error

	var kubectlLocation, kubeconfigLocation string

	utilruntime.Must(v0alpha0.Install(scheme))
	utilruntime.Must(v1alpha1.Install(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))

	k8sVersion := os.Getenv("K8S_VERSION")

	t.Run("should be able to start test environment", func(_ *testing.T) {
		// TODO: Revert to standard envtest.CRDInstallOptions{Paths: []string{...}} once XAccessPolicy v1alpha1 is fully implemented and flipped to `served: true` in manifests.
		var crds []*apiextensionsv1.CustomResourceDefinition
		crds, err = loadAndModifyCRDs(filepath.Join("..", "..", "k8s", "crds"))
		if err != nil {
			panic(fmt.Sprintf("Failed to load and modify CRDs: %v", err))
		}

		testEnv = &envtest.Environment{
			Scheme:                      scheme,
			CRDs:                        crds,
			ErrorIfCRDPathMissing:       true,
			DownloadBinaryAssets:        true,
			DownloadBinaryAssetsVersion: k8sVersion,
		}

		_, err = testEnv.Start()
		if err != nil {
			panic(fmt.Sprintf("Error initializing test environment: %v", err))
		}
	})

	t.Cleanup(func() {
		require.NoError(t, testEnv.Stop())
	})

	t.Run("should be able to set kubectl and kubeconfig and connect to the cluster", func(t *testing.T) {
		kubectlLocation = testEnv.ControlPlane.KubectlPath
		require.NotEmpty(t, kubectlLocation)

		kubeconfigLocation = fmt.Sprintf("%s/kubeconfig", filepath.Dir(kubectlLocation))
		require.NoError(t, os.WriteFile(kubeconfigLocation, testEnv.KubeConfig, 0o600))

		apiResources, err := executeKubectlCommand(t, kubectlLocation, kubeconfigLocation, []string{"api-resources"})
		require.NoError(t, err)
		require.Contains(t, apiResources, "agentic.networking.x-k8s.io/v0alpha0")
		require.Contains(t, apiResources, "agentic.networking.x-k8s.io/v1alpha1")
	})

	t.Run("should be able to install valid examples", func(t *testing.T) {
		output, err := executeKubectlCommand(t, kubectlLocation, kubeconfigLocation, []string{"apply", "--recursive", "-f", filepath.Join("examples", "valid")})
		assert.NoError(t, err, "output", output)
	})

	t.Run("should expect an error in case of validation failure", func(t *testing.T) {
		files, err := getInvalidExamplesFiles(t)
		require.NoError(t, err)

		for _, example := range files {
			t.Run(fmt.Sprintf("validate example %s", example), func(t *testing.T) {
				output, err := executeKubectlCommand(t, kubectlLocation, kubeconfigLocation, []string{"apply", "-f", example})
				require.Error(t, err)
				assert.True(t, expectedValidationError(output), "output does not contain the expected error", output)
			})
		}
	})
}

func expectedValidationError(cmdoutput string) bool {
	return strings.Contains(cmdoutput, "is invalid") ||
		strings.Contains(cmdoutput, "missing required field") ||
		strings.Contains(cmdoutput, "denied request") ||
		strings.Contains(cmdoutput, "Invalid value")
}

func executeKubectlCommand(t *testing.T, kubectl, kubeconfig string, args []string) (string, error) {
	t.Helper()

	cacheDir := filepath.Dir(kubeconfig)
	args = append([]string{"--cache-dir", cacheDir}, args...)

	cmd := exec.CommandContext(t.Context(), kubectl, args...)
	cmd.Env = []string{
		fmt.Sprintf("KUBECONFIG=%s", kubeconfig),
	}

	output, err := cmd.CombinedOutput()
	return string(output), err
}

func getInvalidExamplesFiles(t *testing.T) ([]string, error) {
	t.Helper()

	var files []string
	err := filepath.WalkDir(filepath.Join("examples", "invalid"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() && filepath.Ext(path) == ".yaml" {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func loadAndModifyCRDs(dir string) ([]*apiextensionsv1.CustomResourceDefinition, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var crds []*apiextensionsv1.CustomResourceDefinition
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".yaml") {
			continue
		}

		path := filepath.Join(dir, file.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}

		crd := &apiextensionsv1.CustomResourceDefinition{}
		if err := yaml.Unmarshal(data, crd); err != nil {
			return nil, fmt.Errorf("failed to unmarshal CRD from %s: %w", path, err)
		}

		// If this is the XAccessPolicy CRD, activate v1alpha1 for testing validation
		if crd.Name == "xaccesspolicies.agentic.networking.x-k8s.io" {
			for i, version := range crd.Spec.Versions {
				if version.Name == "v1alpha1" {
					crd.Spec.Versions[i].Served = true
				}
			}
		}

		crds = append(crds, crd)
	}

	return crds, nil
}
