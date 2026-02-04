/*
Copyright 2025 The Kubernetes Authors.

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
	"context"
	"fmt"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
)

func TestValidateXBackend(t *testing.T) {
	ctx := context.Background()
	baseBackend := v0alpha0.XBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: metav1.NamespaceDefault,
		},
		Spec: v0alpha0.BackendSpec{
			MCP: v0alpha0.MCPBackend{
				ServiceName: ptrTo("my-service"),
				Port:        8080,
			},
		},
	}

	testCases := []struct {
		desc       string
		mutate     func(b *v0alpha0.XBackend)
		wantErrors []string
	}{
		{
			desc: "valid backend with serviceName",
			mutate: func(b *v0alpha0.XBackend) {
			},
		},
		{
			desc: "valid backend with hostname",
			mutate: func(b *v0alpha0.XBackend) {
				b.Spec.MCP.ServiceName = nil
				b.Spec.MCP.Hostname = ptrTo("example.com")
			},
		},
		{
			desc: "invalid backend with both serviceName and hostname",
			mutate: func(b *v0alpha0.XBackend) {
				b.Spec.MCP.Hostname = ptrTo("example.com")
			},
			wantErrors: []string{"exactly one of the fields in [serviceName hostname] must be set"},
		},
		{
			desc: "invalid backend with neither serviceName nor hostname",
			mutate: func(b *v0alpha0.XBackend) {
				b.Spec.MCP.ServiceName = nil
			},
			wantErrors: []string{"exactly one of the fields in [serviceName hostname] must be set"},
		},
		{
			desc: "invalid port (too small)",
			mutate: func(b *v0alpha0.XBackend) {
				b.Spec.MCP.Port = 0
			},
			wantErrors: []string{"spec.mcp.port in body should be greater than or equal to 1"},
		},
		{
			desc: "invalid port (too large)",
			mutate: func(b *v0alpha0.XBackend) {
				b.Spec.MCP.Port = 65536
			},
			wantErrors: []string{"spec.mcp.port in body should be less than or equal to 65535"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			b := baseBackend.DeepCopy()
			b.Name = fmt.Sprintf("foo-%v", time.Now().UnixNano())

			if tc.mutate != nil {
				tc.mutate(b)
			}
			err := k8sClient.Create(ctx, b)

			if (len(tc.wantErrors) != 0) != (err != nil) {
				t.Fatalf("Unexpected response while creating XBackend; got err=\n%v\n;want error=%v", err, tc.wantErrors != nil)
			}

			if err != nil {
				var missingErrorStrings []string
				for _, wantError := range tc.wantErrors {
					if !celErrorStringMatches(err.Error(), wantError) {
						missingErrorStrings = append(missingErrorStrings, wantError)
					}
				}
				if len(missingErrorStrings) != 0 {
					t.Errorf("Unexpected response while creating XBackend; got err=\n%v\n;missing strings within error=%q", err, missingErrorStrings)
				}
			}
		})
	}
}
