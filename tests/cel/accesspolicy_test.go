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
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
)

func TestValidateXAccessPolicy(t *testing.T) {
	ctx := context.Background()
	basePolicy := v0alpha0.XAccessPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: metav1.NamespaceDefault,
		},
		Spec: v0alpha0.AccessPolicySpec{
			TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{
				{
					LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{
						Group: "agentic.prototype.x-k8s.io",
						Kind:  "XBackend",
						Name:  "my-backend",
					},
				},
			},
			Rules: []v0alpha0.AccessRule{
				{
					Name: "rule-1",
					Source: v0alpha0.Source{
						Type: v0alpha0.AuthorizationSourceTypeServiceAccount,
						ServiceAccount: &v0alpha0.AuthorizationSourceServiceAccount{
							Name: "sa-1",
						},
					},
				},
			},
		},
	}

	testCases := []struct {
		desc       string
		mutate     func(p *v0alpha0.XAccessPolicy)
		wantErrors []string
	}{
		{
			desc: "valid policy",
			mutate: func(p *v0alpha0.XAccessPolicy) {
			},
		},
		{
			desc: "invalid target group",
			mutate: func(p *v0alpha0.XAccessPolicy) {
				p.Spec.TargetRefs[0].Group = "wrong.group"
			},
			wantErrors: []string{"TargetRef must have group agentic.prototype.x-k8s.io group and kind XBackend"},
		},
		{
			desc: "invalid target kind",
			mutate: func(p *v0alpha0.XAccessPolicy) {
				p.Spec.TargetRefs[0].Kind = "WrongKind"
			},
			wantErrors: []string{"TargetRef must have group agentic.prototype.x-k8s.io group and kind XBackend"},
		},
		{
			desc: "duplicate rule names",
			mutate: func(p *v0alpha0.XAccessPolicy) {
				p.Spec.Rules = append(p.Spec.Rules, v0alpha0.AccessRule{
					Name: "rule-1",
					Source: v0alpha0.Source{
						Type: v0alpha0.AuthorizationSourceTypeServiceAccount,
						ServiceAccount: &v0alpha0.AuthorizationSourceServiceAccount{
							Name: "sa-2",
						},
					},
				})
			},
			wantErrors: []string{"AccessRule names must be unique"},
		},
		{
			desc: "invalid SPIFFE ID pattern",
			mutate: func(p *v0alpha0.XAccessPolicy) {
				spiffe := v0alpha0.AuthorizationSourceSPIFFE("not-a-spiffe-id")
				p.Spec.Rules[0].Source = v0alpha0.Source{
					Type:   v0alpha0.AuthorizationSourceTypeSPIFFE,
					SPIFFE: &spiffe,
				}
			},
			wantErrors: []string{"spec.rules[0].source.spiffe in body should match '^spiffe://[a-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$'"},
		},
		{
			desc: "valid SPIFFE ID",
			mutate: func(p *v0alpha0.XAccessPolicy) {
				spiffe := v0alpha0.AuthorizationSourceSPIFFE("spiffe://trust.domain/workload")
				p.Spec.Rules[0].Source = v0alpha0.Source{
					Type:   v0alpha0.AuthorizationSourceTypeSPIFFE,
					SPIFFE: &spiffe,
				}
			},
		},
		{
			desc: "rule name too long",
			mutate: func(p *v0alpha0.XAccessPolicy) {
				p.Spec.Rules[0].Name = strings.Repeat("a", 254)
			},
			wantErrors: []string{"may not be more than 253 bytes"},
		},
		{
			desc: "too many targets",
			mutate: func(p *v0alpha0.XAccessPolicy) {
				// add 10 more targets, total 11 targets.
				for i := 0; i < 10; i++ {
					p.Spec.TargetRefs = append(p.Spec.TargetRefs, gwapiv1.LocalPolicyTargetReferenceWithSectionName{
						LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{
							Group: "agentic.prototype.x-k8s.io",
							Kind:  "XBackend",
							Name:  "my-backend",
						},
					})
				}
			},
			wantErrors: []string{"must have at most 10 items"},
		},
		{
			desc: "too many rules",
			mutate: func(p *v0alpha0.XAccessPolicy) {
				// add 10 more rules, total 11 rules.
				for i := 0; i < 10; i++ {
					p.Spec.Rules = append(p.Spec.Rules, v0alpha0.AccessRule{
						Name: fmt.Sprintf("rule-%d", i+2),
						Source: v0alpha0.Source{
							Type: v0alpha0.AuthorizationSourceTypeServiceAccount,
							ServiceAccount: &v0alpha0.AuthorizationSourceServiceAccount{
								Name: "sa-1",
							},
						},
					})
				}
			},
			wantErrors: []string{"must have at most 10 items"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {

			p := basePolicy.DeepCopy()
			p.Name = fmt.Sprintf("foo-%v", time.Now().UnixNano())

			if tc.mutate != nil {
				tc.mutate(p)
			}
			err := k8sClient.Create(ctx, p)

			if (len(tc.wantErrors) != 0) != (err != nil) {
				t.Fatalf("Unexpected response while creating XAccessPolicy; got err=\n%v\n;want error=%v", err, tc.wantErrors != nil)
			}

			if err != nil {
				var missingErrorStrings []string
				for _, wantError := range tc.wantErrors {
					if !celErrorStringMatches(err.Error(), wantError) {
						missingErrorStrings = append(missingErrorStrings, wantError)
					}
				}
				if len(missingErrorStrings) != 0 {
					t.Errorf("Unexpected response while creating XAccessPolicy; got err=\n%v\n;missing strings within error=%q", err, missingErrorStrings)
				}
			}
		})
	}
}
