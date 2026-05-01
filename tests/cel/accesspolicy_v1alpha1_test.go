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

	"sigs.k8s.io/kube-agentic-networking/api/v1alpha1"
)

func TestValidateXAccessPolicyV1Alpha1(t *testing.T) {
	ctx := context.Background()
	basePolicy := v1alpha1.XAccessPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo-v1alpha1",
			Namespace: metav1.NamespaceDefault,
		},
		Spec: v1alpha1.AccessPolicySpec{
			TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{
				{
					LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{
						Group: "gateway.networking.k8s.io",
						Kind:  "Gateway",
						Name:  "my-gateway",
					},
				},
			},
			Action: v1alpha1.ActionTypeAllow,
			Rules: []v1alpha1.AccessRule{
				{
					Name: "rule-1",
					Source: v1alpha1.AccessRuleSource{
						Type: v1alpha1.AuthorizationSourceTypeServiceAccount,
						ServiceAccount: &v1alpha1.AuthorizationSourceServiceAccount{
							Name: "sa-1",
						},
					},
				},
			},
		},
	}

	testCases := []struct {
		desc       string
		mutate     func(p *v1alpha1.XAccessPolicy)
		wantErrors []string
	}{
		{
			desc: "valid policy with Allow action",
			mutate: func(_ *v1alpha1.XAccessPolicy) {
			},
		},
		{
			desc: "heterogeneous target kinds",
			mutate: func(p *v1alpha1.XAccessPolicy) {
				p.Spec.TargetRefs = append(p.Spec.TargetRefs, gwapiv1.LocalPolicyTargetReferenceWithSectionName{
					LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{
						Group: "agentic.networking.x-k8s.io",
						Kind:  "XBackend",
						Name:  "my-backend",
					},
				})
			},
			wantErrors: []string{"All targetRefs must have the same Kind"},
		},
		{
			desc: "valid policy with ExternalAuth action",
			mutate: func(p *v1alpha1.XAccessPolicy) {
				p.Spec.Action = v1alpha1.ActionTypeExternalAuth
				p.Spec.ExternalAuth = &gwapiv1.HTTPExternalAuthFilter{
					ExternalAuthProtocol: gwapiv1.HTTPRouteExternalAuthGRPCProtocol,
					BackendRef: gwapiv1.BackendObjectReference{
						Name: "ext-auth-svc",
						Port: ptrTo(gwapiv1.PortNumber(50051)),
					},
					GRPCAuthConfig: &gwapiv1.GRPCAuthConfig{},
				}
			},
		},
		{
			desc: "missing externalAuth when Action is ExternalAuth",
			mutate: func(p *v1alpha1.XAccessPolicy) {
				p.Spec.Action = v1alpha1.ActionTypeExternalAuth
			},
			wantErrors: []string{"externalAuth must be specified when action is set to 'ExternalAuth'"},
		},
		{
			desc: "duplicate rule names",
			mutate: func(p *v1alpha1.XAccessPolicy) {
				p.Spec.Rules = append(p.Spec.Rules, v1alpha1.AccessRule{
					Name: "rule-1",
					Source: v1alpha1.AccessRuleSource{
						Type: v1alpha1.AuthorizationSourceTypeServiceAccount,
						ServiceAccount: &v1alpha1.AuthorizationSourceServiceAccount{
							Name: "sa-2",
						},
					},
				})
			},
			wantErrors: []string{"AccessRule names must be unique"},
		},
		{
			desc: "invalid SPIFFE ID pattern",
			mutate: func(p *v1alpha1.XAccessPolicy) {
				spiffe := v1alpha1.AuthorizationSourceSPIFFE("not-a-spiffe-id")
				p.Spec.Rules[0].Source = v1alpha1.AccessRuleSource{
					Type:   v1alpha1.AuthorizationSourceTypeSPIFFE,
					SPIFFE: &spiffe,
				}
			},
			wantErrors: []string{"spec.rules[0].source.spiffe in body should match '^spiffe://[a-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$'"},
		},
		{
			desc: "valid SPIFFE ID",
			mutate: func(p *v1alpha1.XAccessPolicy) {
				spiffe := v1alpha1.AuthorizationSourceSPIFFE("spiffe://trust.domain/workload")
				p.Spec.Rules[0].Source = v1alpha1.AccessRuleSource{
					Type:   v1alpha1.AuthorizationSourceTypeSPIFFE,
					SPIFFE: &spiffe,
				}
			},
		},
		{
			desc: "rule name too long",
			mutate: func(p *v1alpha1.XAccessPolicy) {
				p.Spec.Rules[0].Name = strings.Repeat("a", 254)
			},
			wantErrors: []string{"may not be more than 253 bytes"},
		},
		{
			desc: "too many targets",
			mutate: func(p *v1alpha1.XAccessPolicy) {
				for i := 0; i < 10; i++ {
					p.Spec.TargetRefs = append(p.Spec.TargetRefs, gwapiv1.LocalPolicyTargetReferenceWithSectionName{
						LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{
							Group: "gateway.networking.k8s.io",
							Kind:  "Gateway",
							Name:  "my-gateway",
						},
					})
				}
			},
			wantErrors: []string{"must have at most 10 items"},
		},
		{
			desc: "too many rules",
			mutate: func(p *v1alpha1.XAccessPolicy) {
				for i := 0; i < 10; i++ {
					p.Spec.Rules = append(p.Spec.Rules, v1alpha1.AccessRule{
						Name: fmt.Sprintf("rule-%d", i+2),
						Source: v1alpha1.AccessRuleSource{
							Type: v1alpha1.AuthorizationSourceTypeServiceAccount,
							ServiceAccount: &v1alpha1.AuthorizationSourceServiceAccount{
								Name: "sa-1",
							},
						},
					})
				}
			},
			wantErrors: []string{"must have at most 10 items"},
		},
		{
			desc: "valid MCP method attributes with Inline type",
			mutate: func(p *v1alpha1.XAccessPolicy) {
				p.Spec.Rules[0].Authorization = &v1alpha1.AuthorizationRule{
					Type: v1alpha1.AuthorizationRuleTypeInline,
					MCP: v1alpha1.MCPAttributes{
						Methods: []v1alpha1.MCPMethod{
							{
								Name: "tools/call",
								Params: []v1alpha1.MCPMethodParam{
									"param1",
								},
							},
						},
					},
				}
			},
		},
		{
			desc: "invalid MCP method with params on prompts/list",
			mutate: func(p *v1alpha1.XAccessPolicy) {
				p.Spec.Rules[0].Authorization = &v1alpha1.AuthorizationRule{
					Type: v1alpha1.AuthorizationRuleTypeInline,
					MCP: v1alpha1.MCPAttributes{
						Methods: []v1alpha1.MCPMethod{
							{
								Name: "prompts/list",
								Params: []v1alpha1.MCPMethodParam{
									"param1",
								},
							},
						},
					},
				}
			},
			wantErrors: []string{"Params can only be specified for get, call, subscribe, unsubscribe, or read methods"},
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
