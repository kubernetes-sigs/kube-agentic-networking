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

package controller

import (
	"context"
	"reflect"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayclientfake "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/fake"
	gatewayinformers "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions"

	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	agenticclient "sigs.k8s.io/kube-agentic-networking/k8s/client/clientset/versioned/fake"
	agenticinformers "sigs.k8s.io/kube-agentic-networking/k8s/client/informers/externalversions"
	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
	"sigs.k8s.io/kube-agentic-networking/pkg/translator"
)

func TestIsPolicyUnderTargetLimit(t *testing.T) {
	ns := "test-ns"
	now := metav1.Now()
	earlier := metav1.NewTime(now.Add(-1 * time.Hour))

	tests := []struct {
		name          string
		existing      []runtime.Object
		currentPolicy *agenticv0alpha0.XAccessPolicy
		wantAccepted  bool
	}{
		{
			name: "under limit - single target",
			existing: []runtime.Object{
				&agenticv0alpha0.XAccessPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "policy-1", Namespace: ns, CreationTimestamp: earlier},
					Spec: agenticv0alpha0.AccessPolicySpec{
						TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{
							LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{
								Group: gwapiv1.Group(agenticv0alpha0.GroupName),
								Kind:  "XBackend",
								Name:  "target-a",
							},
						}},
					},
				},
			},
			currentPolicy: &agenticv0alpha0.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "policy-2", Namespace: ns, CreationTimestamp: now},
				Spec: agenticv0alpha0.AccessPolicySpec{
					TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{
						LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{
							Group: gwapiv1.Group(agenticv0alpha0.GroupName),
							Kind:  "XBackend",
							Name:  "target-a",
						},
					}},
				},
			},
			wantAccepted: true,
		},
		{
			name: "over limit - rejected",
			existing: []runtime.Object{
				&agenticv0alpha0.XAccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: ns, CreationTimestamp: earlier}, Spec: agenticv0alpha0.AccessPolicySpec{TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{Group: gwapiv1.Group(agenticv0alpha0.GroupName), Kind: "XBackend", Name: "target-a"}}}}},
				&agenticv0alpha0.XAccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p2", Namespace: ns, CreationTimestamp: earlier}, Spec: agenticv0alpha0.AccessPolicySpec{TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{Group: gwapiv1.Group(agenticv0alpha0.GroupName), Kind: "XBackend", Name: "target-a"}}}}},
				&agenticv0alpha0.XAccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p3", Namespace: ns, CreationTimestamp: earlier}, Spec: agenticv0alpha0.AccessPolicySpec{TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{Group: gwapiv1.Group(agenticv0alpha0.GroupName), Kind: "XBackend", Name: "target-a"}}}}},
				&agenticv0alpha0.XAccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p4", Namespace: ns, CreationTimestamp: earlier}, Spec: agenticv0alpha0.AccessPolicySpec{TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{Group: gwapiv1.Group(agenticv0alpha0.GroupName), Kind: "XBackend", Name: "target-a"}}}}},
				&agenticv0alpha0.XAccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p5", Namespace: ns, CreationTimestamp: earlier}, Spec: agenticv0alpha0.AccessPolicySpec{TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{Group: gwapiv1.Group(agenticv0alpha0.GroupName), Kind: "XBackend", Name: "target-a"}}}}},
			},
			currentPolicy: &agenticv0alpha0.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "policy-new", Namespace: ns, CreationTimestamp: now},
				Spec: agenticv0alpha0.AccessPolicySpec{
					TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{
						LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{
							Group: gwapiv1.Group(agenticv0alpha0.GroupName),
							Kind:  "XBackend",
							Name:  "target-a",
						},
					}},
				},
			},
			wantAccepted: false,
		},
		{
			name: "over limit - seniority rules (current is older)",
			existing: []runtime.Object{
				&agenticv0alpha0.XAccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: ns, CreationTimestamp: now}, Spec: agenticv0alpha0.AccessPolicySpec{TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{Group: gwapiv1.Group(agenticv0alpha0.GroupName), Kind: "XBackend", Name: "target-a"}}}}},
				&agenticv0alpha0.XAccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p2", Namespace: ns, CreationTimestamp: now}, Spec: agenticv0alpha0.AccessPolicySpec{TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{Group: gwapiv1.Group(agenticv0alpha0.GroupName), Kind: "XBackend", Name: "target-a"}}}}},
				&agenticv0alpha0.XAccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p3", Namespace: ns, CreationTimestamp: now}, Spec: agenticv0alpha0.AccessPolicySpec{TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{Group: gwapiv1.Group(agenticv0alpha0.GroupName), Kind: "XBackend", Name: "target-a"}}}}},
				&agenticv0alpha0.XAccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p4", Namespace: ns, CreationTimestamp: now}, Spec: agenticv0alpha0.AccessPolicySpec{TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{Group: gwapiv1.Group(agenticv0alpha0.GroupName), Kind: "XBackend", Name: "target-a"}}}}},
				&agenticv0alpha0.XAccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p5", Namespace: ns, CreationTimestamp: now}, Spec: agenticv0alpha0.AccessPolicySpec{TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{Group: gwapiv1.Group(agenticv0alpha0.GroupName), Kind: "XBackend", Name: "target-a"}}}}},
			},
			currentPolicy: &agenticv0alpha0.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "policy-old", Namespace: ns, CreationTimestamp: earlier},
				Spec: agenticv0alpha0.AccessPolicySpec{
					TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{
						LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{
							Group: gwapiv1.Group(agenticv0alpha0.GroupName),
							Kind:  "XBackend",
							Name:  "target-a",
						},
					}},
				},
			},
			wantAccepted: true,
		},
		{
			name: "multiple targets - one over limit fails all",
			existing: []runtime.Object{
				&agenticv0alpha0.XAccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: ns, CreationTimestamp: earlier}, Spec: agenticv0alpha0.AccessPolicySpec{TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{Group: gwapiv1.Group(agenticv0alpha0.GroupName), Kind: "XBackend", Name: "target-full"}}}}},
				&agenticv0alpha0.XAccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p2", Namespace: ns, CreationTimestamp: earlier}, Spec: agenticv0alpha0.AccessPolicySpec{TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{Group: gwapiv1.Group(agenticv0alpha0.GroupName), Kind: "XBackend", Name: "target-full"}}}}},
				&agenticv0alpha0.XAccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p3", Namespace: ns, CreationTimestamp: earlier}, Spec: agenticv0alpha0.AccessPolicySpec{TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{Group: gwapiv1.Group(agenticv0alpha0.GroupName), Kind: "XBackend", Name: "target-full"}}}}},
				&agenticv0alpha0.XAccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p4", Namespace: ns, CreationTimestamp: earlier}, Spec: agenticv0alpha0.AccessPolicySpec{TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{Group: gwapiv1.Group(agenticv0alpha0.GroupName), Kind: "XBackend", Name: "target-full"}}}}},
				&agenticv0alpha0.XAccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p5", Namespace: ns, CreationTimestamp: earlier}, Spec: agenticv0alpha0.AccessPolicySpec{TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{Group: gwapiv1.Group(agenticv0alpha0.GroupName), Kind: "XBackend", Name: "target-full"}}}}},
			},
			currentPolicy: &agenticv0alpha0.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "policy-multi", Namespace: ns, CreationTimestamp: now},
				Spec: agenticv0alpha0.AccessPolicySpec{
					TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{
						{
							LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{
								Group: gwapiv1.Group(agenticv0alpha0.GroupName),
								Kind:  "XBackend",
								Name:  "target-empty",
							},
						},
						{
							LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{
								Group: gwapiv1.Group(agenticv0alpha0.GroupName),
								Kind:  "XBackend",
								Name:  "target-full",
							},
						},
					},
				},
			},
			wantAccepted: false,
		},
		{
			name: "determinism - name tie-breaker",
			existing: []runtime.Object{
				&agenticv0alpha0.XAccessPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "policy-b", Namespace: ns, CreationTimestamp: now},
					Spec: agenticv0alpha0.AccessPolicySpec{
						TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{
							LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{
								Group: gwapiv1.Group(agenticv0alpha0.GroupName),
								Kind:  "XBackend",
								Name:  "target-a",
							},
						}},
					},
				},
			},
			currentPolicy: &agenticv0alpha0.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "policy-a", Namespace: ns, CreationTimestamp: now},
				Spec: agenticv0alpha0.AccessPolicySpec{
					TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{
						LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{
							Group: gwapiv1.Group(agenticv0alpha0.GroupName),
							Kind:  "XBackend",
							Name:  "target-a",
						},
					}},
				},
			},
			wantAccepted: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Include current policy in the list because lister.List() should find it
			allPolicies := make([]runtime.Object, 0, len(tt.existing)+1)
			allPolicies = append(allPolicies, tt.existing...)
			allPolicies = append(allPolicies, tt.currentPolicy)
			fakeClient := agenticclient.NewClientset(allPolicies...)
			informerFactory := agenticinformers.NewSharedInformerFactory(fakeClient, 0)
			lister := informerFactory.Agentic().V0alpha0().XAccessPolicies().Lister()

			for _, p := range allPolicies {
				_ = informerFactory.Agentic().V0alpha0().XAccessPolicies().Informer().GetIndexer().Add(p)
			}

			c := &Controller{
				agentic: agenticNetResources{
					client:             fakeClient,
					accessPolicyLister: lister,
				},
			}

			got := c.isPolicyUnderTargetLimit(context.Background(), tt.currentPolicy)
			if got != tt.wantAccepted {
				t.Errorf("isPolicyUnderTargetLimit() = %v, want %v", got, tt.wantAccepted)
			}

			// Verify status updates
			actions := fakeClient.Actions()
			// We expect an UpdateStatus for each targetRef
			expectedUpdates := len(tt.currentPolicy.Spec.TargetRefs)
			updateCount := 0
			for _, action := range actions {
				if action.GetVerb() == "update" && action.GetSubresource() == "status" {
					updateCount++
				}
			}

			if updateCount != expectedUpdates {
				t.Errorf("Expected %d status updates, got %d", expectedUpdates, updateCount)
			}
		})
	}
}

func TestFilterEmptyStrings(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{name: "empty", in: nil, want: nil},
		{name: "drops empties", in: []string{"a", "", "b", ""}, want: []string{"a", "b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterEmptyStrings(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("filterEmptyStrings() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestAccessPolicyHasInvalidTranslationStatus(t *testing.T) {
	ns := gwapiv1.Namespace("default")
	gwGroup := gwapiv1.Group(gwapiv1.GroupName)
	gwKind := gwapiv1.Kind("Gateway")
	invalidAncestor := gwapiv1.PolicyAncestorStatus{
		AncestorRef: gwapiv1.ParentReference{
			Group:     &gwGroup,
			Kind:      &gwKind,
			Namespace: &ns,
			Name:      "gw",
		},
		ControllerName: gwapiv1.GatewayController(constants.ControllerName),
		Conditions: []metav1.Condition{
			{
				Type:   string(agenticv0alpha0.PolicyConditionAccepted),
				Status: metav1.ConditionFalse,
				Reason: string(gwapiv1.PolicyReasonInvalid),
			},
		},
	}
	tests := []struct {
		name   string
		policy *agenticv0alpha0.XAccessPolicy
		want   bool
	}{
		{
			name:   "no ancestors",
			policy: &agenticv0alpha0.XAccessPolicy{},
			want:   false,
		},
		{
			name: "invalid translation",
			policy: &agenticv0alpha0.XAccessPolicy{
				Status: agenticv0alpha0.AccessPolicyStatus{Ancestors: []gwapiv1.PolicyAncestorStatus{invalidAncestor}},
			},
			want: true,
		},
		{
			name: "false for limit exceeded",
			policy: &agenticv0alpha0.XAccessPolicy{
				Status: agenticv0alpha0.AccessPolicyStatus{
					Ancestors: []gwapiv1.PolicyAncestorStatus{
						{
							AncestorRef: invalidAncestor.AncestorRef,
							Conditions: []metav1.Condition{
								{
									Type:   string(agenticv0alpha0.PolicyConditionAccepted),
									Status: metav1.ConditionFalse,
									Reason: string(agenticv0alpha0.PolicyLimitPerTargetExceeded),
								},
							},
						},
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := accessPolicyHasInvalidTranslationStatus(tt.policy); got != tt.want {
				t.Errorf("accessPolicyHasInvalidTranslationStatus() = %v, want %v", got, tt.want)
			}
		})
	}
}

func testPolicyGatewayTarget(name, ns, gwName string) *agenticv0alpha0.XAccessPolicy {
	spiffeID := agenticv0alpha0.AuthorizationSourceSPIFFE("spiffe://cluster.local/ns/x/sa/y")
	return &agenticv0alpha0.XAccessPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Generation: 1},
		Spec: agenticv0alpha0.AccessPolicySpec{
			TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{
				{
					LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{
						Group: gwapiv1.GroupName,
						Kind:  "Gateway",
						Name:  gwapiv1.ObjectName(gwName),
					},
				},
			},
			Rules: []agenticv0alpha0.AccessRule{
				{
					Name:   "r1",
					Source: agenticv0alpha0.Source{Type: agenticv0alpha0.AuthorizationSourceTypeSPIFFE, SPIFFE: &spiffeID},
				},
			},
		},
	}
}

func TestReconcileAccessPolicyTranslationStatus_setsInvalid(t *testing.T) {
	ctx := context.Background()
	ns := "default"
	gwName := "gw1"
	policy := testPolicyGatewayTarget("pol1", ns, gwName)

	fakeAgentic := agenticclient.NewClientset(policy)
	agenticFactory := agenticinformers.NewSharedInformerFactory(fakeAgentic, 0)
	_ = agenticFactory.Agentic().V0alpha0().XAccessPolicies().Informer().GetIndexer().Add(policy)
	apLister := agenticFactory.Agentic().V0alpha0().XAccessPolicies().Lister()

	tr := translator.New(
		"cluster.local",
		nil, nil, nil, nil, nil, nil,
		nil, nil, nil,
		apLister,
		nil,
		nil,
	)

	c := &Controller{
		agentic: agenticNetResources{
			client:             fakeAgentic,
			accessPolicyLister: apLister,
		},
		translator: tr,
	}

	gw := &gwapiv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: gwName, Namespace: ns}}
	issues := map[types.NamespacedName][]string{
		{Namespace: ns, Name: "pol1"}: {"dup", "dup", "rule x: broken"},
	}
	c.reconcileAccessPolicyTranslationStatus(ctx, gw, issues)

	updated, err := fakeAgentic.AgenticV0alpha0().XAccessPolicies(ns).Get(ctx, "pol1", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get policy: %v", err)
	}
	if len(updated.Status.Ancestors) != 1 {
		t.Fatalf("expected 1 ancestor status, got %d", len(updated.Status.Ancestors))
	}
	cond := meta.FindStatusCondition(updated.Status.Ancestors[0].Conditions, string(agenticv0alpha0.PolicyConditionAccepted))
	if cond == nil {
		t.Fatal("missing Accepted condition")
	}
	if cond.Status != metav1.ConditionFalse || cond.Reason != string(gwapiv1.PolicyReasonInvalid) {
		t.Fatalf("Accepted condition = %+v, want False/Invalid", cond)
	}
	wantMsg := "dup; rule x: broken"
	if cond.Message != wantMsg {
		t.Errorf("message = %q, want %q", cond.Message, wantMsg)
	}
}

func TestReconcileAccessPolicyTranslationStatus_clearsInvalidViaLimitCheck(t *testing.T) {
	ctx := context.Background()
	ns := "default"
	gwName := "gw1"
	policy := testPolicyGatewayTarget("pol1", ns, gwName)
	nsG := gwapiv1.Namespace(ns)
	gwG := gwapiv1.Group(gwapiv1.GroupName)
	gwK := gwapiv1.Kind("Gateway")
	policy.Status = agenticv0alpha0.AccessPolicyStatus{
		Ancestors: []gwapiv1.PolicyAncestorStatus{
			{
				AncestorRef: gwapiv1.ParentReference{
					Group:     &gwG,
					Kind:      &gwK,
					Namespace: &nsG,
					Name:      gwapiv1.ObjectName(gwName),
				},
				ControllerName: gwapiv1.GatewayController(constants.ControllerName),
				Conditions: []metav1.Condition{
					{
						Type:   string(agenticv0alpha0.PolicyConditionAccepted),
						Status: metav1.ConditionFalse,
						Reason: string(gwapiv1.PolicyReasonInvalid),
					},
				},
			},
		},
	}

	fakeAgentic := agenticclient.NewClientset(policy)
	agenticFactory := agenticinformers.NewSharedInformerFactory(fakeAgentic, 0)
	_ = agenticFactory.Agentic().V0alpha0().XAccessPolicies().Informer().GetIndexer().Add(policy)
	apLister := agenticFactory.Agentic().V0alpha0().XAccessPolicies().Lister()

	gwClient := gatewayclientfake.NewClientset()
	gwFactory := gatewayinformers.NewSharedInformerFactory(gwClient, 0)
	httprouteLister := gwFactory.Gateway().V1().HTTPRoutes().Lister()

	tr := translator.New(
		"cluster.local",
		nil, nil, nil, nil, nil, nil,
		nil, httprouteLister, nil,
		apLister,
		nil,
		nil,
	)

	c := &Controller{
		agentic: agenticNetResources{
			client:             fakeAgentic,
			accessPolicyLister: apLister,
		},
		translator: tr,
	}

	gw := &gwapiv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: gwName, Namespace: ns}}
	c.reconcileAccessPolicyTranslationStatus(ctx, gw, nil)

	updated, err := fakeAgentic.AgenticV0alpha0().XAccessPolicies(ns).Get(ctx, "pol1", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get policy: %v", err)
	}
	cond := meta.FindStatusCondition(updated.Status.Ancestors[0].Conditions, string(agenticv0alpha0.PolicyConditionAccepted))
	if cond == nil {
		t.Fatal("missing Accepted condition")
	}
	if cond.Status != metav1.ConditionTrue {
		t.Fatalf("expected Accepted True after translation cleared, got %+v", cond)
	}
}
