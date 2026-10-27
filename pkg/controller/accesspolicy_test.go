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
	"errors"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/ptr"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewaylisters "sigs.k8s.io/gateway-api/pkg/client/listers/apis/v1"

	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	agenticv1alpha1 "sigs.k8s.io/kube-agentic-networking/api/v1alpha1"
	agenticclient "sigs.k8s.io/kube-agentic-networking/k8s/client/clientset/versioned/fake"
	agenticinformers "sigs.k8s.io/kube-agentic-networking/k8s/client/informers/externalversions"
	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

func TestIsPolicyUnderTargetLimit(t *testing.T) {
	ns := "test-ns"
	now := metav1.Now()
	earlier := metav1.NewTime(now.Add(-1 * time.Hour))

	tests := []struct {
		name          string
		existing      []runtime.Object
		currentPolicy *agenticv1alpha1.XAccessPolicy
		wantAccepted  bool
	}{
		{
			name: "under limit - single target",
			existing: []runtime.Object{
				&agenticv1alpha1.XAccessPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "policy-1", Namespace: ns, CreationTimestamp: earlier},
					Spec: agenticv1alpha1.AccessPolicySpec{
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
			currentPolicy: &agenticv1alpha1.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "policy-2", Namespace: ns, CreationTimestamp: now},
				Spec: agenticv1alpha1.AccessPolicySpec{
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
			name: "external auth conflict - secondary policy rejected",
			existing: []runtime.Object{
				&agenticv1alpha1.XAccessPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "ext-auth-senior", Namespace: ns, CreationTimestamp: earlier},
					Spec: agenticv1alpha1.AccessPolicySpec{
						Action: agenticv1alpha1.ActionTypeExternalAuth,
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
			currentPolicy: &agenticv1alpha1.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "ext-auth-junior", Namespace: ns, CreationTimestamp: now},
				Spec: agenticv1alpha1.AccessPolicySpec{
					Action: agenticv1alpha1.ActionTypeExternalAuth,
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
			name: "over limit - rejected",
			existing: []runtime.Object{
				&agenticv1alpha1.XAccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: ns, CreationTimestamp: earlier}, Spec: agenticv1alpha1.AccessPolicySpec{TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{Group: gwapiv1.Group(agenticv0alpha0.GroupName), Kind: "XBackend", Name: "target-a"}}}}},
				&agenticv1alpha1.XAccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p2", Namespace: ns, CreationTimestamp: earlier}, Spec: agenticv1alpha1.AccessPolicySpec{TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{Group: gwapiv1.Group(agenticv0alpha0.GroupName), Kind: "XBackend", Name: "target-a"}}}}},
				&agenticv1alpha1.XAccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p3", Namespace: ns, CreationTimestamp: earlier}, Spec: agenticv1alpha1.AccessPolicySpec{TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{Group: gwapiv1.Group(agenticv0alpha0.GroupName), Kind: "XBackend", Name: "target-a"}}}}},
				&agenticv1alpha1.XAccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p4", Namespace: ns, CreationTimestamp: earlier}, Spec: agenticv1alpha1.AccessPolicySpec{TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{Group: gwapiv1.Group(agenticv0alpha0.GroupName), Kind: "XBackend", Name: "target-a"}}}}},
				&agenticv1alpha1.XAccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p5", Namespace: ns, CreationTimestamp: earlier}, Spec: agenticv1alpha1.AccessPolicySpec{TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{Group: gwapiv1.Group(agenticv0alpha0.GroupName), Kind: "XBackend", Name: "target-a"}}}}},
			},
			currentPolicy: &agenticv1alpha1.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "policy-new", Namespace: ns, CreationTimestamp: now},
				Spec: agenticv1alpha1.AccessPolicySpec{
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
				&agenticv1alpha1.XAccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: ns, CreationTimestamp: now}, Spec: agenticv1alpha1.AccessPolicySpec{TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{Group: gwapiv1.Group(agenticv0alpha0.GroupName), Kind: "XBackend", Name: "target-a"}}}}},
				&agenticv1alpha1.XAccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p2", Namespace: ns, CreationTimestamp: now}, Spec: agenticv1alpha1.AccessPolicySpec{TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{Group: gwapiv1.Group(agenticv0alpha0.GroupName), Kind: "XBackend", Name: "target-a"}}}}},
				&agenticv1alpha1.XAccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p3", Namespace: ns, CreationTimestamp: now}, Spec: agenticv1alpha1.AccessPolicySpec{TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{Group: gwapiv1.Group(agenticv0alpha0.GroupName), Kind: "XBackend", Name: "target-a"}}}}},
				&agenticv1alpha1.XAccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p4", Namespace: ns, CreationTimestamp: now}, Spec: agenticv1alpha1.AccessPolicySpec{TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{Group: gwapiv1.Group(agenticv0alpha0.GroupName), Kind: "XBackend", Name: "target-a"}}}}},
				&agenticv1alpha1.XAccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p5", Namespace: ns, CreationTimestamp: now}, Spec: agenticv1alpha1.AccessPolicySpec{TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{Group: gwapiv1.Group(agenticv0alpha0.GroupName), Kind: "XBackend", Name: "target-a"}}}}},
			},
			currentPolicy: &agenticv1alpha1.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "policy-old", Namespace: ns, CreationTimestamp: earlier},
				Spec: agenticv1alpha1.AccessPolicySpec{
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
				&agenticv1alpha1.XAccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: ns, CreationTimestamp: earlier}, Spec: agenticv1alpha1.AccessPolicySpec{TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{Group: gwapiv1.Group(agenticv0alpha0.GroupName), Kind: "XBackend", Name: "target-full"}}}}},
				&agenticv1alpha1.XAccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p2", Namespace: ns, CreationTimestamp: earlier}, Spec: agenticv1alpha1.AccessPolicySpec{TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{Group: gwapiv1.Group(agenticv0alpha0.GroupName), Kind: "XBackend", Name: "target-full"}}}}},
				&agenticv1alpha1.XAccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p3", Namespace: ns, CreationTimestamp: earlier}, Spec: agenticv1alpha1.AccessPolicySpec{TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{Group: gwapiv1.Group(agenticv0alpha0.GroupName), Kind: "XBackend", Name: "target-full"}}}}},
				&agenticv1alpha1.XAccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p4", Namespace: ns, CreationTimestamp: earlier}, Spec: agenticv1alpha1.AccessPolicySpec{TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{Group: gwapiv1.Group(agenticv0alpha0.GroupName), Kind: "XBackend", Name: "target-full"}}}}},
				&agenticv1alpha1.XAccessPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p5", Namespace: ns, CreationTimestamp: earlier}, Spec: agenticv1alpha1.AccessPolicySpec{TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{Group: gwapiv1.Group(agenticv0alpha0.GroupName), Kind: "XBackend", Name: "target-full"}}}}},
			},
			currentPolicy: &agenticv1alpha1.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "policy-multi", Namespace: ns, CreationTimestamp: now},
				Spec: agenticv1alpha1.AccessPolicySpec{
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
				&agenticv1alpha1.XAccessPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "policy-b", Namespace: ns, CreationTimestamp: now},
					Spec: agenticv1alpha1.AccessPolicySpec{
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
			currentPolicy: &agenticv1alpha1.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "policy-a", Namespace: ns, CreationTimestamp: now},
				Spec: agenticv1alpha1.AccessPolicySpec{
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
			fakeClient := agenticclient.NewSimpleClientset(allPolicies...)
			informerFactory := agenticinformers.NewSharedInformerFactory(fakeClient, 0)
			lister := informerFactory.Agentic().V1alpha1().XAccessPolicies().Lister()

			for _, p := range allPolicies {
				_ = informerFactory.Agentic().V1alpha1().XAccessPolicies().Informer().GetIndexer().Add(p)
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

func TestUpdateAccessPolicyStatus_ProgrammedCondition(t *testing.T) {
	ns := "test-ns"
	policy := &agenticv1alpha1.XAccessPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: ns},
		Spec: agenticv1alpha1.AccessPolicySpec{
			TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{
					Group: gwapiv1.Group(agenticv0alpha0.GroupName),
					Kind:  "XBackend",
					Name:  "target-1",
				},
			}},
		},
	}

	fakeClient := agenticclient.NewSimpleClientset(policy)
	informerFactory := agenticinformers.NewSharedInformerFactory(fakeClient, 0)
	lister := informerFactory.Agentic().V1alpha1().XAccessPolicies().Lister()
	_ = informerFactory.Agentic().V1alpha1().XAccessPolicies().Informer().GetIndexer().Add(policy)

	c := &Controller{
		agentic: agenticNetResources{
			client:             fakeClient,
			accessPolicyLister: lister,
		},
	}

	err := c.updateAccessPolicyStatus(context.Background(), policy, policy.Spec.TargetRefs[0], true, agenticv1alpha1.PolicyReasonAccepted, "Policy accepted")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	updated, err := fakeClient.AgenticV1alpha1().XAccessPolicies(ns).Get(context.Background(), "test-policy", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to fetch updated policy: %v", err)
	}

	if len(updated.Status.Ancestors) == 0 {
		t.Fatalf("expected ancestors status, got empty")
	}

	ancestor := updated.Status.Ancestors[0]
	acceptedCond := meta.FindStatusCondition(ancestor.Conditions, string(agenticv1alpha1.PolicyConditionAccepted))
	if acceptedCond == nil || acceptedCond.Status != metav1.ConditionTrue || acceptedCond.Reason != string(agenticv1alpha1.PolicyReasonAccepted) {
		t.Errorf("unexpected Accepted condition: %+v", acceptedCond)
	}

	programmedCond := meta.FindStatusCondition(ancestor.Conditions, string(agenticv1alpha1.PolicyConditionProgrammed))
	if programmedCond == nil || programmedCond.Status != metav1.ConditionFalse || programmedCond.Reason != string(agenticv1alpha1.PolicyReasonPending) {
		t.Errorf("unexpected Programmed condition: %+v", programmedCond)
	}

	// Verify that a subsequent acceptance re-sync preserves Programmed=True if already set.
	meta.SetStatusCondition(&updated.Status.Ancestors[0].Conditions, metav1.Condition{
		Type:               string(agenticv1alpha1.PolicyConditionProgrammed),
		Status:             metav1.ConditionTrue,
		Reason:             string(agenticv1alpha1.PolicyReasonProgrammed),
		Message:            "Policy has been programmed into the data plane",
		ObservedGeneration: updated.Generation,
	})
	if _, updateErr := fakeClient.AgenticV1alpha1().XAccessPolicies(ns).UpdateStatus(context.Background(), updated, metav1.UpdateOptions{}); updateErr != nil {
		t.Fatalf("failed to update policy status with Programmed=True: %v", updateErr)
	}
	if indexerErr := informerFactory.Agentic().V1alpha1().XAccessPolicies().Informer().GetIndexer().Update(updated); indexerErr != nil {
		t.Fatalf("failed to update indexer: %v", indexerErr)
	}

	err = c.updateAccessPolicyStatus(context.Background(), policy, policy.Spec.TargetRefs[0], true, agenticv1alpha1.PolicyReasonAccepted, "Policy accepted")
	if err != nil {
		t.Fatalf("unexpected error on resync: %v", err)
	}

	resynced, getErr := fakeClient.AgenticV1alpha1().XAccessPolicies(ns).Get(context.Background(), "test-policy", metav1.GetOptions{})
	if getErr != nil {
		t.Fatalf("failed to fetch resynced policy: %v", getErr)
	}
	resyncedProgrammed := meta.FindStatusCondition(resynced.Status.Ancestors[0].Conditions, string(agenticv1alpha1.PolicyConditionProgrammed))
	if resyncedProgrammed == nil || resyncedProgrammed.Status != metav1.ConditionTrue || resyncedProgrammed.Reason != string(agenticv1alpha1.PolicyReasonProgrammed) {
		t.Errorf("acceptance re-sync reset Programmed condition: %+v", resyncedProgrammed)
	}
}

func TestUpdateAccessPolicyProgrammedStatus(t *testing.T) {
	tests := []struct {
		name              string
		ancestorRef       gwapiv1.ParentReference
		programmingErr    error
		wantStatus        metav1.ConditionStatus
		wantReason        string
		wantMessagePrefix string
	}{
		{
			name: "Gateway xDS update succeeded",
			ancestorRef: gwapiv1.ParentReference{
				Group:     ptr.To(gwapiv1.Group(gwapiv1.GroupName)),
				Kind:      ptr.To(gwapiv1.Kind("Gateway")),
				Namespace: ptr.To(gwapiv1.Namespace("test-ns")),
				Name:      "test-gateway",
			},
			wantStatus:        metav1.ConditionTrue,
			wantReason:        string(agenticv1alpha1.PolicyReasonProgrammed),
			wantMessagePrefix: "Policy has been programmed",
		},
		{
			name: "Gateway xDS update failed",
			ancestorRef: gwapiv1.ParentReference{
				Group:     ptr.To(gwapiv1.Group(gwapiv1.GroupName)),
				Kind:      ptr.To(gwapiv1.Kind("Gateway")),
				Namespace: ptr.To(gwapiv1.Namespace("test-ns")),
				Name:      "test-gateway",
			},
			programmingErr:    errors.New("xDS update failed"),
			wantStatus:        metav1.ConditionFalse,
			wantReason:        string(agenticv1alpha1.PolicyReasonFailed),
			wantMessagePrefix: "Failed to program policy",
		},
		{
			name: "XBackend xDS update succeeded",
			ancestorRef: gwapiv1.ParentReference{
				Group:     ptr.To(gwapiv1.Group(agenticv0alpha0.GroupName)),
				Kind:      ptr.To(gwapiv1.Kind("XBackend")),
				Namespace: ptr.To(gwapiv1.Namespace("test-ns")),
				Name:      "test-backend",
			},
			wantStatus:        metav1.ConditionTrue,
			wantReason:        string(agenticv1alpha1.PolicyReasonProgrammed),
			wantMessagePrefix: "Policy has been programmed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const (
				ns         = "test-ns"
				policyName = "test-policy"
			)
			policy := &agenticv1alpha1.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: ns, Generation: 2},
				Status: agenticv1alpha1.AccessPolicyStatus{Ancestors: []gwapiv1.PolicyAncestorStatus{{
					AncestorRef:    tt.ancestorRef,
					ControllerName: gwapiv1.GatewayController(constants.ControllerName),
					Conditions: []metav1.Condition{
						{
							Type:               string(agenticv1alpha1.PolicyConditionAccepted),
							Status:             metav1.ConditionTrue,
							Reason:             string(agenticv1alpha1.PolicyReasonAccepted),
							ObservedGeneration: 2,
						},
						{
							Type:               string(agenticv1alpha1.PolicyConditionProgrammed),
							Status:             metav1.ConditionFalse,
							Reason:             string(agenticv1alpha1.PolicyReasonPending),
							ObservedGeneration: 2,
						},
					},
				}}},
			}

			fakeClient := agenticclient.NewSimpleClientset(policy)
			informerFactory := agenticinformers.NewSharedInformerFactory(fakeClient, 0)
			lister := informerFactory.Agentic().V1alpha1().XAccessPolicies().Lister()
			if err := informerFactory.Agentic().V1alpha1().XAccessPolicies().Informer().GetIndexer().Add(policy); err != nil {
				t.Fatalf("failed to add policy to indexer: %v", err)
			}

			c := &Controller{agentic: agenticNetResources{client: fakeClient, accessPolicyLister: lister}}
			if err := c.updateAccessPolicyProgrammedStatus(context.Background(), policy, tt.ancestorRef, tt.programmingErr); err != nil {
				t.Fatalf("updateAccessPolicyProgrammedStatus() error = %v", err)
			}

			updated, err := fakeClient.AgenticV1alpha1().XAccessPolicies(ns).Get(context.Background(), policyName, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("failed to get updated policy: %v", err)
			}
			condition := meta.FindStatusCondition(updated.Status.Ancestors[0].Conditions, string(agenticv1alpha1.PolicyConditionProgrammed))
			if condition == nil {
				t.Fatal("Programmed condition not found")
			}
			if condition.Status != tt.wantStatus || condition.Reason != tt.wantReason || !strings.HasPrefix(condition.Message, tt.wantMessagePrefix) {
				t.Errorf("Programmed condition = %+v, want status=%s reason=%s message prefix=%q", condition, tt.wantStatus, tt.wantReason, tt.wantMessagePrefix)
			}
			if condition.ObservedGeneration != policy.Generation {
				t.Errorf("ObservedGeneration = %d, want %d", condition.ObservedGeneration, policy.Generation)
			}
		})
	}
}

func TestAccessPoliciesForGateway(t *testing.T) {
	const ns = "test-ns"
	gateway := &gwapiv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-1", Namespace: ns},
	}

	// 1. Accepted policy targeting Gateway gw-1
	gwPolicy := &agenticv1alpha1.XAccessPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-policy", Namespace: ns},
		Spec: agenticv1alpha1.AccessPolicySpec{
			TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{
					Group: gwapiv1.GroupName,
					Kind:  "Gateway",
					Name:  "gw-1",
				},
			}},
		},
		Status: agenticv1alpha1.AccessPolicyStatus{Ancestors: []gwapiv1.PolicyAncestorStatus{{
			AncestorRef: gwapiv1.ParentReference{
				Group:     ptr.To(gwapiv1.Group(gwapiv1.GroupName)),
				Kind:      ptr.To(gwapiv1.Kind("Gateway")),
				Namespace: ptr.To(gwapiv1.Namespace(ns)),
				Name:      "gw-1",
			},
			Conditions: []metav1.Condition{{
				Type:   string(agenticv1alpha1.PolicyConditionAccepted),
				Status: metav1.ConditionTrue,
			}},
		}}},
	}

	// 2. Unaccepted policy targeting Gateway gw-1 (should be omitted)
	unacceptedPolicy := &agenticv1alpha1.XAccessPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "unaccepted-policy", Namespace: ns},
		Spec: agenticv1alpha1.AccessPolicySpec{
			TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{
					Group: gwapiv1.GroupName,
					Kind:  "Gateway",
					Name:  "gw-1",
				},
			}},
		},
		Status: agenticv1alpha1.AccessPolicyStatus{Ancestors: []gwapiv1.PolicyAncestorStatus{{
			AncestorRef: gwapiv1.ParentReference{
				Group:     ptr.To(gwapiv1.Group(gwapiv1.GroupName)),
				Kind:      ptr.To(gwapiv1.Kind("Gateway")),
				Namespace: ptr.To(gwapiv1.Namespace(ns)),
				Name:      "gw-1",
			},
			Conditions: []metav1.Condition{{
				Type:   string(agenticv1alpha1.PolicyConditionAccepted),
				Status: metav1.ConditionFalse,
			}},
		}}},
	}

	// 3. Accepted policy targeting XBackend backend-1
	backendPolicy := &agenticv1alpha1.XAccessPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "backend-policy", Namespace: ns},
		Spec: agenticv1alpha1.AccessPolicySpec{
			TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{
					Group: agenticv0alpha0.GroupName,
					Kind:  "XBackend",
					Name:  "backend-1",
				},
			}},
		},
		Status: agenticv1alpha1.AccessPolicyStatus{Ancestors: []gwapiv1.PolicyAncestorStatus{{
			AncestorRef: gwapiv1.ParentReference{
				Group:     ptr.To(gwapiv1.Group(agenticv0alpha0.GroupName)),
				Kind:      ptr.To(gwapiv1.Kind("XBackend")),
				Namespace: ptr.To(gwapiv1.Namespace(ns)),
				Name:      "backend-1",
			},
			Conditions: []metav1.Condition{{
				Type:   string(agenticv1alpha1.PolicyConditionAccepted),
				Status: metav1.ConditionTrue,
			}},
		}}},
	}

	// 4. Policy targeting XBackend backend-2 which belongs to another gateway (should be omitted)
	otherBackendPolicy := &agenticv1alpha1.XAccessPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "other-backend-policy", Namespace: ns},
		Spec: agenticv1alpha1.AccessPolicySpec{
			TargetRefs: []gwapiv1.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{
					Group: agenticv0alpha0.GroupName,
					Kind:  "XBackend",
					Name:  "backend-2",
				},
			}},
		},
		Status: agenticv1alpha1.AccessPolicyStatus{Ancestors: []gwapiv1.PolicyAncestorStatus{{
			AncestorRef: gwapiv1.ParentReference{
				Group:     ptr.To(gwapiv1.Group(agenticv0alpha0.GroupName)),
				Kind:      ptr.To(gwapiv1.Kind("XBackend")),
				Namespace: ptr.To(gwapiv1.Namespace(ns)),
				Name:      "backend-2",
			},
			Conditions: []metav1.Condition{{
				Type:   string(agenticv1alpha1.PolicyConditionAccepted),
				Status: metav1.ConditionTrue,
			}},
		}}},
	}

	// HTTPRoute attached to gw-1, referencing backend-1
	route1 := &gwapiv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-1", Namespace: ns},
		Spec: gwapiv1.HTTPRouteSpec{
			CommonRouteSpec: gwapiv1.CommonRouteSpec{
				ParentRefs: []gwapiv1.ParentReference{{
					Group: ptr.To(gwapiv1.Group(gwapiv1.GroupName)),
					Kind:  ptr.To(gwapiv1.Kind("Gateway")),
					Name:  "gw-1",
				}},
			},
			Rules: []gwapiv1.HTTPRouteRule{{
				BackendRefs: []gwapiv1.HTTPBackendRef{{
					BackendRef: gwapiv1.BackendRef{
						BackendObjectReference: gwapiv1.BackendObjectReference{
							Group: ptr.To(gwapiv1.Group(agenticv0alpha0.GroupName)),
							Kind:  ptr.To(gwapiv1.Kind("XBackend")),
							Name:  "backend-1",
						},
					},
				}},
			}},
		},
	}

	fakeClient := agenticclient.NewSimpleClientset(gwPolicy, unacceptedPolicy, backendPolicy, otherBackendPolicy)
	informerFactory := agenticinformers.NewSharedInformerFactory(fakeClient, 0)
	policyLister := informerFactory.Agentic().V1alpha1().XAccessPolicies().Lister()
	for _, p := range []*agenticv1alpha1.XAccessPolicy{gwPolicy, unacceptedPolicy, backendPolicy, otherBackendPolicy} {
		if err := informerFactory.Agentic().V1alpha1().XAccessPolicies().Informer().GetIndexer().Add(p); err != nil {
			t.Fatalf("indexer.Add: %v", err)
		}
	}

	routeIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	if err := routeIndexer.Add(route1); err != nil {
		t.Fatalf("routeIndexer.Add: %v", err)
	}

	c := &Controller{
		gateway: gatewayResources{
			httprouteLister: gatewaylisters.NewHTTPRouteLister(routeIndexer),
		},
		agentic: agenticNetResources{
			client:             fakeClient,
			accessPolicyLister: policyLister,
		},
	}

	results, err := c.accessPoliciesForGateway(gateway)
	if err != nil {
		t.Fatalf("accessPoliciesForGateway() error = %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("accessPoliciesForGateway() returned %d results, want 2", len(results))
	}

	names := make(map[string]gwapiv1.ParentReference)
	for _, res := range results {
		names[res.policy.Name] = res.ancestorRef
	}

	if ref, ok := names["gw-policy"]; !ok || *ref.Kind != "Gateway" || ref.Name != "gw-1" {
		t.Errorf("expected gw-policy with Gateway ancestor, got %+v", ref)
	}
	if ref, ok := names["backend-policy"]; !ok || *ref.Kind != "XBackend" || ref.Name != "backend-1" {
		t.Errorf("expected backend-policy with XBackend ancestor, got %+v", ref)
	}
}

func TestHasAccessPolicyChangedIgnoresProgrammedStatus(t *testing.T) {
	oldPolicy := &agenticv1alpha1.XAccessPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "test-ns", Generation: 1},
		Status: agenticv1alpha1.AccessPolicyStatus{Ancestors: []gwapiv1.PolicyAncestorStatus{{
			Conditions: []metav1.Condition{
				{Type: string(agenticv1alpha1.PolicyConditionAccepted), Status: metav1.ConditionTrue},
				{Type: string(agenticv1alpha1.PolicyConditionProgrammed), Status: metav1.ConditionFalse},
			},
		}}},
	}
	newPolicy := oldPolicy.DeepCopy()
	meta.SetStatusCondition(&newPolicy.Status.Ancestors[0].Conditions, metav1.Condition{
		Type:   string(agenticv1alpha1.PolicyConditionProgrammed),
		Status: metav1.ConditionTrue,
		Reason: string(agenticv1alpha1.PolicyReasonProgrammed),
	})

	if hasAccessPolicyChanged(oldPolicy, newPolicy) {
		t.Error("hasAccessPolicyChanged() = true for Programmed-only status update, want false")
	}
}
