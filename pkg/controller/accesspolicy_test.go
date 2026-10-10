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
	"k8s.io/utils/ptr"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

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
}

func TestUpdateAccessPolicyProgrammedStatus(t *testing.T) {
	tests := []struct {
		name              string
		programmingErr    error
		wantStatus        metav1.ConditionStatus
		wantReason        string
		wantMessagePrefix string
	}{
		{
			name:              "xDS update succeeded",
			wantStatus:        metav1.ConditionTrue,
			wantReason:        string(agenticv1alpha1.PolicyReasonProgrammed),
			wantMessagePrefix: "Policy has been programmed",
		},
		{
			name:              "xDS update failed",
			programmingErr:    errors.New("xDS update failed"),
			wantStatus:        metav1.ConditionFalse,
			wantReason:        string(agenticv1alpha1.PolicyReasonPending),
			wantMessagePrefix: "Failed to program policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const (
				ns          = "test-ns"
				policyName  = "test-policy"
				gatewayName = "test-gateway"
			)
			gatewayRef := gwapiv1.ParentReference{
				Group:     ptr.To(gwapiv1.Group(gwapiv1.GroupName)),
				Kind:      ptr.To(gwapiv1.Kind("Gateway")),
				Namespace: ptr.To(gwapiv1.Namespace(ns)),
				Name:      gwapiv1.ObjectName(gatewayName),
			}
			policy := &agenticv1alpha1.XAccessPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: ns, Generation: 2},
				Status: agenticv1alpha1.AccessPolicyStatus{Ancestors: []gwapiv1.PolicyAncestorStatus{{
					AncestorRef:    gatewayRef,
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
			gateway := &gwapiv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: gatewayName, Namespace: ns}}

			fakeClient := agenticclient.NewSimpleClientset(policy)
			informerFactory := agenticinformers.NewSharedInformerFactory(fakeClient, 0)
			lister := informerFactory.Agentic().V1alpha1().XAccessPolicies().Lister()
			if err := informerFactory.Agentic().V1alpha1().XAccessPolicies().Informer().GetIndexer().Add(policy); err != nil {
				t.Fatalf("failed to add policy to indexer: %v", err)
			}

			c := &Controller{agentic: agenticNetResources{client: fakeClient, accessPolicyLister: lister}}
			if err := c.updateAccessPolicyProgrammedStatus(context.Background(), policy, gateway, tt.programmingErr); err != nil {
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
