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
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	agenticclient "sigs.k8s.io/kube-agentic-networking/k8s/client/clientset/versioned/fake"
	agenticinformers "sigs.k8s.io/kube-agentic-networking/k8s/client/informers/externalversions"
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
			fakeClient := agenticclient.NewSimpleClientset(allPolicies...)
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
