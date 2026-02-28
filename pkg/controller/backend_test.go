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
	"testing"

	"k8s.io/client-go/tools/cache"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	agenticlisters "sigs.k8s.io/kube-agentic-networking/k8s/client/listers/api/v0alpha0"
)

func TestHasAccessPoliciesTargetingBackend(t *testing.T) {
	ns := "default"
	backendName := "my-backend"

	t.Run("no policies in namespace", func(t *testing.T) {
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		c := &Controller{
			agentic: agenticNetResources{
				accessPolicyLister: agenticlisters.NewXAccessPolicyLister(indexer),
			},
		}
		backend := &agenticv0alpha0.XBackend{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: backendName},
		}
		if hasAccessPoliciesTargetingBackend(c, backend) {
			t.Error("expected false when no policies exist in namespace")
		}
	})

	t.Run("policy targets different backend", func(t *testing.T) {
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		policy := &agenticv0alpha0.XAccessPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "policy-1"},
			Spec: agenticv0alpha0.AccessPolicySpec{
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
					{
						LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
							Group: agenticv0alpha0.GroupName,
							Kind:  "XBackend",
							Name:  gatewayv1.ObjectName("other-backend"),
						},
					},
				},
				Rules: []agenticv0alpha0.AccessRule{{Name: "rule1"}},
			},
		}
		if err := indexer.Add(policy); err != nil {
			t.Fatalf("indexer.Add: %v", err)
		}
		c := &Controller{
			agentic: agenticNetResources{
				accessPolicyLister: agenticlisters.NewXAccessPolicyLister(indexer),
			},
		}
		backend := &agenticv0alpha0.XBackend{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: backendName},
		}
		if hasAccessPoliciesTargetingBackend(c, backend) {
			t.Error("expected false when policy targets a different backend")
		}
	})

	t.Run("policy targets this backend", func(t *testing.T) {
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		policy := &agenticv0alpha0.XAccessPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "policy-1"},
			Spec: agenticv0alpha0.AccessPolicySpec{
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
					{
						LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
							Group: agenticv0alpha0.GroupName,
							Kind:  "XBackend",
							Name:  gatewayv1.ObjectName(backendName),
						},
					},
				},
				Rules: []agenticv0alpha0.AccessRule{{Name: "rule1"}},
			},
		}
		if err := indexer.Add(policy); err != nil {
			t.Fatalf("indexer.Add: %v", err)
		}
		c := &Controller{
			agentic: agenticNetResources{
				accessPolicyLister: agenticlisters.NewXAccessPolicyLister(indexer),
			},
		}
		backend := &agenticv0alpha0.XBackend{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: backendName},
		}
		if !hasAccessPoliciesTargetingBackend(c, backend) {
			t.Error("expected true when a policy targets this backend")
		}
	})

	t.Run("policy targets this backend by name but wrong group is skipped", func(t *testing.T) {
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		policy := &agenticv0alpha0.XAccessPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "policy-1"},
			Spec: agenticv0alpha0.AccessPolicySpec{
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
					{
						LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
							Group: "other.group",
							Kind:  "XBackend",
							Name:  gatewayv1.ObjectName(backendName),
						},
					},
				},
				Rules: []agenticv0alpha0.AccessRule{{Name: "rule1"}},
			},
		}
		if err := indexer.Add(policy); err != nil {
			t.Fatalf("indexer.Add: %v", err)
		}
		c := &Controller{
			agentic: agenticNetResources{
				accessPolicyLister: agenticlisters.NewXAccessPolicyLister(indexer),
			},
		}
		backend := &agenticv0alpha0.XBackend{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: backendName},
		}
		if hasAccessPoliciesTargetingBackend(c, backend) {
			t.Error("expected false when only targetRef has wrong group (not XBackend)")
		}
	})

	t.Run("multiple targetRefs one matches backend", func(t *testing.T) {
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		policy := &agenticv0alpha0.XAccessPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "policy-1"},
			Spec: agenticv0alpha0.AccessPolicySpec{
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
					{
						LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
							Group: agenticv0alpha0.GroupName,
							Kind:  "XBackend",
							Name:  gatewayv1.ObjectName("other-backend"),
						},
					},
					{
						LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
							Group: agenticv0alpha0.GroupName,
							Kind:  "XBackend",
							Name:  gatewayv1.ObjectName(backendName),
						},
					},
				},
				Rules: []agenticv0alpha0.AccessRule{{Name: "rule1"}},
			},
		}
		if err := indexer.Add(policy); err != nil {
			t.Fatalf("indexer.Add: %v", err)
		}
		c := &Controller{
			agentic: agenticNetResources{
				accessPolicyLister: agenticlisters.NewXAccessPolicyLister(indexer),
			},
		}
		backend := &agenticv0alpha0.XBackend{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: backendName},
		}
		if !hasAccessPoliciesTargetingBackend(c, backend) {
			t.Error("expected true when one targetRef matches this backend")
		}
	})
}
