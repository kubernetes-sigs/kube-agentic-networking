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

package envoy

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestConfigMapDesiredMatchesExisting(t *testing.T) {
	base := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "cm1",
			Namespace:       "ns",
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Gateway", Name: "gw", UID: "uid"}},
		},
		Data: map[string]string{"k": "v"},
	}
	got := base.DeepCopy()
	got.ResourceVersion = "7"
	got.UID = "abc"
	if !configMapDesiredMatchesExisting(base, got) {
		t.Fatal("expected match when only apiserver metadata differs")
	}
	got2 := base.DeepCopy()
	got2.Data["k"] = "other"
	if configMapDesiredMatchesExisting(base, got2) {
		t.Fatal("expected mismatch when data changes")
	}
}

func TestServicePortsManagedMatch(t *testing.T) {
	a := []corev1.ServicePort{
		{Name: "b", Port: 2, Protocol: corev1.ProtocolTCP},
		{Name: "a", Port: 1, Protocol: corev1.ProtocolTCP},
	}
	b := []corev1.ServicePort{
		{Name: "a", Port: 1},
		{Name: "b", Port: 2, Protocol: corev1.ProtocolTCP},
	}
	if !servicePortsManagedMatch(a, b) {
		t.Fatal("expected order-independent match with default protocol normalization")
	}
	if servicePortsManagedMatch(a, []corev1.ServicePort{{Name: "a", Port: 1}}) {
		t.Fatal("expected mismatch when port count differs")
	}
}
