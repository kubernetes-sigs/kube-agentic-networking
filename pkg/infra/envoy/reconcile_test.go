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
)

func TestConfigMapDataChecksum(t *testing.T) {
	cm := &corev1.ConfigMap{
		Data: map[string]string{"b": "2", "a": "1"},
	}
	h1 := configMapDataChecksum(cm)
	cm.Data["a"] = "changed"
	h2 := configMapDataChecksum(cm)
	if h1 == h2 {
		t.Fatal("expected digest to change when data changes")
	}
	cm2 := &corev1.ConfigMap{Data: map[string]string{"a": "1", "b": "2"}}
	if configMapDataChecksum(cm2) != h1 {
		t.Fatal("expected stable digest for same key/value pairs regardless of map iteration order")
	}
}
