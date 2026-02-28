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

package controller

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const testFinalizer = "test.example.com/finalizer"

func TestEnsureFinalizer(t *testing.T) {
	t.Run("nil finalizers", func(t *testing.T) {
		obj := &metav1.ObjectMeta{}
		changed := ensureFinalizer(obj, testFinalizer)
		if !changed {
			t.Error("expected true when Finalizers was nil")
		}
		if len(obj.Finalizers) != 1 || obj.Finalizers[0] != testFinalizer {
			t.Errorf("expected Finalizers to be [%q], got %v", testFinalizer, obj.Finalizers)
		}
	})

	t.Run("empty finalizers slice", func(t *testing.T) {
		obj := &metav1.ObjectMeta{Finalizers: []string{}}
		changed := ensureFinalizer(obj, testFinalizer)
		if !changed {
			t.Error("expected true when Finalizers was empty")
		}
		if len(obj.Finalizers) != 1 || obj.Finalizers[0] != testFinalizer {
			t.Errorf("expected Finalizers to be [%q], got %v", testFinalizer, obj.Finalizers)
		}
	})

	t.Run("finalizer already present", func(t *testing.T) {
		obj := &metav1.ObjectMeta{Finalizers: []string{testFinalizer}}
		changed := ensureFinalizer(obj, testFinalizer)
		if changed {
			t.Error("expected false when finalizer already present")
		}
		if len(obj.Finalizers) != 1 || obj.Finalizers[0] != testFinalizer {
			t.Errorf("expected Finalizers unchanged [%q], got %v", testFinalizer, obj.Finalizers)
		}
	})

	t.Run("other finalizers present, add new one", func(t *testing.T) {
		obj := &metav1.ObjectMeta{Finalizers: []string{"other.example.com/keep"}}
		changed := ensureFinalizer(obj, testFinalizer)
		if !changed {
			t.Error("expected true when adding new finalizer")
		}
		if len(obj.Finalizers) != 2 {
			t.Errorf("expected 2 finalizers, got %v", obj.Finalizers)
		}
		has := false
		for _, f := range obj.Finalizers {
			if f == testFinalizer {
				has = true
				break
			}
		}
		if !has {
			t.Errorf("expected %q in Finalizers, got %v", testFinalizer, obj.Finalizers)
		}
	})
}

func TestRemoveFinalizer(t *testing.T) {
	t.Run("nil finalizers", func(t *testing.T) {
		obj := &metav1.ObjectMeta{}
		changed := removeFinalizer(obj, testFinalizer)
		if changed {
			t.Error("expected false when Finalizers was nil")
		}
		if obj.Finalizers != nil {
			t.Errorf("expected Finalizers to stay nil, got %v", obj.Finalizers)
		}
	})

	t.Run("empty finalizers slice", func(t *testing.T) {
		obj := &metav1.ObjectMeta{Finalizers: []string{}}
		changed := removeFinalizer(obj, testFinalizer)
		if changed {
			t.Error("expected false when Finalizers was empty")
		}
		if len(obj.Finalizers) != 0 {
			t.Errorf("expected Finalizers unchanged [], got %v", obj.Finalizers)
		}
	})

	t.Run("finalizer not in list", func(t *testing.T) {
		obj := &metav1.ObjectMeta{Finalizers: []string{"other.example.com/keep"}}
		changed := removeFinalizer(obj, testFinalizer)
		if changed {
			t.Error("expected false when finalizer not present")
		}
		if len(obj.Finalizers) != 1 || obj.Finalizers[0] != "other.example.com/keep" {
			t.Errorf("expected Finalizers unchanged, got %v", obj.Finalizers)
		}
	})

	t.Run("finalizer only one in list", func(t *testing.T) {
		obj := &metav1.ObjectMeta{Finalizers: []string{testFinalizer}}
		changed := removeFinalizer(obj, testFinalizer)
		if !changed {
			t.Error("expected true when removing the only finalizer")
		}
		if len(obj.Finalizers) != 0 {
			t.Errorf("expected empty Finalizers, got %v", obj.Finalizers)
		}
	})

	t.Run("finalizer one of several", func(t *testing.T) {
		obj := &metav1.ObjectMeta{
			Finalizers: []string{"first.example.com/f", testFinalizer, "last.example.com/l"},
		}
		changed := removeFinalizer(obj, testFinalizer)
		if !changed {
			t.Error("expected true when removing finalizer from list")
		}
		if len(obj.Finalizers) != 2 {
			t.Errorf("expected 2 finalizers left, got %v", obj.Finalizers)
		}
		for _, f := range obj.Finalizers {
			if f == testFinalizer {
				t.Errorf("expected %q removed from Finalizers, got %v", testFinalizer, obj.Finalizers)
				break
			}
		}
	})
}
