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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
)

// ensureFinalizer adds the given finalizer to objectMeta if not present.
func ensureFinalizer(objectMeta *metav1.ObjectMeta, finalizer string) bool {
	if objectMeta.Finalizers == nil {
		objectMeta.Finalizers = []string{finalizer}
		return true
	}
	if sets.New(objectMeta.Finalizers...).Has(finalizer) {
		return false
	}
	objectMeta.Finalizers = append(objectMeta.Finalizers, finalizer)
	return true
}

// removeFinalizer removes the given finalizer from objectMeta if present.
func removeFinalizer(objectMeta *metav1.ObjectMeta, finalizer string) bool {
	if objectMeta.Finalizers == nil {
		return false
	}
	newFinalizers := make([]string, 0, len(objectMeta.Finalizers))
	for _, f := range objectMeta.Finalizers {
		if f != finalizer {
			newFinalizers = append(newFinalizers, f)
		}
	}
	if len(newFinalizers) == len(objectMeta.Finalizers) {
		return false
	}
	objectMeta.Finalizers = newFinalizers
	return true
}
