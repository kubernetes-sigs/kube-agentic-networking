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
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
)

// configMapDesiredMatchesExisting reports whether the live ConfigMap already matches what we
// would send on server-side apply (see configMapApply), so we can skip a redundant Apply.
//
// Managed fields (must match want for this function to return true):
//   - metadata.labels, metadata.annotations
//   - metadata.ownerReferences
//   - immutable (when set on want)
//   - data, binaryData
//
// Unmanaged / intentionally ignored:
//   - metadata.uid, resourceVersion, creationTimestamp, managedFields, etc.
//   - Extra keys in live data not present in want count as drift (we re-Apply).
func configMapDesiredMatchesExisting(want, got *corev1.ConfigMap) bool {
	if !apiequality.Semantic.DeepEqual(want.Labels, got.Labels) ||
		!apiequality.Semantic.DeepEqual(want.Annotations, got.Annotations) ||
		!apiequality.Semantic.DeepEqual(want.OwnerReferences, got.OwnerReferences) {
		return false
	}
	if (want.Immutable == nil) != (got.Immutable == nil) {
		return false
	}
	if want.Immutable != nil && got.Immutable != nil && *want.Immutable != *got.Immutable {
		return false
	}
	return apiequality.Semantic.DeepEqual(want.Data, got.Data) &&
		apiequality.Semantic.DeepEqual(want.BinaryData, got.BinaryData)
}

// serviceDesiredMatchesExisting reports whether the live Service already matches what we would
// send on server-side apply (see serviceApply), so we can skip a redundant Apply.
//
// Managed fields (must match want for this function to return true):
//   - metadata.labels, metadata.annotations, metadata.ownerReferences
//   - spec.type, spec.selector
//   - spec.ports (name, port, protocol), order-independent
//
// Unmanaged / intentionally ignored:
//   - spec.clusterIP, clusterIPs, nodePort, sessionAffinity, traffic distribution, ipFamilies, etc.
//   - status (including loadBalancer ingress)
//   - Extra labels/annotations on live objects vs want count as drift (same caveat as ServiceAccount).
func serviceDesiredMatchesExisting(want, got *corev1.Service) bool {
	if !apiequality.Semantic.DeepEqual(want.Labels, got.Labels) ||
		!apiequality.Semantic.DeepEqual(want.Annotations, got.Annotations) ||
		!apiequality.Semantic.DeepEqual(want.OwnerReferences, got.OwnerReferences) {
		return false
	}
	if want.Spec.Type != got.Spec.Type {
		return false
	}
	if !apiequality.Semantic.DeepEqual(want.Spec.Selector, got.Spec.Selector) {
		return false
	}
	return servicePortsManagedMatch(want.Spec.Ports, got.Spec.Ports)
}

func servicePortsManagedMatch(want, got []corev1.ServicePort) bool {
	if len(want) != len(got) {
		return false
	}
	type portKey struct {
		Name     string
		Port     int32
		Protocol corev1.Protocol
	}
	toKeys := func(ports []corev1.ServicePort) []portKey {
		out := make([]portKey, 0, len(ports))
		for i := range ports {
			p := ports[i]
			proto := p.Protocol
			if proto == "" {
				proto = corev1.ProtocolTCP
			}
			out = append(out, portKey{Name: p.Name, Port: p.Port, Protocol: proto})
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].Port != out[j].Port {
				return out[i].Port < out[j].Port
			}
			if out[i].Name != out[j].Name {
				return out[i].Name < out[j].Name
			}
			return out[i].Protocol < out[j].Protocol
		})
		return out
	}
	return apiequality.Semantic.DeepEqual(toKeys(want), toKeys(got))
}

// deploymentDesiredMatchesExisting reports whether the live Deployment already matches what we
// would send on server-side apply (see deploymentApply), including the pod template checksum
// annotation set in ensureDeployment before Apply.
//
// Managed fields (must match want for this function to return true):
//   - metadata.labels, metadata.annotations, metadata.ownerReferences
//   - spec.replicas, spec.selector
//   - spec.template metadata (labels, annotations), including infra config checksum annotation
//   - spec.template.spec after normalizing API defaults on pod fields we declare
//
// Unmanaged / intentionally ignored:
//   - status, generation, observedGeneration, collisionCount, etc.
//   - spec.strategy, minReadySeconds, revisionHistoryLimit, progressDeadlineSeconds (not set by deploymentApply)
//   - Pod fields we do not set in render; extra live-only fields count as drift.
func deploymentDesiredMatchesExisting(want, got *appsv1.Deployment) bool {
	if !apiequality.Semantic.DeepEqual(want.Labels, got.Labels) ||
		!apiequality.Semantic.DeepEqual(want.Annotations, got.Annotations) ||
		!apiequality.Semantic.DeepEqual(want.OwnerReferences, got.OwnerReferences) {
		return false
	}
	if (want.Spec.Replicas == nil) != (got.Spec.Replicas == nil) {
		return false
	}
	if want.Spec.Replicas != nil && got.Spec.Replicas != nil && *want.Spec.Replicas != *got.Spec.Replicas {
		return false
	}
	if !apiequality.Semantic.DeepEqual(want.Spec.Selector, got.Spec.Selector) {
		return false
	}
	if !apiequality.Semantic.DeepEqual(want.Spec.Template.Labels, got.Spec.Template.Labels) ||
		!apiequality.Semantic.DeepEqual(want.Spec.Template.Annotations, got.Spec.Template.Annotations) {
		return false
	}
	wantPS := want.Spec.Template.Spec.DeepCopy()
	gotPS := got.Spec.Template.Spec.DeepCopy()
	normalizePodSpecForCompare(wantPS)
	normalizePodSpecForCompare(gotPS)
	return apiequality.Semantic.DeepEqual(wantPS, gotPS)
}

func normalizePodSpecForCompare(ps *corev1.PodSpec) {
	if ps.RestartPolicy == "" {
		ps.RestartPolicy = corev1.RestartPolicyAlways
	}
	if ps.DNSPolicy == "" {
		ps.DNSPolicy = corev1.DNSClusterFirst
	}
	if ps.EnableServiceLinks == nil {
		t := true
		ps.EnableServiceLinks = &t
	}
	if ps.ShareProcessNamespace == nil {
		f := false
		ps.ShareProcessNamespace = &f
	}
	for i := range ps.Containers {
		c := &ps.Containers[i]
		if c.TerminationMessagePath == "" {
			c.TerminationMessagePath = "/dev/termination-log"
		}
		if c.TerminationMessagePolicy == "" {
			c.TerminationMessagePolicy = corev1.TerminationMessageReadFile
		}
		if c.ImagePullPolicy == "" {
			if strings.Contains(c.Image, ":") && !strings.HasSuffix(c.Image, ":latest") {
				c.ImagePullPolicy = corev1.PullIfNotPresent
			} else {
				c.ImagePullPolicy = corev1.PullAlways
			}
		}
	}
}
