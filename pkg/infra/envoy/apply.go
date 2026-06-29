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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	applyappsv1 "k8s.io/client-go/applyconfigurations/apps/v1"
	applycorev1 "k8s.io/client-go/applyconfigurations/core/v1"
	applymetav1 "k8s.io/client-go/applyconfigurations/meta/v1"
)

// envoyInfraFieldManager is the server-side apply field manager for Envoy proxy
// ServiceAccount, ConfigMap, Deployment, and Service objects.
const envoyInfraFieldManager = "agentic-networking.sigs.k8s.io/envoy-proxy"

func envoyInfraApplyOptions() metav1.ApplyOptions {
	return metav1.ApplyOptions{
		FieldManager: envoyInfraFieldManager,
		Force:        true,
	}
}

func ownerReferencesApply(refs []metav1.OwnerReference) []*applymetav1.OwnerReferenceApplyConfiguration {
	out := make([]*applymetav1.OwnerReferenceApplyConfiguration, 0, len(refs))
	for _, ref := range refs {
		r := applymetav1.OwnerReference().
			WithAPIVersion(ref.APIVersion).
			WithKind(ref.Kind).
			WithName(ref.Name).
			WithUID(ref.UID)
		if ref.Controller != nil {
			r.WithController(*ref.Controller)
		}
		if ref.BlockOwnerDeletion != nil {
			r.WithBlockOwnerDeletion(*ref.BlockOwnerDeletion)
		}
		out = append(out, r)
	}
	return out
}

func serviceAccountApply(sa *corev1.ServiceAccount) *applycorev1.ServiceAccountApplyConfiguration {
	b := applycorev1.ServiceAccount(sa.Name, sa.Namespace)
	if len(sa.Labels) > 0 {
		b.WithLabels(sa.Labels)
	}
	if len(sa.Annotations) > 0 {
		b.WithAnnotations(sa.Annotations)
	}
	if len(sa.OwnerReferences) > 0 {
		b.WithOwnerReferences(ownerReferencesApply(sa.OwnerReferences)...)
	}
	return b
}

func configMapApply(cm *corev1.ConfigMap) *applycorev1.ConfigMapApplyConfiguration {
	b := applycorev1.ConfigMap(cm.Name, cm.Namespace)
	if len(cm.Labels) > 0 {
		b.WithLabels(cm.Labels)
	}
	if len(cm.Annotations) > 0 {
		b.WithAnnotations(cm.Annotations)
	}
	if len(cm.OwnerReferences) > 0 {
		b.WithOwnerReferences(ownerReferencesApply(cm.OwnerReferences)...)
	}
	if cm.Immutable != nil {
		b.WithImmutable(*cm.Immutable)
	}
	b.Data = cm.Data
	b.BinaryData = cm.BinaryData
	return b
}

func serviceApply(svc *corev1.Service) *applycorev1.ServiceApplyConfiguration {
	b := applycorev1.Service(svc.Name, svc.Namespace)
	if len(svc.Labels) > 0 {
		b.WithLabels(svc.Labels)
	}
	if len(svc.Annotations) > 0 {
		b.WithAnnotations(svc.Annotations)
	}
	if len(svc.OwnerReferences) > 0 {
		b.WithOwnerReferences(ownerReferencesApply(svc.OwnerReferences)...)
	}
	spec := applycorev1.ServiceSpec().WithType(svc.Spec.Type).WithSelector(svc.Spec.Selector)
	ports := make([]*applycorev1.ServicePortApplyConfiguration, 0, len(svc.Spec.Ports))
	for i := range svc.Spec.Ports {
		p := &svc.Spec.Ports[i]
		sp := applycorev1.ServicePort().
			WithName(p.Name).
			WithPort(p.Port).
			WithProtocol(p.Protocol)
		ports = append(ports, sp)
	}
	spec.WithPorts(ports...)
	b.WithSpec(spec)
	return b
}

func deploymentApply(d *appsv1.Deployment) *applyappsv1.DeploymentApplyConfiguration {
	dep := applyappsv1.Deployment(d.Name, d.Namespace)
	if len(d.Labels) > 0 {
		dep.WithLabels(d.Labels)
	}
	if len(d.Annotations) > 0 {
		dep.WithAnnotations(d.Annotations)
	}
	if len(d.OwnerReferences) > 0 {
		dep.WithOwnerReferences(ownerReferencesApply(d.OwnerReferences)...)
	}
	spec := applyappsv1.DeploymentSpec()
	if d.Spec.Replicas != nil {
		spec.WithReplicas(*d.Spec.Replicas)
	}
	if d.Spec.Selector != nil {
		spec.WithSelector(applymetav1.LabelSelector().WithMatchLabels(d.Spec.Selector.MatchLabels))
	}
	tpl := applycorev1.PodTemplateSpec()
	if len(d.Spec.Template.Labels) > 0 {
		tpl.WithLabels(d.Spec.Template.Labels)
	}
	if len(d.Spec.Template.Annotations) > 0 {
		tpl.WithAnnotations(d.Spec.Template.Annotations)
	}
	tpl.WithSpec(podSpecApply(&d.Spec.Template.Spec))
	spec.WithTemplate(tpl)
	dep.WithSpec(spec)
	return dep
}

func podSpecApply(ps *corev1.PodSpec) *applycorev1.PodSpecApplyConfiguration {
	out := applycorev1.PodSpec().WithServiceAccountName(ps.ServiceAccountName)
	vols := make([]*applycorev1.VolumeApplyConfiguration, 0, len(ps.Volumes))
	for i := range ps.Volumes {
		vols = append(vols, volumeApply(&ps.Volumes[i]))
	}
	if len(vols) > 0 {
		out.WithVolumes(vols...)
	}
	ctrs := make([]*applycorev1.ContainerApplyConfiguration, 0, len(ps.Containers))
	for i := range ps.Containers {
		ctrs = append(ctrs, containerApply(&ps.Containers[i]))
	}
	if len(ctrs) > 0 {
		out.WithContainers(ctrs...)
	}
	return out
}

func containerApply(c *corev1.Container) *applycorev1.ContainerApplyConfiguration {
	out := applycorev1.Container().WithName(c.Name).WithImage(c.Image)
	for _, s := range c.Command {
		out.WithCommand(s)
	}
	for _, s := range c.Args {
		out.WithArgs(s)
	}
	for i := range c.VolumeMounts {
		out.WithVolumeMounts(volumeMountApply(&c.VolumeMounts[i]))
	}
	return out
}

func volumeMountApply(vm *corev1.VolumeMount) *applycorev1.VolumeMountApplyConfiguration {
	m := applycorev1.VolumeMount().WithName(vm.Name).WithMountPath(vm.MountPath)
	if vm.ReadOnly {
		m.WithReadOnly(true)
	}
	if vm.SubPath != "" {
		m.WithSubPath(vm.SubPath)
	}
	if vm.MountPropagation != nil {
		m.WithMountPropagation(*vm.MountPropagation)
	}
	if vm.RecursiveReadOnly != nil {
		m.WithRecursiveReadOnly(*vm.RecursiveReadOnly)
	}
	if vm.SubPathExpr != "" {
		m.WithSubPathExpr(vm.SubPathExpr)
	}
	return m
}

func volumeApply(v *corev1.Volume) *applycorev1.VolumeApplyConfiguration {
	va := applycorev1.Volume().WithName(v.Name)
	if v.ConfigMap != nil {
		cm := applycorev1.ConfigMapVolumeSource().WithName(v.ConfigMap.Name)
		if v.ConfigMap.DefaultMode != nil {
			cm.WithDefaultMode(*v.ConfigMap.DefaultMode)
		}
		for i := range v.ConfigMap.Items {
			cm.WithItems(keyToPathApply(&v.ConfigMap.Items[i]))
		}
		if v.ConfigMap.Optional != nil {
			cm.WithOptional(*v.ConfigMap.Optional)
		}
		return va.WithConfigMap(cm)
	}
	if v.Projected != nil {
		pj := applycorev1.ProjectedVolumeSource()
		if v.Projected.DefaultMode != nil {
			pj.WithDefaultMode(*v.Projected.DefaultMode)
		}
		for i := range v.Projected.Sources {
			pj.WithSources(volumeProjectionApply(&v.Projected.Sources[i]))
		}
		return va.WithProjected(pj)
	}
	return va
}

func keyToPathApply(k *corev1.KeyToPath) *applycorev1.KeyToPathApplyConfiguration {
	kp := applycorev1.KeyToPath().WithKey(k.Key).WithPath(k.Path)
	if k.Mode != nil {
		kp.WithMode(*k.Mode)
	}
	return kp
}

func volumeProjectionApply(p *corev1.VolumeProjection) *applycorev1.VolumeProjectionApplyConfiguration {
	vp := applycorev1.VolumeProjection()
	if p.ClusterTrustBundle != nil {
		ctb := applycorev1.ClusterTrustBundleProjection().WithPath(p.ClusterTrustBundle.Path)
		if p.ClusterTrustBundle.Name != nil {
			ctb.WithName(*p.ClusterTrustBundle.Name)
		}
		if p.ClusterTrustBundle.SignerName != nil {
			ctb.WithSignerName(*p.ClusterTrustBundle.SignerName)
		}
		if p.ClusterTrustBundle.LabelSelector != nil {
			ls := applymetav1.LabelSelector()
			if len(p.ClusterTrustBundle.LabelSelector.MatchLabels) > 0 {
				ls.WithMatchLabels(p.ClusterTrustBundle.LabelSelector.MatchLabels)
			}
			ctb.WithLabelSelector(ls)
		}
		if p.ClusterTrustBundle.Optional != nil {
			ctb.WithOptional(*p.ClusterTrustBundle.Optional)
		}
		vp.WithClusterTrustBundle(ctb)
	}
	if p.PodCertificate != nil {
		pc := applycorev1.PodCertificateProjection().
			WithSignerName(p.PodCertificate.SignerName).
			WithKeyType(p.PodCertificate.KeyType)
		if p.PodCertificate.MaxExpirationSeconds != nil {
			pc.WithMaxExpirationSeconds(*p.PodCertificate.MaxExpirationSeconds)
		}
		if p.PodCertificate.CredentialBundlePath != "" {
			pc.WithCredentialBundlePath(p.PodCertificate.CredentialBundlePath)
		}
		if p.PodCertificate.KeyPath != "" {
			pc.WithKeyPath(p.PodCertificate.KeyPath)
		}
		if p.PodCertificate.CertificateChainPath != "" {
			pc.WithCertificateChainPath(p.PodCertificate.CertificateChainPath)
		}
		if len(p.PodCertificate.UserAnnotations) > 0 {
			pc.WithUserAnnotations(p.PodCertificate.UserAnnotations)
		}
		vp.WithPodCertificate(pc)
	}
	return vp
}
