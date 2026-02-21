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
	"bytes"
	_ "embed"
	"fmt"
	"text/template"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
	"sigs.k8s.io/kube-agentic-networking/pkg/infra/agentidentity/agenticidentitysigner"
)

const (
	envoyBootstrapConfigVolumeName = "envoy-bootstrap-config"
	envoySdsConfigVolumeName       = "envoy-sds-config"
	envoyIdentityMtlsVolumeName    = "envoy-identity-mtls"
)

//go:embed templates/bootstrap.yaml
var bootstrapTemplate string

//go:embed templates/spiffe_identity.yaml
var spiffeIdentityTemplate string

//go:embed templates/spiffe_trust.yaml
var spiffeTrustTemplate string

type bootstrapConfigData struct {
	Cluster             string
	ID                  string
	ControlPlaneAddress string
	ControlPlanePort    int
}

type sdsConfigData struct {
	SdsConfigName                  string
	SpiffeMountPath                string
	SpiffeCredentialBundleFileName string
	SpiffeTrustBundleFileName      string
}

// generateEnvoyBootstrapConfig returns an envoy config generated from config data
func generateEnvoyBootstrapConfig(cluster, id string) (string, error) {
	if cluster == "" || id == "" {
		return "", fmt.Errorf("missing parameters for envoy config")
	}

	data := &bootstrapConfigData{
		Cluster:             cluster,
		ID:                  id,
		ControlPlaneAddress: fmt.Sprintf("%s.%s.svc.cluster.local", constants.XDSServerServiceName, constants.AgenticNetSystemNamespace),
		ControlPlanePort:    15001,
	}

	t, err := template.New("gateway-config").Parse(bootstrapTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse config template: %w", err)
	}
	// execute the template
	var buff bytes.Buffer
	err = t.Execute(&buff, data)
	if err != nil {
		return "", fmt.Errorf("error executing config template: %w", err)
	}
	return buff.String(), nil
}

func generateSdsConfig(tmpl, sdsConfigName, trustDomain string) (string, error) {
	data := &sdsConfigData{
		SdsConfigName:                  sdsConfigName,
		SpiffeMountPath:                constants.SpiffeMountPath,
		SpiffeCredentialBundleFileName: constants.SpiffeCredentialBundleFileName,
		SpiffeTrustBundleFileName:      constants.SpiffeTrustBundleFileName(trustDomain),
	}
	t, err := template.New("sds-config").Parse(tmpl)
	if err != nil {
		return "", err
	}
	var buff bytes.Buffer
	if err := t.Execute(&buff, data); err != nil {
		return "", err
	}
	return buff.String(), nil
}

// renderConfigMap creates a ConfigMap for envoy bootstrap config and SDS configs.
func (r *ResourceManager) renderConfigMap() (*corev1.ConfigMap, error) {
	bootstrap, err := generateEnvoyBootstrapConfig(types.NamespacedName{
		Namespace: r.gw.Namespace,
		Name:      r.gw.Name,
	}.String(), r.nodeID)
	if err != nil {
		return nil, err
	}

	identitySds, err := generateSdsConfig(spiffeIdentityTemplate, constants.SpiffeIdentitySdsConfigName, r.agenticIdentityTrustDomain)
	if err != nil {
		return nil, err
	}

	trustSds, err := generateSdsConfig(spiffeTrustTemplate, constants.SpiffeTrustSdsConfigName, r.agenticIdentityTrustDomain)
	if err != nil {
		return nil, err
	}

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:            r.nodeID,
			Namespace:       r.namespace,
			OwnerReferences: ownerRef(r.gw),
		},
		Data: map[string]string{
			constants.EnvoyBootstrapCfgFileName: bootstrap,
			constants.SpiffeIdentitySdsFileName: identitySds,
			constants.SpiffeTrustSdsFileName:    trustSds,
		},
	}, nil
}

func (r *ResourceManager) renderDeployment() *appsv1.Deployment {
	replicas := int32(1)
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.nodeID,
			Namespace: r.namespace,
			Labels: map[string]string{
				constants.GatewayNameLabel: r.gw.Name,
			},
			OwnerReferences: ownerRef(r.gw),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					constants.GatewayNameLabel: r.gw.Name,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app":                      r.nodeID,
						constants.GatewayNameLabel: r.gw.Name,
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: r.nodeID,
					Containers: []corev1.Container{
						{
							Name:    "envoy-proxy",
							Image:   r.envoyImage,
							Command: []string{"envoy", "-c", fmt.Sprintf("%s/%s", constants.EnvoyBootstrapMountPath, constants.EnvoyBootstrapCfgFileName), "--log-level", "debug"},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      envoyBootstrapConfigVolumeName,
									MountPath: constants.EnvoyBootstrapMountPath,
									ReadOnly:  true,
								},
								{
									Name:      envoySdsConfigVolumeName,
									MountPath: constants.EnvoySdsMountPath,
									ReadOnly:  true,
								},
								{
									Name:      envoyIdentityMtlsVolumeName,
									MountPath: constants.SpiffeMountPath,
									ReadOnly:  true,
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							// envoy-bootstrap-config holds the static Envoy startup configuration.
							Name: envoyBootstrapConfigVolumeName,
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: r.nodeID,
									},
									Items: []corev1.KeyToPath{
										{
											Key:  constants.EnvoyBootstrapCfgFileName,
											Path: constants.EnvoyBootstrapCfgFileName,
										},
									},
								},
							},
						},
						{
							// envoy-sds-config holds the dynamic SDS configuration files.
							// These files act as a bridge, pointing Envoy's TLS configuration to the physical
							// certificate files mounted in the 'envoy-identity-mtls' volume below.
							//
							// Note:
							// 	Loading the certificate chain and private key separately can cause
							//	problems during certificate rotation.
							// 	https://github.com/kubernetes-sigs/kube-agentic-networking/issues/101
							Name: envoySdsConfigVolumeName,
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: r.nodeID,
									},
									Items: []corev1.KeyToPath{
										{
											Key:  constants.SpiffeIdentitySdsFileName,
											Path: constants.SpiffeIdentitySdsFileName,
										},
										{
											Key:  constants.SpiffeTrustSdsFileName,
											Path: constants.SpiffeTrustSdsFileName,
										},
									},
								},
							},
						},
						{
							// envoy-identity-mtls holds the actual secret material (certificates and keys)
							// generated by the Kubernetes Pod Certificate Signer.
							Name: envoyIdentityMtlsVolumeName,
							VolumeSource: corev1.VolumeSource{
								Projected: &corev1.ProjectedVolumeSource{
									Sources: []corev1.VolumeProjection{
										{
											ClusterTrustBundle: &corev1.ClusterTrustBundleProjection{
												SignerName: ptr.To(agenticidentitysigner.Name),
												LabelSelector: &metav1.LabelSelector{
													MatchLabels: agenticidentitysigner.CTBLabels(r.agenticIdentityTrustDomain),
												},
												Path: constants.SpiffeTrustBundleFileName(r.agenticIdentityTrustDomain),
											},
										},
										{
											PodCertificate: &corev1.PodCertificateProjection{
												SignerName:           agenticidentitysigner.Name,
												KeyType:              constants.DefaultKeyType,
												CredentialBundlePath: constants.SpiffeCredentialBundleFileName,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func (r *ResourceManager) renderService() *corev1.Service {
	ports := []corev1.ServicePort{}
	for _, listener := range r.gw.Spec.Listeners {
		ports = append(ports, corev1.ServicePort{
			Name:     string(listener.Name),
			Port:     int32(listener.Port),
			Protocol: corev1.ProtocolTCP, // TODO : Support other protocols if needed.
		})
	}

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.nodeID,
			Namespace: r.namespace,
			Labels: map[string]string{
				constants.GatewayNameLabel: r.gw.Name,
			},
			OwnerReferences: ownerRef(r.gw),
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Selector: map[string]string{
				"app": r.nodeID,
			},
			Ports: ports,
		},
	}
}

func (r *ResourceManager) renderServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.nodeID,
			Namespace: r.namespace,
			Labels: map[string]string{
				constants.GatewayNameLabel: r.gw.Name,
			},
			OwnerReferences: ownerRef(r.gw),
		},
	}
}

func ownerRef(gw *gatewayv1.Gateway) []metav1.OwnerReference {
	return []metav1.OwnerReference{*metav1.NewControllerRef(gw, gatewayv1.SchemeGroupVersion.WithKind("Gateway"))}
}
