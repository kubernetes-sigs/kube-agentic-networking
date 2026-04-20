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

package envoy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

// ResourceManager manages the Envoy proxy resources for a given Gateway.
type ResourceManager struct {
	client                     kubernetes.Interface
	gw                         *gatewayv1.Gateway
	nodeID                     string
	envoyImage                 string
	namespace                  string
	agenticIdentityTrustDomain string
}

// NewResourceManager creates a new ResourceManager.
// The nodeID is generated based on the Gateway's namespace and name and is not exposed to the controller.
func NewResourceManager(client kubernetes.Interface, gw *gatewayv1.Gateway, envoyImage string, agenticIdentityTrustDomain string) *ResourceManager {
	return &ResourceManager{
		client:                     client,
		gw:                         gw,
		nodeID:                     proxyName(gw.Namespace, gw.Name),
		envoyImage:                 envoyImage,
		namespace:                  gw.Namespace,
		agenticIdentityTrustDomain: agenticIdentityTrustDomain,
	}
}

// proxyName generates a deterministic name for the Envoy proxy resources.
func proxyName(namespace, name string) string {
	namespacedName := types.NamespacedName{
		Namespace: namespace,
		Name:      name,
	}
	hash := sha256.Sum256([]byte(namespacedName.String()))
	return fmt.Sprintf(constants.ProxyNameFormat, hex.EncodeToString(hash[:6]))
}

// EnsureProxyExist ensures that the Envoy proxy deployment, service, and other resources exist and match desired state.
// It returns the LoadBalancer address (IP or Hostname) of the proxy service when assigned.
func (r *ResourceManager) EnsureProxyExist(ctx context.Context) (string, error) {
	logger := klog.FromContext(ctx).WithValues("resourceName", klog.KRef(r.namespace, r.nodeID))
	ctx = klog.NewContext(ctx, logger)

	if err := r.ensureSA(ctx); err != nil {
		return "", err
	}

	if err := r.ensureConfigMap(ctx); err != nil {
		return "", err
	}

	if err := r.ensureDeployment(ctx); err != nil {
		return "", err
	}

	return r.ensureService(ctx)
}

func (r *ResourceManager) NodeID() string {
	return r.nodeID
}

// ensureSA applies the ServiceAccount for the Envoy proxy (server-side apply).
func (r *ResourceManager) ensureSA(ctx context.Context) error {
	logger := klog.FromContext(ctx)
	want := r.renderServiceAccount()
	if _, err := r.client.CoreV1().ServiceAccounts(want.Namespace).Apply(ctx, serviceAccountApply(want), envoyInfraApplyOptions()); err != nil {
		return fmt.Errorf("failed to apply envoy serviceaccount: %w", err)
	}
	logger.Info("Envoy proxy serviceaccount applied", "name", want.Name, "namespace", want.Namespace)
	return nil
}

// ensureConfigMap applies the ConfigMap for the Envoy proxy (server-side apply).
func (r *ResourceManager) ensureConfigMap(ctx context.Context) error {
	logger := klog.FromContext(ctx)
	want, err := r.renderConfigMap()
	if err != nil {
		return err
	}
	if _, err = r.client.CoreV1().ConfigMaps(want.Namespace).Apply(ctx, configMapApply(want), envoyInfraApplyOptions()); err != nil {
		return fmt.Errorf("failed to apply envoy configmap: %w", err)
	}
	logger.Info("Envoy bootstrap configmap applied", "name", want.Name, "namespace", want.Namespace)
	return nil
}

// ensureDeployment applies the Envoy Deployment (server-side apply). It does not wait for the
// Deployment Available condition so the controller is not blocked from reconciling other Gateways
// while a rollout is in progress.
func (r *ResourceManager) ensureDeployment(ctx context.Context) error {
	logger := klog.FromContext(ctx)
	cm, err := r.renderConfigMap()
	if err != nil {
		return err
	}
	want := r.renderDeployment()
	if want.Spec.Template.Annotations == nil {
		want.Spec.Template.Annotations = map[string]string{}
	}
	want.Spec.Template.Annotations[constants.EnvoyInfraConfigChecksumAnnotation] = configMapDataChecksum(cm)

	if _, err = r.client.AppsV1().Deployments(want.Namespace).Apply(ctx, deploymentApply(want), envoyInfraApplyOptions()); err != nil {
		return fmt.Errorf("failed to apply envoy deployment: %w", err)
	}
	logger.Info("Envoy proxy deployment applied (rollout may still be in progress)", "name", want.Name, "namespace", want.Namespace)
	return nil
}

// ensureService applies the Service for the Envoy proxy (server-side apply), then reads status
// until a LoadBalancer address (IP or Hostname) is assigned.
func (r *ResourceManager) ensureService(ctx context.Context) (string, error) {
	logger := klog.FromContext(ctx)
	want := r.renderService()
	if _, err := r.client.CoreV1().Services(want.Namespace).Apply(ctx, serviceApply(want), envoyInfraApplyOptions()); err != nil {
		return "", fmt.Errorf("failed to apply envoy service: %w", err)
	}
	logger.Info("Envoy proxy service applied", "name", want.Name, "namespace", want.Namespace)

	svc, err := r.client.CoreV1().Services(want.Namespace).Get(ctx, want.Name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to refresh envoy service: %w", err)
	}

	if svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
		return "", fmt.Errorf("envoy service %s type is %s, expected %s", want.Name, svc.Spec.Type, corev1.ServiceTypeLoadBalancer)
	}

	if len(svc.Status.LoadBalancer.Ingress) == 0 {
		return "", fmt.Errorf("loadbalancer address is not assigned yet for service %s", want.Name)
	}

	ingress := svc.Status.LoadBalancer.Ingress[0]
	address := ingress.IP
	if address == "" {
		address = ingress.Hostname
	}
	if address == "" {
		return "", fmt.Errorf("loadbalancer IP or Hostname is not assigned yet for service %s", want.Name)
	}

	logger.Info("Envoy proxy service is ready with LoadBalancer address!", "address", address)
	return address, nil
}

func DeleteProxy(ctx context.Context, client kubernetes.Interface, namespace, name string) error {
	nodeID := proxyName(namespace, name)
	logger := klog.FromContext(ctx).WithValues("resourceName", klog.KRef(namespace, nodeID))

	// Delete Deployment
	err := client.AppsV1().Deployments(namespace).Delete(ctx, nodeID, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete envoy deployment: %w", err)
	}
	logger.Info("Envoy deployment deleted")

	// Delete Service
	err = client.CoreV1().Services(namespace).Delete(ctx, nodeID, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete envoy service: %w", err)
	}
	logger.Info("Envoy service deleted")

	// Delete ConfigMap
	err = client.CoreV1().ConfigMaps(namespace).Delete(ctx, nodeID, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete envoy configmap: %w", err)
	}
	logger.Info("Envoy configmap deleted")

	// Delete ServiceAccount
	err = client.CoreV1().ServiceAccounts(namespace).Delete(ctx, nodeID, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete envoy serviceaccount: %w", err)
	}
	logger.Info("Envoy serviceaccount deleted")

	// TODO: Clean up xds cache, though it should be ok if we don't.
	return nil
}
