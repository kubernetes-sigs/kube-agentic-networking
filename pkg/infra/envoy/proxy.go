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
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

// ResourceManager manages the Envoy proxy resources for a given Gateway.
type ResourceManager struct {
	client     kubernetes.Interface
	gw         *gatewayv1.Gateway
	nodeID     string
	envoyImage string
	namespace  string
}

// NewResourceManager creates a new ResourceManager.
// The nodeID is generated based on the Gateway's namespace and name and is not exposed to the controller.
func NewResourceManager(client kubernetes.Interface, gw *gatewayv1.Gateway, envoyImage string) *ResourceManager {
	return &ResourceManager{
		client:     client,
		gw:         gw,
		nodeID:     proxyName(gw.Namespace, gw.Name),
		envoyImage: envoyImage,
		namespace:  gw.Namespace,
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

// EnsureProxyExist ensures that the Envoy proxy deployment, service, and other resources exist and are ready.
func (r *ResourceManager) EnsureProxyExist(ctx context.Context) error {
	logger := klog.FromContext(ctx).WithValues("resourceName", klog.KRef(r.namespace, r.nodeID))
	ctx = klog.NewContext(ctx, logger)

	if err := r.ensureSA(ctx); err != nil {
		return err
	}

	if err := r.ensureConfigMap(ctx); err != nil {
		return err
	}

	if err := r.ensureDeployment(ctx); err != nil {
		return err
	}

	if err := r.ensureService(ctx); err != nil {
		return err
	}

	return nil
}

func (r *ResourceManager) NodeID() string {
	return r.nodeID
}

func (r *ResourceManager) ensureSA(ctx context.Context) error {
	logger := klog.FromContext(ctx)

	sa := r.renderServiceAccount()
	_, err := r.client.CoreV1().ServiceAccounts(sa.Namespace).Get(ctx, sa.Name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			_, err = r.client.CoreV1().ServiceAccounts(sa.Namespace).Create(ctx, sa, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("failed to create envoy serviceaccount: %w", err)
			}
		} else {
			return fmt.Errorf("failed to get envoy serviceaccount: %w", err)
		}
	}
	logger.Info("Envoy proxy serviceaccount is ready!")
	return nil
}

func (r *ResourceManager) ensureConfigMap(ctx context.Context) error {
	logger := klog.FromContext(ctx)
	cm, err := r.renderConfigMap()
	if err != nil {
		return err
	}

	_, err = r.client.CoreV1().ConfigMaps(cm.Namespace).Get(ctx, cm.Name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			_, err = r.client.CoreV1().ConfigMaps(cm.Namespace).Create(ctx, cm, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("failed to create envoy configmap: %w", err)
			}
		} else {
			return fmt.Errorf("failed to get envoy configmap: %w", err)
		}
	}

	logger.Info("Envoy bootstrap configmap is ready!")
	return nil
}

func (r *ResourceManager) ensureDeployment(ctx context.Context) error {
	logger := klog.FromContext(ctx)

	deployment := r.renderDeployment()
	_, err := r.client.AppsV1().Deployments(deployment.Namespace).Get(ctx, deployment.Name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			_, err = r.client.AppsV1().Deployments(deployment.Namespace).Create(ctx, deployment, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("failed to create envoy deployment: %w", err)
			}
		} else {
			return fmt.Errorf("failed to get envoy deployment: %w", err)
		}
	}

	if err := waitForDeploymentAvailable(ctx, r.client, deployment.Namespace, deployment.Name); err != nil {
		return err
	}
	logger.Info("Envoy proxy deployment is ready!")
	return nil
}

func (r *ResourceManager) ensureService(ctx context.Context) error {
	logger := klog.FromContext(ctx)
	service := r.renderService()
	_, err := r.client.CoreV1().Services(service.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			_, err = r.client.CoreV1().Services(service.Namespace).Create(ctx, service, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("failed to create envoy service: %w", err)
			}
		} else {
			return fmt.Errorf("failed to get envoy service: %w", err)
		}
	}

	if err := waitForServiceReady(ctx, r.client, service.Namespace, service.Name); err != nil {
		return err
	}
	logger.Info("Envoy proxy service is ready!")
	return nil
}

func waitForServiceReady(ctx context.Context, client kubernetes.Interface, namespace, name string) error {
	logger := klog.FromContext(ctx)
	logger.Info("Waiting for envoy service to be ready...")
	err := wait.PollUntilContextTimeout(ctx, 2*time.Second, 1*time.Minute, true, func(ctx context.Context) (bool, error) {
		svc, err := client.CoreV1().Services(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if svc.Spec.ClusterIP != "" {
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return fmt.Errorf("waiting for envoy service %s to be ready: %w", name, err)
	}
	return nil
}

func waitForDeploymentAvailable(ctx context.Context, client kubernetes.Interface, namespace, name string) error {
	logger := klog.FromContext(ctx)
	logger.Info("Waiting for envoy deployment to be available...")
	err := wait.PollUntilContextTimeout(ctx, 2*time.Second, 1*time.Minute, true, func(ctx context.Context) (bool, error) {
		dep, err := client.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		for _, cond := range dep.Status.Conditions {
			if cond.Type == appsv1.DeploymentAvailable && cond.Status == corev1.ConditionTrue {
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		return fmt.Errorf("waiting for envoy deployment %s to be available: %w", name, err)
	}
	return nil
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
