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
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"time"

	"k8s.io/utils/ptr"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	gatewayclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
	gatewayinformers "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions/apis/v1"
	gatewayinformersv1beta1 "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions/apis/v1beta1"
	gatewaylisters "sigs.k8s.io/gateway-api/pkg/client/listers/apis/v1"
	gatewaylistersv1beta1 "sigs.k8s.io/gateway-api/pkg/client/listers/apis/v1beta1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	agenticclient "sigs.k8s.io/kube-agentic-networking/k8s/client/clientset/versioned"
	agenticinformers "sigs.k8s.io/kube-agentic-networking/k8s/client/informers/externalversions/api/v0alpha0"
	agenticlisters "sigs.k8s.io/kube-agentic-networking/k8s/client/listers/api/v0alpha0"
	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
	"sigs.k8s.io/kube-agentic-networking/pkg/infra/envoy"
	"sigs.k8s.io/kube-agentic-networking/pkg/infra/xds"
	"sigs.k8s.io/kube-agentic-networking/pkg/translator"
)

// maxGatewaySyncRetries is the maximum number of rate-limited requeues for a
// single Gateway key before the worker drops it (avoids infinite hot loops).
const maxGatewaySyncRetries = 15

// maxBackendFinalizerRetries is the same cap for the XBackend finalizer queue.
const maxBackendFinalizerRetries = 15

type coreResources struct {
	client kubernetes.Interface

	nsLister corev1listers.NamespaceLister
	nsSynced cache.InformerSynced

	svcLister corev1listers.ServiceLister
	svcSynced cache.InformerSynced

	secretLister corev1listers.SecretLister
	secretSynced cache.InformerSynced
}

type gatewayResources struct {
	client gatewayclient.Interface

	gatewayClassLister gatewaylisters.GatewayClassLister
	gatewayClassSynced cache.InformerSynced

	gatewayLister gatewaylisters.GatewayLister
	gatewaySynced cache.InformerSynced

	httprouteLister      gatewaylisters.HTTPRouteLister
	httprouteIndexer     cache.Indexer
	referenceGrantLister gatewaylistersv1beta1.ReferenceGrantLister
	httprouteSynced      cache.InformerSynced
	referenceGrantSynced cache.InformerSynced
}

type agenticNetResources struct {
	client agenticclient.Interface

	backendLister agenticlisters.XBackendLister
	backendSynced cache.InformerSynced

	accessPolicyLister  agenticlisters.XAccessPolicyLister
	accessPolicyIndexer cache.Indexer
	accessPolicySynced  cache.InformerSynced
}

// Controller is the controller implementation for Gateway resources
type Controller struct {
	core    coreResources
	gateway gatewayResources
	agentic agenticNetResources

	agenticIdentityTrustDomain string
	envoyImage                 string

	gatewayqueue          workqueue.TypedRateLimitingInterface[string]
	backendFinalizerQueue workqueue.TypedRateLimitingInterface[string]
	xdsServer             *xds.Server
	translator            *translator.Translator
}

// New returns a new *Controller with the event handlers setup for types we are interested in.
func New(
	ctx context.Context,
	agenticIdentityTrustDomain string,
	envoyImage string,
	kubeClientSet kubernetes.Interface,
	gwClientSet gatewayclient.Interface,
	agenticClientSet agenticclient.Interface,
	namespaceInformer corev1informers.NamespaceInformer,
	serviceInformer corev1informers.ServiceInformer,
	secretInformer corev1informers.SecretInformer,
	gatewayClassInformer gatewayinformers.GatewayClassInformer,
	gatewayInformer gatewayinformers.GatewayInformer,
	httprouteInformer gatewayinformers.HTTPRouteInformer,
	referenceGrantInformer gatewayinformersv1beta1.ReferenceGrantInformer,
	backendInformer agenticinformers.XBackendInformer,
	accessPolicyInformer agenticinformers.XAccessPolicyInformer,
) (*Controller, error) {
	apInformer := accessPolicyInformer.Informer()
	if err := apInformer.AddIndexers(cache.Indexers{AccessPolicyTargetRefIndex: accessPolicyTargetRefIndexFunc}); err != nil {
		return nil, fmt.Errorf("add AccessPolicy targetRef index: %w", err)
	}

	c := &Controller{
		core: coreResources{
			client:       kubeClientSet,
			nsLister:     namespaceInformer.Lister(),
			nsSynced:     namespaceInformer.Informer().HasSynced,
			svcLister:    serviceInformer.Lister(),
			svcSynced:    serviceInformer.Informer().HasSynced,
			secretLister: secretInformer.Lister(),
			secretSynced: secretInformer.Informer().HasSynced,
		},
		gateway: gatewayResources{
			client:               gwClientSet,
			gatewayClassLister:   gatewayClassInformer.Lister(),
			gatewayClassSynced:   gatewayClassInformer.Informer().HasSynced,
			gatewayLister:        gatewayInformer.Lister(),
			gatewaySynced:        gatewayInformer.Informer().HasSynced,
			httprouteLister:      httprouteInformer.Lister(),
			httprouteIndexer:     httprouteInformer.Informer().GetIndexer(),
			referenceGrantLister: referenceGrantInformer.Lister(),
			httprouteSynced:      httprouteInformer.Informer().HasSynced,
			referenceGrantSynced: referenceGrantInformer.Informer().HasSynced,
		},
		agentic: agenticNetResources{
			client:              agenticClientSet,
			backendLister:       backendInformer.Lister(),
			backendSynced:       backendInformer.Informer().HasSynced,
			accessPolicyLister:  accessPolicyInformer.Lister(),
			accessPolicyIndexer: apInformer.GetIndexer(),
			accessPolicySynced:  apInformer.HasSynced,
		},
		agenticIdentityTrustDomain: agenticIdentityTrustDomain,
		envoyImage:                 envoyImage,
		gatewayqueue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.DefaultTypedControllerRateLimiter[string](),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "gateway"},
		),
		backendFinalizerQueue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.DefaultTypedControllerRateLimiter[string](),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "backend-finalizer"},
		),
		xdsServer: xds.NewServer(ctx),
	}

	c.translator = translator.New(
		agenticIdentityTrustDomain,
		kubeClientSet,
		gwClientSet,
		namespaceInformer.Lister(),
		serviceInformer.Lister(),
		secretInformer.Lister(),
		gatewayInformer.Lister(),
		httprouteInformer.Lister(),
		referenceGrantInformer.Lister(),
		accessPolicyInformer.Lister(),
		backendInformer.Lister(),
	)

	// Setup event handlers for all relevant resources.
	if err := c.setupGatewayClassEventHandlers(ctx, gatewayClassInformer); err != nil {
		return nil, err
	}
	if err := c.setupGatewayEventHandlers(gatewayInformer); err != nil {
		return nil, err
	}
	if err := c.setupHTTPRouteEventHandlers(httprouteInformer); err != nil {
		return nil, err
	}
	if err := c.setupBackendEventHandlers(backendInformer); err != nil {
		return nil, err
	}
	if err := c.setupAccessPolicyEventHandlers(accessPolicyInformer); err != nil {
		return nil, err
	}
	if err := c.setupServiceEventHandlers(serviceInformer); err != nil {
		return nil, err
	}

	return c, nil
}

// Run will
// - sync informer caches and start workers.
// - start the xDS server
func (c *Controller) Run(ctx context.Context, workers int) error {
	defer runtime.HandleCrashWithContext(ctx)
	defer c.gatewayqueue.ShutDown()
	defer c.backendFinalizerQueue.ShutDown()

	// start the xDS server
	klog.Info("Starting the Envoy xDS server")
	if err := c.xdsServer.Run(ctx); err != nil {
		return fmt.Errorf("failed to start xDS server: %w", err)
	}

	klog.Info("Waiting for informer caches to sync")
	if ok := cache.WaitForCacheSync(ctx.Done(),
		c.core.nsSynced,
		c.core.svcSynced,
		c.core.secretSynced,
		c.gateway.gatewayClassSynced,
		c.gateway.gatewaySynced,
		c.gateway.httprouteSynced,
		c.gateway.referenceGrantSynced,
		c.agentic.backendSynced,
		c.agentic.accessPolicySynced); !ok {
		return errors.New("failed to wait for caches to sync")
	}

	klog.InfoS("Starting gateway workers", "count", workers)
	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, c.runWorker, time.Second)
	}
	klog.InfoS("Starting backend finalizer workers", "count", workers)
	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, c.runBackendFinalizerWorker, time.Second)
	}

	klog.Info("Started workers")
	<-ctx.Done()
	klog.Info("Shutting down workers")

	return nil
}

// runWorker is a long-running function that will continually call the
// processNextGatewayItem function in order to read and process a message on the
// workqueue.
func (c *Controller) runWorker(ctx context.Context) {
	for c.processNextGatewayItem(ctx) {
	}
}

// processNextGatewayItem will read a single work item off the workqueue and
// attempt to process it, by calling the syncHandler.
func (c *Controller) processNextGatewayItem(ctx context.Context) bool {
	obj, shutdown := c.gatewayqueue.Get()
	if shutdown {
		return false
	}
	defer c.gatewayqueue.Done(obj)

	// We expect strings (namespace/name) to come off the workqueue.
	if err := c.syncGateway(ctx, obj); err != nil {
		if c.gatewayqueue.NumRequeues(obj) < maxGatewaySyncRetries {
			c.gatewayqueue.AddRateLimited(obj)
			klog.ErrorS(err, "Error syncing gateway; will retry with rate limit", "key", obj, "requeues", c.gatewayqueue.NumRequeues(obj))
		} else {
			c.gatewayqueue.Forget(obj)
			klog.ErrorS(err, "Dropping gateway sync after max retries", "key", obj, "maxRetries", maxGatewaySyncRetries)
		}
		return true
	}

	// Finally, if no error occurs we Forget this item so it does not
	// get queued again until another change happens.
	c.gatewayqueue.Forget(obj)
	klog.InfoS("Successfully synced", "key", obj)
	return true
}

func (c *Controller) runBackendFinalizerWorker(ctx context.Context) {
	for c.processNextBackendFinalizerItem(ctx) {
	}
}

func (c *Controller) processNextBackendFinalizerItem(ctx context.Context) bool {
	obj, shutdown := c.backendFinalizerQueue.Get()
	if shutdown {
		return false
	}
	defer c.backendFinalizerQueue.Done(obj)
	if err := c.syncBackendFinalizer(ctx, obj); err != nil {
		if c.backendFinalizerQueue.NumRequeues(obj) < maxBackendFinalizerRetries {
			c.backendFinalizerQueue.AddRateLimited(obj)
			klog.ErrorS(err, "Error syncing backend finalizer; will retry with rate limit", "key", obj, "requeues", c.backendFinalizerQueue.NumRequeues(obj))
		} else {
			c.backendFinalizerQueue.Forget(obj)
			klog.ErrorS(err, "Dropping backend finalizer sync after max retries", "key", obj, "maxRetries", maxBackendFinalizerRetries)
		}
		return true
	}
	c.backendFinalizerQueue.Forget(obj)
	return true
}

// syncGateway compares the actual state with the desired, and attempts to
// converge the two.
func (c *Controller) syncGateway(ctx context.Context, key string) error {
	startTime := time.Now()
	defer func() {
		klog.V(2).Infof("Finished syncing gateway %q (%v)", key, time.Since(startTime))
	}()

	// Convert the namespace/name string into a distinct namespace and name
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		runtime.HandleError(fmt.Errorf("invalid resource key: %s (err: %w)", key, err))
		return nil
	}

	logger := klog.FromContext(ctx).WithValues("gateway", klog.KRef(namespace, name))
	ctx = klog.NewContext(ctx, logger)

	// Get the Gateway resource with this namespace/name
	gateway, err := c.gateway.gatewayLister.Gateways(namespace).Get(name)
	if apierrors.IsNotFound(err) {
		logger.Info("Gateway deleted, cleaning up associated resources.")
		return envoy.DeleteProxy(ctx, c.core.client, namespace, name)
	}
	if err != nil {
		return fmt.Errorf("failed to get gateway %s: %w", key, err)
	}

	// Only reconcile Gateways whose spec.gatewayClassName refers to a GatewayClass
	if !c.isGatewayOwnedByController(gateway) {
		logger.V(4).Info("Skipping Gateway: not owned by this controller (GatewayClass controllerName mismatch or GatewayClass not found)",
			"gateway", klog.KRef(gateway.Namespace, gateway.Name),
			"gatewayClassName", string(gateway.Spec.GatewayClassName))
		return nil
	}

	// If Gateway is being deleted, block until no HTTPRoutes or AccessPolicies reference it, then clean up and remove finalizer.
	if gateway.DeletionTimestamp != nil {
		if hasHTTPRoutesReferencingGateway(c, gateway) {
			logger.V(4).Info("Gateway has HTTPRoutes still referencing it, blocking deletion")
			return nil
		}
		if hasAccessPoliciesTargetingGateway(c, gateway) {
			logger.V(4).Info("Gateway has AccessPolicies still targeting it, blocking deletion")
			return nil
		}
		if errDel := envoy.DeleteProxy(ctx, c.core.client, namespace, name); errDel != nil {
			return errDel
		}
		if err = c.updateGatewayRemoveFinalizer(ctx, namespace, name); err != nil {
			return fmt.Errorf("failed to remove finalizer from Gateway: %w", err)
		}
		return nil
	}

	finalizerAdded, err := c.ensureGatewayFinalizer(ctx, namespace, name)
	if err != nil {
		return fmt.Errorf("failed to add finalizer to Gateway: %w", err)
	}
	if finalizerAdded {
		c.gatewayqueue.Add(key)
		return nil
	}

	logger.Info("Syncing gateway")

	newGW := gateway.DeepCopy()

	// Ensure Envoy proxy deployment and service exist.
	rm := envoy.NewResourceManager(c.core.client, gateway, c.envoyImage, c.agenticIdentityTrustDomain)
	proxyIP, err := rm.EnsureProxyExist(ctx)
	if err != nil {
		updateErr := updateGatewayStatus(ctx, c, gateway, newGW, nil, err)
		return errors.Join(err, updateErr)
	}

	// TODO: Add support for IPv6?
	newGW.Status.Addresses = []gatewayv1.GatewayStatusAddress{}
	if net.ParseIP(proxyIP) != nil {
		newGW.Status.Addresses = append(newGW.Status.Addresses,
			gatewayv1.GatewayStatusAddress{
				Type:  ptr.To(gatewayv1.IPAddressType),
				Value: proxyIP,
			})
	}

	logger.Info("Ensured Envoy proxy for gateway exists", "nodeID", rm.NodeID(), "proxyIP", proxyIP)

	// Translate Gateway to xDS resources (includes only current HTTPRoutes/XAccessPolicies; stale rules are omitted).
	resources, listenerStatuses, httpRouteStatuses, _, err := c.translator.TranslateGatewayToXDS(ctx, gateway)
	if err != nil {
		updateErr := updateGatewayStatus(ctx, c, gateway, newGW, nil, fmt.Errorf("failed to translate gateway to xDS resources: %w", err))
		return errors.Join(err, updateErr)
	}

	logger.Info("Translated gateway to xDS resources")

	newGW.Status.Listeners = listenerStatuses
	// Update the xDS server with the new resources.
	xdsErr := c.xdsServer.UpdateXDSServer(ctx, rm.NodeID(), resources)
	updateGatewayStatusErr := updateGatewayStatus(ctx, c, gateway, newGW, listenerStatuses, xdsErr)
	updateHTTPRouteStatusErr := c.updateHTTPRouteStatuses(ctx, httpRouteStatuses)
	return errors.Join(xdsErr, updateGatewayStatusErr, updateHTTPRouteStatusErr)
}

func (c *Controller) updateGatewayRemoveFinalizer(ctx context.Context, namespace, name string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest, err := c.gateway.gatewayLister.Gateways(namespace).Get(name)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil
			}
			return err
		}
		u := latest.DeepCopy()
		if !removeFinalizer(&u.ObjectMeta, constants.GatewayFinalizer) {
			return nil
		}
		_, err = c.gateway.client.GatewayV1().Gateways(namespace).Update(ctx, u, metav1.UpdateOptions{})
		return err
	})
}

// updateGatewayStatus updates the Gateway status in the API server if it has changed.
// Note: this function modifies newGW.
func updateGatewayStatus(ctx context.Context, c *Controller, gateway *gatewayv1.Gateway, newGW *gatewayv1.Gateway, listenerStatuses []gatewayv1.ListenerStatus, syncErr error) error {
	setGatewayConditions(newGW, listenerStatuses, syncErr)

	if reflect.DeepEqual(gateway.Status, newGW.Status) {
		return nil
	}

	if _, statusErr := c.gateway.client.GatewayV1().Gateways(newGW.Namespace).UpdateStatus(ctx, newGW, metav1.UpdateOptions{}); statusErr != nil {
		klog.FromContext(ctx).Error(statusErr, "failed to update gateway status")
		return fmt.Errorf("failed to update gateway status: %w", statusErr)
	}
	klog.FromContext(ctx).Info("Updated gateway status")
	return nil
}

// ensureGatewayFinalizer adds the controller finalizer via the API when missing.
// It returns (true, nil) when the finalizer was absent at the start of the call and is present
// after a successful retry loop (caller should requeue and exit early so metadata is fresh).
func (c *Controller) ensureGatewayFinalizer(ctx context.Context, namespace, name string) (requeue bool, err error) {
	gw, err := c.gateway.gatewayLister.Gateways(namespace).Get(name)
	if err != nil {
		return false, err
	}
	hadFinalizer := sets.New(gw.Finalizers...).Has(constants.GatewayFinalizer)
	probe := gw.DeepCopy()
	if !ensureFinalizer(&probe.ObjectMeta, constants.GatewayFinalizer) {
		return false, nil
	}
	if retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest, getErr := c.gateway.gatewayLister.Gateways(namespace).Get(name)
		if getErr != nil {
			return getErr
		}
		u := latest.DeepCopy()
		if !ensureFinalizer(&u.ObjectMeta, constants.GatewayFinalizer) {
			return nil
		}
		_, updErr := c.gateway.client.GatewayV1().Gateways(namespace).Update(ctx, u, metav1.UpdateOptions{})
		return updErr
	}); retryErr != nil {
		return false, retryErr
	}
	fresh, err := c.gateway.gatewayLister.Gateways(namespace).Get(name)
	if err != nil {
		return false, err
	}
	nowHas := sets.New(fresh.Finalizers...).Has(constants.GatewayFinalizer)
	return !hadFinalizer && nowHas, nil
}

// hasHTTPRoutesReferencingGateway returns true if any HTTPRoute has a ParentRef to the given Gateway.
func hasHTTPRoutesReferencingGateway(c *Controller, gw *gatewayv1.Gateway) bool {
	routes, err := c.gateway.httprouteLister.List(labels.Everything())
	if err != nil {
		klog.V(4).ErrorS(err, "failed to list HTTPRoutes for Gateway finalizer")
		return true // conservatively block
	}
	for _, route := range routes {
		for _, parentRef := range route.Spec.ParentRefs {
			if (parentRef.Group != nil && string(*parentRef.Group) != gatewayv1.GroupName) ||
				(parentRef.Kind != nil && string(*parentRef.Kind) != "Gateway") {
				continue
			}
			refNamespace := route.Namespace
			if parentRef.Namespace != nil {
				refNamespace = string(*parentRef.Namespace)
			}
			if string(parentRef.Name) == gw.Name && refNamespace == gw.Namespace {
				return true
			}
		}
	}
	return false
}

// hasAccessPoliciesTargetingGateway returns true if any XAccessPolicy has a targetRef to the given Gateway.
// Used to block Gateway finalizer removal until all targeting AccessPolicies are removed (avoids dangling refs).
func hasAccessPoliciesTargetingGateway(c *Controller, gw *gatewayv1.Gateway) bool {
	policies, err := c.agentic.accessPolicyLister.XAccessPolicies(gw.Namespace).List(labels.Everything())
	if err != nil {
		klog.V(4).ErrorS(err, "failed to list AccessPolicies for Gateway finalizer")
		return true // conservatively block
	}
	for _, policy := range policies {
		for _, targetRef := range policy.Spec.TargetRefs {
			if !isGatewayTargetRef(targetRef) {
				continue
			}
			if string(targetRef.Name) == gw.Name {
				return true
			}
		}
	}
	return false
}
