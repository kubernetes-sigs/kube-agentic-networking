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
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	gatewayclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
	gatewayinformers "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions/apis/v1"
	gatewaylisters "sigs.k8s.io/gateway-api/pkg/client/listers/apis/v1"

	agenticclient "sigs.k8s.io/kube-agentic-networking/k8s/client/clientset/versioned"
	agenticinformers "sigs.k8s.io/kube-agentic-networking/k8s/client/informers/externalversions/api/v0alpha0"
	agenticlisters "sigs.k8s.io/kube-agentic-networking/k8s/client/listers/api/v0alpha0"
	"sigs.k8s.io/kube-agentic-networking/pkg/infra/envoy"
	"sigs.k8s.io/kube-agentic-networking/pkg/infra/xds"
	"sigs.k8s.io/kube-agentic-networking/pkg/translator"
)

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

	httprouteLister gatewaylisters.HTTPRouteLister
	httprouteSynced cache.InformerSynced
}

type agenticNetResources struct {
	client agenticclient.Interface

	backendLister agenticlisters.XBackendLister
	backendSynced cache.InformerSynced

	accessPolicyLister agenticlisters.XAccessPolicyLister
	accessPolicySynced cache.InformerSynced
}

// Controller is the controller implementation for Gateway resources
type Controller struct {
	core    coreResources
	gateway gatewayResources
	agentic agenticNetResources

	jwtIssuer  string
	envoyImage string

	gatewayqueue workqueue.TypedRateLimitingInterface[string]
	xdsServer    *xds.Server
	translator   *translator.Translator
}

// New returns a new *Controller with the event handlers setup for types we are interested in.
func New(
	ctx context.Context,
	jwtIssuer string,
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
	backendInformer agenticinformers.XBackendInformer,
	accessPolicyInformer agenticinformers.XAccessPolicyInformer,
) (*Controller, error) {
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
			client:             gwClientSet,
			gatewayClassLister: gatewayClassInformer.Lister(),
			gatewayClassSynced: gatewayClassInformer.Informer().HasSynced,
			gatewayLister:      gatewayInformer.Lister(),
			gatewaySynced:      gatewayInformer.Informer().HasSynced,
			httprouteLister:    httprouteInformer.Lister(),
			httprouteSynced:    httprouteInformer.Informer().HasSynced,
		},
		agentic: agenticNetResources{
			client:             agenticClientSet,
			backendLister:      backendInformer.Lister(),
			backendSynced:      backendInformer.Informer().HasSynced,
			accessPolicyLister: accessPolicyInformer.Lister(),
			accessPolicySynced: accessPolicyInformer.Informer().HasSynced,
		},
		jwtIssuer:  jwtIssuer,
		envoyImage: envoyImage,
		gatewayqueue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.DefaultTypedControllerRateLimiter[string](),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "gateway"},
		),
		xdsServer: xds.NewServer(ctx),
	}

	c.translator = translator.New(
		jwtIssuer,
		kubeClientSet,
		gwClientSet,
		namespaceInformer.Lister(),
		serviceInformer.Lister(),
		secretInformer.Lister(),
		gatewayInformer.Lister(),
		httprouteInformer.Lister(),
		accessPolicyInformer.Lister(),
		backendInformer.Lister(),
	)

	// Setup event handlers for all relevant resources.
	if err := c.setupGatewayClassEventHandlers(gatewayClassInformer); err != nil {
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
		c.agentic.backendSynced,
		c.agentic.accessPolicySynced); !ok {
		return errors.New("failed to wait for caches to sync")
	}

	klog.InfoS("Starting workers", "count", workers)
	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, c.runWorker, time.Second)
	}

	klog.Info("Started workers")
	<-ctx.Done()
	klog.Info("Shutting down workers")

	return nil
}

// runWorker is a long-running function that will continually call the
// processNextWorkItem function in order to read and process a message on the
// workqueue.
func (c *Controller) runWorker(ctx context.Context) {
	for c.processNextWorkItem(ctx) {
	}
}

// processNextWorkItem will read a single work item off the workqueue and
// attempt to process it, by calling the syncHandler.
func (c *Controller) processNextWorkItem(ctx context.Context) bool {
	obj, shutdown := c.gatewayqueue.Get()
	if shutdown {
		return false
	}
	defer c.gatewayqueue.Done(obj)

	// We expect strings (namespace/name) to come off the workqueue.
	if err := c.syncHandler(ctx, obj); err != nil {
		// Put the item back on the workqueue to handle any transient errors.
		c.gatewayqueue.AddRateLimited(obj)
		klog.ErrorS(err, "Error syncing", "key", obj)
		return true
	}

	// Finally, if no error occurs we Forget this item so it does not
	// get queued again until another change happens.
	c.gatewayqueue.Forget(obj)
	klog.InfoS("Successfully synced", "key", obj)
	return true
}

// syncHandler compares the actual state with the desired, and attempts to
// converge the two.
func (c *Controller) syncHandler(ctx context.Context, key string) error {
	// Convert the namespace/name string into a distinct namespace and name
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		runtime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	logger := klog.FromContext(ctx).WithValues("gateway", klog.KRef(namespace, name))
	ctx = klog.NewContext(ctx, logger)

	// Get the Gateway resource with this namespace/name
	gateway, err := c.gateway.gatewayLister.Gateways(namespace).Get(name)
	if err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("Gateway deleted, cleaning up associated resources.")
			return envoy.DeleteProxy(ctx, c.core.client, namespace, name)
		}
		return err
	}

	logger.Info("Syncing gateway")

	// Ensure Envoy proxy deployment and service exist.
	rm := envoy.NewResourceManager(c.core.client, gateway, c.envoyImage)
	if err := rm.EnsureProxyExist(ctx); err != nil {
		return err
	}

	logger.Info("Ensured Envoy proxy for gateway exists", "nodeID", rm.NodeID())

	// Translate Gateway to xDS resources.
	resources, err := c.translator.TranslateGatewayToXDS(ctx, gateway)
	if err != nil {
		// TODO: Update Gateway status with the error.
		return fmt.Errorf("failed to translate gateway to xDS resources: %w", err)
	}

	logger.Info("Translated gateway to xDS resources")

	// Update the xDS server with the new resources.
	if err := c.xdsServer.UpdateXDSServer(ctx, rm.NodeID(), resources); err != nil {
		return fmt.Errorf("failed to update xDS server: %w", err)
	}

	logger.Info("Updated xDS server with new resources", "nodeID", rm.NodeID())
	return nil
}
