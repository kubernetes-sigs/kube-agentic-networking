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

package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

// podForwardFunc forwards an ephemeral 127.0.0.1 port to a pod port and returns
// the local port. stop tears the forward down and waits for it to exit.
type podForwardFunc func(ctx context.Context, namespace, pod string, podPort int32) (localPort uint16, stop func(), err error)

// resolveServiceTarget picks a Ready pod behind a Service and the pod port that
// the Service's port maps to.
func resolveServiceTarget(ctx context.Context, kube kubernetes.Interface, namespace, name string, port int32) (pod string, podPort int32, err error) {
	svc, err := kube.CoreV1().Services(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", 0, fmt.Errorf("getting service %s/%s: %w", namespace, name, err)
	}

	svcPort, ok := findServicePort(svc, port)
	if !ok {
		return "", 0, fmt.Errorf("service %s/%s has no TCP port %d", namespace, name, port)
	}
	if len(svc.Spec.Selector) == 0 {
		return "", 0, fmt.Errorf("service %s/%s has no selector, so there are no pods to forward to", namespace, name)
	}

	pods, err := kube.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labels.SelectorFromSet(svc.Spec.Selector).String(),
	})
	if err != nil {
		return "", 0, fmt.Errorf("listing pods for service %s/%s: %w", namespace, name, err)
	}

	// Lowest name among the Ready pods, so the choice is stable.
	var selected *corev1.Pod
	for i := range pods.Items {
		p := &pods.Items[i]
		if isPodReady(p) && (selected == nil || p.Name < selected.Name) {
			selected = p
		}
	}
	if selected == nil {
		return "", 0, fmt.Errorf("no Ready pod found for service %s/%s", namespace, name)
	}

	podPort, err = resolveTargetPort(svcPort, selected)
	if err != nil {
		return "", 0, fmt.Errorf("service %s/%s: %w", namespace, name, err)
	}
	return selected.Name, podPort, nil
}

// findServicePort finds the TCP port a backend's port refers to. Backend ports
// are Service ports, not pod ports.
func findServicePort(svc *corev1.Service, port int32) (corev1.ServicePort, bool) {
	for _, sp := range svc.Spec.Ports {
		if sp.Port == port && (sp.Protocol == "" || sp.Protocol == corev1.ProtocolTCP) {
			return sp, true
		}
	}
	return corev1.ServicePort{}, false
}

func isPodReady(pod *corev1.Pod) bool {
	if pod.DeletionTimestamp != nil {
		return false
	}
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// resolveTargetPort maps a ServicePort to a port on the given pod.
func resolveTargetPort(sp corev1.ServicePort, pod *corev1.Pod) (int32, error) {
	target := sp.TargetPort
	switch {
	case target.Type == intstr.String && target.StrVal != "":
		for _, c := range pod.Spec.Containers {
			for _, cp := range c.Ports {
				if cp.Name == target.StrVal && (cp.Protocol == "" || cp.Protocol == corev1.ProtocolTCP) {
					return cp.ContainerPort, nil
				}
			}
		}
		return 0, fmt.Errorf("targetPort %q is not a named TCP port of any container in pod %s", target.StrVal, pod.Name)
	case target.Type == intstr.Int && target.IntVal != 0:
		return target.IntVal, nil
	default:
		// An unset targetPort defaults to the Service port.
		return sp.Port, nil
	}
}

// newPodForwarder returns a podForwardFunc that goes through the API server
// over SPDY, the way kubectl port-forward does.
func newPodForwarder(config *rest.Config, restClient rest.Interface) podForwardFunc {
	return func(ctx context.Context, namespace, pod string, podPort int32) (uint16, func(), error) {
		// The upgrade round tripper keeps the connection it negotiates, so
		// each forward needs its own.
		transport, upgrader, err := spdy.RoundTripperFor(config)
		if err != nil {
			return 0, nil, fmt.Errorf("creating SPDY transport: %w", err)
		}
		dialer := &spdyDialer{
			ctx:      ctx,
			upgrader: upgrader,
			client:   &http.Client{Transport: transport},
			url:      restClient.Post().Namespace(namespace).Resource("pods").Name(pod).SubResource("portforward").URL(),
		}

		localPort, stop, err := startForward(ctx, dialer, podPort)
		if err != nil {
			return 0, nil, fmt.Errorf("port-forwarding to pod %s/%s port %d: %w", namespace, pod, podPort, err)
		}
		return localPort, stop, nil
	}
}

// startForward listens on an ephemeral 127.0.0.1 port and forwards it to
// podPort through dialer. It returns once the listener is ready, or when the
// forward fails or ctx ends. stop is safe to call more than once.
func startForward(ctx context.Context, dialer httpstream.Dialer, podPort int32) (localPort uint16, stop func(), err error) {
	stopCh := make(chan struct{})
	readyCh := make(chan struct{})
	fw, err := portforward.NewOnAddresses(dialer, []string{"127.0.0.1"}, []string{fmt.Sprintf("0:%d", podPort)}, stopCh, readyCh, io.Discard, io.Discard)
	if err != nil {
		return 0, nil, err
	}

	done := make(chan struct{})
	var forwardErr error
	go func() {
		defer close(done)
		forwardErr = fw.ForwardPorts()
	}()
	stop = sync.OnceFunc(func() {
		close(stopCh)
		<-done
	})

	select {
	case <-readyCh:
	case <-done:
		return 0, nil, forwardErr
	case <-ctx.Done():
		stop()
		return 0, nil, ctx.Err()
	}

	ports, err := fw.GetPorts()
	if err != nil {
		stop()
		return 0, nil, err
	}
	return ports[0].Local, stop, nil
}

// spdyDialer upgrades a request to a pod's portforward endpoint to SPDY. It
// differs from spdy.NewDialer in that Dial gives up when ctx ends: a stalled
// API server, for example one that can't reach the kubelet, holds the upgrade
// response back, and reading it can't be canceled.
type spdyDialer struct {
	ctx      context.Context
	upgrader spdy.Upgrader
	client   *http.Client
	url      *url.URL
}

var _ httpstream.Dialer = (*spdyDialer)(nil)

func (d *spdyDialer) Dial(protocols ...string) (httpstream.Connection, string, error) {
	req, err := http.NewRequestWithContext(d.ctx, http.MethodPost, d.url.String(), nil)
	if err != nil {
		return nil, "", fmt.Errorf("creating request: %w", err)
	}

	type result struct {
		conn     httpstream.Connection
		protocol string
		err      error
	}
	results := make(chan result, 1)
	go func() {
		conn, protocol, err := spdy.Negotiate(d.upgrader, d.client, req, protocols...)
		results <- result{conn, protocol, err}
	}()

	select {
	case r := <-results:
		return r.conn, r.protocol, r.err
	case <-d.ctx.Done():
		// Nobody will use a connection that arrives late, so close it.
		go func() {
			if r := <-results; r.conn != nil {
				r.conn.Close()
			}
		}()
		return nil, "", d.ctx.Err()
	}
}
