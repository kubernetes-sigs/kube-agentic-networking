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

package xds

import (
	"context"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	serverv3 "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"k8s.io/klog/v2"
)

var _ serverv3.Callbacks = &callbacks{}

type callbacks struct{}

func (cb *callbacks) OnStreamOpen(ctx context.Context, id int64, typ string) error {
	klog.V(5).Infof("xDS stream %d opened for type %s", id, typ)
	return nil
}

func (cb *callbacks) OnStreamClosed(id int64, node *corev3.Node) {
	nodeID := "unknown"
	if node != nil {
		nodeID = node.GetId()
	}
	klog.V(5).Infof("xDS stream %d closed for node %s", id, nodeID)
}

func (cb *callbacks) OnStreamRequest(id int64, req *discoveryv3.DiscoveryRequest) error {
	klog.V(5).Infof("xDS stream %d received request for type %s from node %s", id, req.TypeUrl, req.Node.GetId())
	return nil
}

func (cb *callbacks) OnStreamResponse(ctx context.Context, id int64, req *discoveryv3.DiscoveryRequest, resp *discoveryv3.DiscoveryResponse) {
	klog.V(5).Infof("xDS stream %d sent response for type %s to node %s", id, resp.TypeUrl, req.Node.GetId())
}

func (cb *callbacks) OnFetchRequest(ctx context.Context, req *discoveryv3.DiscoveryRequest) error {
	klog.V(5).Infof("xDS fetch request received for type %s from node %s", req.TypeUrl, req.Node.GetId())
	return nil
}

func (cb *callbacks) OnFetchResponse(req *discoveryv3.DiscoveryRequest, resp *discoveryv3.DiscoveryResponse) {
	klog.V(5).Infof("xDS fetch response sent for type %s to node %s", resp.TypeUrl, req.Node.GetId())
}

func (cb *callbacks) OnStreamDeltaRequest(id int64, req *discoveryv3.DeltaDiscoveryRequest) error {
	return nil
}

func (cb *callbacks) OnStreamDeltaResponse(id int64, req *discoveryv3.DeltaDiscoveryRequest, resp *discoveryv3.DeltaDiscoveryResponse) {
}

func (cb *callbacks) OnDeltaStreamClosed(int64, *corev3.Node) {}

func (cb *callbacks) OnDeltaStreamOpen(context.Context, int64, string) error {
	return nil
}
