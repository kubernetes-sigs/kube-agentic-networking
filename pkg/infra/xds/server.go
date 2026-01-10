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
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	clusterv3service "github.com/envoyproxy/go-control-plane/envoy/service/cluster/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	listenerv3service "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	routev3service "github.com/envoyproxy/go-control-plane/envoy/service/route/v3"
	runtimev3 "github.com/envoyproxy/go-control-plane/envoy/service/runtime/v3"
	secretv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	envoyproxytypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	serverv3 "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"k8s.io/klog/v2"
)

const (
	grpcKeepaliveTime        = 30 * time.Second
	grpcKeepaliveTimeout     = 5 * time.Second
	grpcKeepaliveMinTime     = 30 * time.Second
	grpcMaxConcurrentStreams = 1000000
)

// Server is the xDS server.
type Server struct {
	cache   cachev3.SnapshotCache
	server  serverv3.Server
	version atomic.Uint64
}

// NewServer creates a new xDS server.
func NewServer(ctx context.Context) *Server {
	cache := cachev3.NewSnapshotCache(false, cachev3.IDHash{}, nil)
	server := serverv3.NewServer(ctx, cache, &callbacks{})
	return &Server{
		cache:  cache,
		server: server,
	}
}

// Run starts the xDS server.
func (s *Server) Run(ctx context.Context) error {
	var grpcOptions []grpc.ServerOption
	grpcOptions = append(grpcOptions,
		grpc.MaxConcurrentStreams(grpcMaxConcurrentStreams),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    grpcKeepaliveTime,
			Timeout: grpcKeepaliveTimeout,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             grpcKeepaliveMinTime,
			PermitWithoutStream: true,
		}),
	)
	grpcServer := grpc.NewServer(grpcOptions...)

	discoveryv3.RegisterAggregatedDiscoveryServiceServer(grpcServer, s.server)
	endpointv3.RegisterEndpointDiscoveryServiceServer(grpcServer, s.server)
	clusterv3service.RegisterClusterDiscoveryServiceServer(grpcServer, s.server)
	routev3service.RegisterRouteDiscoveryServiceServer(grpcServer, s.server)
	listenerv3service.RegisterListenerDiscoveryServiceServer(grpcServer, s.server)
	secretv3.RegisterSecretDiscoveryServiceServer(grpcServer, s.server)
	runtimev3.RegisterRuntimeDiscoveryServiceServer(grpcServer, s.server)

	// The xDS server listens on a fixed port (15001) on all interfaces.
	listener, err := net.Listen("tcp", "0.0.0.0:15001")
	if err != nil {
		return err
	}

	klog.Infof("xDS management server listening on %s", listener.Addr().String())
	go func() {
		if err = grpcServer.Serve(listener); err != nil {
			klog.Errorln("gRPC server error:", err)
		}
	}()

	go func() {
		<-ctx.Done()
		grpcServer.Stop()
	}()

	return nil
}

// UpdateXDSServer updates the xDS server with new resources.
func (s *Server) UpdateXDSServer(ctx context.Context, nodeid string, resources map[resourcev3.Type][]envoyproxytypes.Resource) error {
	s.version.Add(1)
	version := s.version.Load()

	snapshot, err := cachev3.NewSnapshot(fmt.Sprintf("%d", version), resources)
	if err != nil {
		return fmt.Errorf("failed to create new snapshot cache: %v", err)
	}

	if err := s.cache.SetSnapshot(ctx, nodeid, snapshot); err != nil {
		return fmt.Errorf("failed to update resource snapshot in management server: %v", err)
	}
	klog.V(4).Infof("Updated snapshot cache for node %s with version %d", nodeid, version)
	return nil
}
