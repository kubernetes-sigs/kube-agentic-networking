# Data Plane

The data plane consists of the Envoy proxies managed by the control plane.

## Connection to the control plane

Each Envoy proxy is configured with a static bootstrap configuration that points it to the control plane's xDS server.

## Bootstrap config

The bootstrap configuration is delivered to the Envoy pod as a `ConfigMap` mounted as a file (`envoy.yaml`). It contains:
- **Node ID**: A unique identifier for the proxy, derived from its parent `Gateway`'s name and namespace. This ID is used by the xDS server to send the correct configuration.
- **xDS Cluster**: A static cluster definition named `xds_cluster` that points to the control plane's service FQDN (`agentic-net-xds-server.agentic-net-system.svc.cluster.local:15001`).
- **ADS Config**: Configuration that tells Envoy to use the Aggregated Discovery Service (ADS) to fetch all its dynamic resources (Listeners, Clusters, Routes) from the `xds_cluster`.

## Envoy Config overview

The controller generates a rich set of Envoy configurations to implement the desired policies:

- **Listeners**: One Envoy Listener is created for each port defined in the `Gateway.spec.listeners`. It is responsible for accepting incoming connections.
- **HTTP Connection Manager**: This is the primary network filter. It chains together several specialized HTTP filters to process each request.
- **HTTP Filters**: The filters are executed in a specific order to implement the agentic networking logic:
    1.  **JWT Authn Filter**: This filter intercepts incoming requests, expects a Kubernetes `ServiceAccount` JWT in a specific header (`x-k8s-sa-token`), and validates it against the Kubernetes API server's OIDC discovery endpoint. Upon successful validation, it extracts the subject claim (e.g., `system:serviceaccount:default:my-app`) and places it into a new header, `x-user-role`, to carry the client's identity.
    2.  **MCP Filter**: This is a custom filter that parses the body of [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) requests. It extracts key information, such as the `method` being called (e.g., `tools/call`) and the `name` of the tool from the parameters, and makes this information available as dynamic metadata.
    3.  **RBAC Filter**: This filter enforces access control. Its rules are configured on a per-route basis and can match on the `x-user-role` header (populated by the JWT filter) and the dynamic metadata (populated by the MCP filter). This allows for fine-grained policies like "allow service account X to call tool Y".
    4.  **Router Filter**: This is the final filter in the chain. It takes the processed request and routes it to the appropriate upstream `Cluster` as defined by the `RouteConfiguration`.
- **Route Configuration**: Contains the routing rules. One `RouteConfiguration` is generated per listener port. It contains a list of `VirtualHosts`.
- **Virtual Hosts**: Match requests based on the HTTP `Host` header. They contain a list of `Routes`.
- **Routes**: Match requests based on path, headers, or query parameters and define what to do with the request, such as forwarding it to an upstream `Cluster`.
- **Clusters**: Define the upstream services (`XBackend`). A `Cluster` contains the address of the service and connection properties like TLS settings.
