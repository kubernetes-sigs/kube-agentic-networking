# Mutual TLS (mTLS) Configuration

This guide explains how to configure Mutual TLS (mTLS) for your Gateway.

## Overview

Mutual TLS (mTLS) ensures that both the client and the server authenticate each other using certificates. In this project, mTLS is configured at the Gateway level.

## Configuration Requirements

To enable mTLS, you must provide **both** a server certificate reference and a CA certificate reference for client validation.

### 1. Server Certificate (Listener Level)

The server certificate is configured within the `listeners` section of the Gateway spec. This certificate is presented by the Gateway to the client.

- **Field**: [`gw.Spec.Listeners[*].TLS.CertificateRefs`](https://gateway-api.sigs.k8s.io/reference/1.5/spec/#listenertlsconfig)
- **Resource**: Must point to a Kubernetes `Secret` containing `tls.crt` and `tls.key`.

### 2. Client Validation (Gateway Level)

The CA certificate used to validate client certificates is configured in the `tls.frontend` section of the Gateway spec. You can provide a default CA for all ports or specify different CAs per port.

- **Field**: [`gw.Spec.TLS.Frontend.Default.Validation.CACertificateRefs`](https://gateway-api.sigs.k8s.io/reference/1.5/spec/#frontendtlsconfig) (Default)
- **Field**: [`gw.Spec.TLS.Frontend.PerPort[*].TLS.Validation.CACertificateRefs`](https://gateway-api.sigs.k8s.io/reference/1.5/spec/#frontendtlsconfig) (Per-port)
- **Resource**: Must point to a Kubernetes `ConfigMap` containing a `ca.crt` key.

> [!IMPORTANT]
> For mTLS to function correctly, you MUST provide both the `CertificateRefs` in the listener and the `CACertificateRefs` in the frontend validation. If `CACertificateRefs` is omitted, the Gateway will fall back to default trust settings (e.g., SPIFFE trust) which may not be what you intended for a custom mTLS setup.
>
> For more details on how we are discussing enforcing strict client validation in the long term, see [Issue #254](https://github.com/kubernetes-sigs/kube-agentic-networking/issues/254).

## Example Configuration

Below is an example of a Gateway configured with mTLS:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
  namespace: my-namespace
spec:
  gatewayClassName: agentic-net-gateway-class
  listeners:
  - name: https-listener
    port: 443
    protocol: HTTPS
    tls:
      mode: Terminate
      certificateRefs:
      - name: my-server-cert # Points to a Secret
    allowedRoutes:
      namespaces:
        from: Same
  tls:
    frontend:
      default:
        validation:
          caCertificateRefs:
          - name: my-client-ca # Points to a ConfigMap
```

## Status Conditions

The controller validates your TLS configuration. You can check the status of your Gateway listeners to ensure references are resolved correctly:

- `ResolvedRefs`: Will be `True` if all certificates and ConfigMaps are found and valid.
- `Programmed`: Will be `True` if the listener is successfully configured in the underlying proxy (Envoy).

If you provide `CertificateRefs` but omit `CACertificateRefs`, the listener may still be `Programmed`, but you will see a message in the `ResolvedRefs` condition recommending the addition of `CACertificateRefs` for a proper mTLS setup.
