# CEL vocabulary

An `XAccessPolicy` rule can authorize requests with a [CEL](https://cel.dev/) expression by
setting `authorization.type: CEL` and `authorization.cel.expression`.

The API does not standardize the variables and functions available to CEL expressions; each
implementation documents its own (see the
[Dynamic Authorization proposal](../proposals/0017-DynamicAuth.md#cel-context-vocabulary)).
This page describes what the reference implementation supports. Expressions written for it
may not work with other implementations.

## How CEL rules are evaluated

The controller translates each CEL rule into an Envoy RBAC policy, and Envoy evaluates the
expression at request time. A CEL rule only applies to MCP `tools/call` requests: it matches
a `tools/call` request from the rule's source when the expression evaluates to `true`. If the
expression evaluates to `false`, to a non-boolean value, or to an error (for example, reading a
header the request does not have), the rule does not match.

Because a CEL rule never matches other requests, including the MCP `initialize` and
`tools/list` calls an agent makes before it can call a tool, a policy with action `Allow`
usually needs a second, `Inline` rule that allows the base MCP protocol methods:

```yaml
apiVersion: agentic.networking.x-k8s.io/v1alpha1
kind: XAccessPolicy
metadata:
  name: allow-verify-tools
  namespace: default
spec:
  targetRefs:
  - group: agentic.networking.x-k8s.io
    kind: XBackend
    name: my-backend
  action: Allow
  rules:
  - name: allow-verify-tools
    source:
      type: ServiceAccount
      serviceAccount:
        name: my-agent
    authorization:
      type: CEL
      cel:
        expression: "request.mcp.tool_name.startsWith('verify_')"
  - name: allow-base-mcp
    source:
      type: ServiceAccount
      serviceAccount:
        name: my-agent
    authorization:
      type: Inline
      mcp:
        mcpBaseProtocolMethodsOption: MATCH_BASE_PROTOCOL_METHODS
```

## Variables

| Variable | Type | Description |
|----------|------|-------------|
| `request.mcp.tool_name` | `string` | Name of the tool being called. |
| `request.path` | `string` | Request path, including the query string. |
| `request.url_path` | `string` | Request path without the query string. |
| `request.method` | `string` | Request method, for example `POST`. |
| `request.host` | `string` | Host portion of the URL, taken from the `:authority` or `Host` header. |
| `request.headers` | `map<string, string>` | Request headers, keyed by lower-case header name. Repeated headers are joined with a comma. |
| `request.time` | `timestamp` | Time the first byte of the request was received. |

All of these except `request.mcp.tool_name` are Envoy
[request attributes](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/advanced/attributes#request-attributes)
and behave as Envoy documents them. `request.mcp.tool_name` is specific to this implementation:
before the expression is sent to Envoy, the controller replaces it with
`metadata.filter_metadata['mcp_proxy'].params.name`, the tool name that the MCP filter extracts
from the `tools/call` request.

Reading a key that is not in `request.headers` is an error, so check that an optional header is
present first, for example `'x-user' in request.headers && request.headers['x-user'] == 'alice'`.

The controller rejects expressions that reference any other `request` attribute, such as
`request.query` or `request.scheme`. Top-level variables such as `source` or `identity` are not
defined, so expressions that use them fail to compile.

## Functions

Use the functions and macros from the
[CEL standard definitions](https://github.com/google/cel-spec/blob/master/doc/langdef.md#standard-definitions),
for example `startsWith`, `endsWith`, `contains`, `matches`, `size`, `in` and `has`.

Envoy's CEL evaluator does not support the following, even though the controller accepts
expressions that use them. Do not use them in policies:

- macros that iterate over a list or map: `all`, `exists`, `exists_one`, `map` and `filter`
- string and list concatenation with `+`
- conversion to a string with `string()`
- the cel-go string extension functions, such as `lowerAscii`, `split` and `replace`

## Validation errors

The controller compiles every CEL expression when an `XAccessPolicy` is created or updated. If
an expression references an unsupported variable or does not compile, the policy is rejected
for all of its `targetRefs`: the `Accepted` condition of each ancestor in its status is set to
`False` with reason `InvalidCEL`, and the message contains the error, for example:

```text
Failed to compile CEL expression "request.foo == 'bar'": unsupported CEL variable: request.foo
```

A policy that is not accepted is not applied until the expression is fixed.
