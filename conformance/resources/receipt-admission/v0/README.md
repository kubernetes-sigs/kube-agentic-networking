# Receipt admission conformance vectors (v0)

Envelope-neutral conformance vectors for the receipt-based admission-control discussion in
[#243](https://github.com/kubernetes-sigs/kube-agentic-networking/issues/243). They pin five admission
concerns, in the order a controller evaluates them, and every expected outcome is reproducible from the
bytes in `vectors.json` alone.

- **resolution** — the chain reference is fetched before anything is verified. A present but unresolvable
  reference is rejected, because a committed digest in the annotation is not sufficient on its own.
- **binding** — the controller recomputes the manifest digest from the object it actually received and
  compares it to the chain's committed value, so a chain produced for one object cannot admit a
  different one.
- **declared-vs-observed** — for a bound chain, an independent observation of the effect either agrees
  with, diverges from, or simply does not see what the receipt declares. A receipt is the agent
  session's own account, so a missing observation is inconclusive, never confirmation.
- **canonicalization** — the same object content under reordered keys and added whitespace must produce
  one digest, so the profile (not a coincidence of two serializers) is what makes recompute
  interoperable.
- **stage** — a commitment names the pipeline stage it was computed at, and the kind is fixed per stage
  value in a closed table: `agent-declared` and `controller-observed-object` are object stages verified
  by recompute, `observed-effect` is verified by compare. The verb derives from the stage alone, so
  there is no separate stage-kind field that can drift. The required stage selects the verb, and a
  commitment whose stage differs rejects with two distinct reasons in both directions: within the object
  kind a digest mismatch (cross-stage being the pipeline/defaulting case, same-stage being tampering),
  across kinds a stage-kind mismatch decided before any recompute or compare. This is the defaulting case
  from the thread: the API server defaults and mutates the object before the validating controller sees
  it, so an `agent-declared` commitment recomputed at the `controller-observed-object` stage must reject,
  which is the pipeline, not tampering.

These vectors deliberately do not define the final canonicalization profile for Kubernetes objects;
they make that open question explicit and stay reproducible independent of it. The `stage` family
likewise does not assume a final field name in the proposal; it pins the verification contract a named
stage field has to satisfy.

## Format

`vectors.json` carries a machine-readable canonicalization block and a list of vectors. A second
implementation reproduces every verdict from these fields without any shared code:

```json
"canonicalization": {
  "profile": "jcs-json-v1",
  "description": "RFC 8785 (JCS) over the JSON object, restricted here to strings, objects, and small integers, so RFC 8785 number formatting is not exercised; a full implementation is required for general objects",
  "hash": "sha256",
  "digest_encoding": "hex",
  "digest_prefix": "sha256:"
}
```

To recompute a manifest digest: canonicalize the object under the named profile, hash it with the named
hash, encode per `digest_encoding`, and prefix with `digest_prefix`. The committed digest is checked by
recomputation, not trusted as supplied.

## Verdicts

- `resolution`: `unresolvable` (reason `chain_reference_unresolvable_digest_alone_insufficient`).
- `binding`: `bound` | `digest_mismatch` | `missing_commitment`.
- `grounding` (bound chains): `confirmed` | `contradicted` | `unobserved`, each with a `grounding_reason`.
- `canonicalization`: `all_variants_match` | `variant_mismatch`.
- `stage`: `bound` | `cross_stage_digest_mismatch` | `digest_mismatch` | `stage_kind_mismatch` |
  `confirmed` | `contradicted` | `unobserved` | `unknown_stage`, each with a `stage_reason`. The
  `stage -> kind -> verb` table is machine-readable in `spec.stage_model`.

The required failure case is `g2`/`g3`: a cryptographically valid, bound chain whose independent observed
effect diverges from the declaration. Vector `g5` is the case where a controller-signed attestation
covers the submitted object but the effect is unobserved; it carries the distinct reason
`object_attestation_not_effect_observation`, so attesting the object is never read as observing the
effect, and it stays `unobserved`.

In the `stage` family, `st3` is the defaulting cross-stage reject (a pipeline digest mismatch, kept
distinct from the `st4` same-stage tampering reject), and `st5`/`st6` are the cross-kind category error
rejected before any recompute or compare, in both directions.

## Scope

Signature and chain-integrity verification is the emitter side and is assumed valid here; these vectors
isolate resolution, binding, declared-vs-observed, canonicalization, and stage. They are recompute-only
and make no claim about any implementation. The canonical profile id `jcs-json-v1` is a placeholder for these
fixtures; the production Kubernetes object profile (YAML/JSON normalization, defaulting, field ordering)
is the open question for the proposal, and the committing and recomputing sides must share one named
profile or recompute is not deterministic across implementations.
