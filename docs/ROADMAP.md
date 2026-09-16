# Roadmap

This repo is meant to keep moving. Concrete next steps:

## Reliability

- [ ] Persist vault across gateway restarts (0600 file / sqlite), or session-scoped restore keys.
- [ ] Prefer last-token logits over `n_predict=1` generation (llama.cpp `n_probs` / transformers), so Q4 stays usable.
- [ ] Publish **F16 GGUF** next to Q4 on Hugging Face; document Q4 generation-path failure.
- [ ] Restore `response.output_text.delta` and other Responses events with tests against recorded SSE.

## Coverage

- [ ] More Layer 0 patterns (Azure, GCP, Kubernetes service accounts) with a false-positive suite.
- [ ] Configurable extra regex file without code change.
- [ ] Optional PII pack (phone / ID) off by default.

## Performance

- [ ] Prompt-prefix KV cache dedicated slot for Layer 1.
- [ ] Batch candidates in one llama.cpp request if/when supported.
- [ ] Skip Layer 1 entirely when candidate list is empty (already) and when request size is huge but Layer 0 already ran.

## Product

- [ ] Allowlist hosts that bypass the gateway (health checks).
- [ ] Metrics: redactions/sec, layer1 latency histogram, fail-open count.
- [ ] Do not let `/privacy/dry-run` be reachable off-localhost in the unit file.

## Training

- [ ] Publish a tiny eval set (synthetic secrets only) for regression.
- [ ] Calibrate Layer 1 threshold on F16 vs Q4 vs fused HF.
- [ ] Consider a smaller head-only classifier if 0.5B is still too slow on the edge.

## Runtime

### Node.js (DSH runtime only)

The DSH deployment runs its own Node at `/opt/dsh-runtime/bin/node`; the system
Node at `/usr/bin/node` is separate and is used by other services on this host.

Upgraded **v22.23.2 (LTS Jod) -> v24.21.0 (LTS Krypton)** on 2026-09-16, verified
before the swap by booting the real web server under the new binary on a scratch
port and by force-loading every ABI-sensitive path:

| check | Node 22 | Node 24 |
|---|---|---|
| DSH web boot + all plugin routes | pass | pass |
| sharp (libvips) resize | pass | pass |
| node-pty spawn/kill | pass | pass |
| koffi FFI call | pass | pass |
| node:sqlite | pass | pass |

All native addons in this deployment are N-API (prebuilds / N-API FFI), so they
are forward-compatible across the ABI change (127 -> 137).

Rollback is a single file copy, no reinstall needed:

```bash
systemctl stop deepseek-harness
cp /opt/node-v22.23.2-backup/bin/node /opt/dsh-runtime/bin/node
systemctl start deepseek-harness
```

Only the `node` binary is referenced by absolute path; npm/pnpm/corepack are
symlinks inside the runtime and no shebang in the profile pins that path, so
nothing else has to move for a version change.
