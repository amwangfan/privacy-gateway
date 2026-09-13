# Security

- The vault holds **plaintext secrets in process memory**. Anyone with root on the gateway host can read them. That is intentional: restore needs them locally; they must not go to the upstream model.
- Logs must never print secret values (only type + placeholder).
- `/privacy/dry-run` redacts into the live vault. Bind it to localhost or firewall it; do not expose it on the public internet.
- Layer 1 is fail-open: if llama-server is down, only Layer 0 applies.
- Clients that skip the gateway (direct vendor API) are unprotected.
- Do not commit `.gguf`, adapter weights, `.env`, or real credentials. Tests in this repo use obviously fake tokens.
