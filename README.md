# Observer — Minimalist CSOD Webhook Receiver

Lightweight Go application for receiving, authenticating, decrypting, decompressing, and inspecting Cornerstone OnDemand (CSOD) webhooks, deployable via Docker Compose behind Caddy and [Autentico](https://getautentico.dev) ForwardAuth.

## Features

- **Per-endpoint listener configuration** (`/hooks/<slug>`):
  - `x-api-key` verification
  - Up to 4 custom `x-*` header checks (enforcing CSOD key/value regexes)
  - **Token Challenge** (`x-challenge-sha256`) verification response
  - **HMAC-SHA256** verification (`Authorization: HMAC-SHA256 Credential=...&SignedHeaders=...&Signature=...` + `x-content-sha256` body digest)
  - **PGP decryption** (`x-content-encrypted: true` with ASCII-armored private key + optional passphrase)
  - **`gzip` decompression** (`Content-Encoding: gzip` and `x-original-encoding: gzip`, strictly ordered *Decrypt -> Decompress -> Parse*)
- **SQLite storage + automatic retention**: separates real events, heartbeats (`records: []`), challenges, and errors, purging expired data on a configurable schedule.
- **Minimal embedded Web UI**: protected by Caddy + Autentico ForwardAuth (`X-Auth-User` / `X-Auth-Email`).

## VPS Deployment

1. Copy `.env.example` to `.env` and set `OBSERVER_MASTER_KEY` (`openssl rand -hex 32`) and `PROXY_NETWORK` (matching the Docker network shared with Caddy):

   ```bash
   cp .env.example .env
   ```

2. Register Observer as a Protected App in Autentico (`origin`: `https://webhooks.example.com`, `allowed_return_paths`: `["/"]`), note its `data.id`, and optionally set `OBSERVER_AUTENTICO_LOGOUT_PATH=/_autentico/<id>/logout` in `.env`.

3. Add the site block from `Caddyfile.example` to your Caddy configuration and reload Caddy.

4. Build and start Observer:

   ```bash
   docker compose up -d --build
   ```

5. Open `https://webhooks.example.com` (authenticates via Autentico), create an endpoint (e.g., slug `training`), and configure `https://webhooks.example.com/hooks/training` in Cornerstone CSX.
