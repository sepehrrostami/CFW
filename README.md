# Edge Relay

A lightweight WebSocket-to-TCP relay built for Cloudflare Workers, with a built-in page for generating and sharing a connection profile (QR code included).

**[نسخه فارسی این راهنما → README.fa.md](./README.fa.md)**

## What's included

- `src/worker.js` — the relay itself, deployed as a single Cloudflare Worker
- `/panel` route — a built-in page that displays your connection profile as a scannable QR code and a copyable link
- `/links` route — the same profile as plain text, for scripting or manual copy-paste

No database, no separate backend, no server to maintain, and — as shown below — **no terminal or command line required either.** Everything can be set up entirely from the Cloudflare dashboard in a browser.

## What you need

- A Cloudflare account (the free tier is enough) — sign up at [dash.cloudflare.com](https://dash.cloudflare.com) if you don't have one
- The contents of `src/worker.js` from this repository (open it on GitHub and copy everything, or download the file)

That's it. No Node.js, no npm, no Wrangler, no git required for this method.

## Deploying from the dashboard

### Step 1 — Create the Worker

1. Log in to [dash.cloudflare.com](https://dash.cloudflare.com).
2. In the left sidebar, select **Workers & Pages**.
3. Select **Create application**.
4. Choose the **"Hello World"** worker template and give it a name (this name becomes part of your final address, e.g. `my-relay.<your-subdomain>.workers.dev`).
5. Select **Deploy**.

### Step 2 — Paste in the code

1. Once the placeholder Worker is deployed, select **Edit code**. This opens an online code editor right in your browser.
2. Select all the existing placeholder code and delete it.
3. Paste in the entire contents of `src/worker.js` from this repository.
4. Before deploying, find this line near the top and change the password to whatever you'd like:
   ```js
   let plainPassword = 'ygsyafgGGFud123';
   ```
   **This is the only line you need to edit.** The value actually used to validate incoming connections is derived from it automatically, so there's nothing else to keep in sync.
5. Select **Deploy** (usually in the top-right of the editor) to publish your changes.

### Step 3 — Get your connection profile

Open this address in any browser:

```
https://<your-worker-name>.<your-subdomain>.workers.dev/panel
```

You'll immediately see a QR code and a copyable link — nothing else to configure. The plain-text link alone is also available at `/links`.

### Step 4 (optional) — Set a preferred fallback address

Some destinations can't be reached with a direct connection (see **Known limitations** below), so the relay automatically tries a few fallback hosts. If you'd rather use one you control:

1. Go to your Worker's page in the dashboard → the **Settings** tab → **Variables and Secrets**.
2. Select **Add** → set Type to **Secret**, Name to `PROXYIP`, and Value to your fallback host.
3. Select **Save and deploy**.

If you skip this step, the built-in fallback list in `src/worker.js` (the `h2` array) is used instead — see the limitations section for why that list isn't guaranteed to always be available.

## Configuration reference

The generated link/QR encodes the following:

| Field | Value | Notes |
|---|---|---|
| Address | your Worker's domain | read automatically from the incoming request, no manual entry needed |
| Port | 443 | fixed |
| Password | value of `plainPassword` | sent as plain text; the client hashes it before use |
| Transport | WebSocket | |
| TLS | enabled | `fp=chrome` fingerprint |
| Early data | up to 2560 bytes | carried in the `Sec-WebSocket-Protocol` header |

## Known limitations

- **Destinations behind Cloudflare's own network can't be reached with a direct connection.** Workers aren't allowed to open outbound TCP sockets to Cloudflare's own IP ranges — this is a platform-level restriction, not a bug in this code. The relay automatically falls back to the hosts in `h2` when this happens.
- **The default fallback hosts are community-run and may go offline without notice.** For anything you depend on, set your own address via the `PROXYIP` variable (Step 4 above).
- If a specific destination consistently fails, open your Worker's page in the dashboard → **Logs** tab → **Begin log stream**, then reproduce the issue. The relay logs every connection attempt, including which fallback hosts were tried and why each one failed.

## Alternative: deploying from a terminal

If you'd rather work locally with git and the Wrangler CLI instead of the dashboard, this repository also includes `wrangler.jsonc`, `package.json`, and `.gitignore` for that workflow:

```bash
git clone <your-repo-url>
cd edge-relay
npm install
npx wrangler login
npx wrangler deploy
```

Both methods deploy the exact same code — use whichever is more comfortable.

## Project structure

```
edge-relay/
├── src/
│   └── worker.js       # the relay
├── wrangler.jsonc       # only needed for the terminal-based method
├── package.json         # only needed for the terminal-based method
├── .gitignore
├── README.md            # this file
└── README.fa.md         # Persian translation
```

## License

MIT — update this section with your preferred license before publishing.
