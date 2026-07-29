# @561-group/site

Deployable public identity site for `https://561.group/`.

It is the canonical public Web carrier of the 561 Group. The same carrier
publishes the apex at `https://561.group/` and the catalog projection at
`https://market.561.group/`, while every listed service remains owned and
settled by its operating enterprise. It does not take payment, select service
providers, or custody customer assets.

## Commands

```sh
pnpm test
pnpm check
pnpm serve
node scripts/cloudflare-deployment.mjs preflight
node scripts/cloudflare-deployment.mjs dry-run
node scripts/cloudflare-deployment.mjs deploy
```

Cloudflare projection uses the site-declared Wrangler 4.114.0 and the
canonical `linux-cloudflare-authentication-cell`; it never searches arbitrary
sibling `node_modules`. The preflight requires Node 22 or newer, activates and
verifies the named `bare-cedar-fog-semantic-content-identity` profile against
the expected account, and places the authentication cell's compatibility
wrapper before Ubuntu's `secret-tool`. This is necessary because Ubuntu
`libsecret-tools` implements credential operations but exits 2 for Wrangler's
non-standard `secret-tool --version` probe.

An absent tool, absent profile, expired OAuth grant, and account mismatch are
distinct typed refusals. When the existing grant has expired, the exact repair
from this directory is:

```sh
node_modules/.bin/authenticate-linux-colony-with-cloudflare ops/cloudflare-authentication-request.json
```

That interactive operation stores the renewed grant through Linux Secret
Service, returns no credential, verifies account and exact scopes, and binds
the named profile to this site. On WSL, the authentication cell reads
Wrangler's one-time authorization URL from a private pipe, redacts it from
terminal output, and passes the exact string directly to the Windows browser
through `wslview`; no URL is copied through chat, Markdown, or the clipboard.
A successful `cloudflare:deploy` then builds
the Worker from canonical sources before publishing `561.group`,
`market.561.group`, and `gui.561.group`.

The owner-local unit at `ops/systemd/561-group-site.service` remains a local
development projection. The public carrier is the disposable Cloudflare
Worker deployment above.
