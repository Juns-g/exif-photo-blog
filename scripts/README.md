# Photo import

Requires Node >= 22. The private Ed25519 PEM stays on the owner's Mac.
The server uses the public key in `src/import/auth.ts`, or `IMPORT_PUBLIC_KEY`
(a PEM string) when configured. No browser admin session is needed.

```sh
node scripts/photo-import.mjs \
  --base https://photos.juns.page \
  --key ~/.config/photo-import/ed25519.pem \
  upload /path/to/photo.jpg --title 'Photo title'

node scripts/photo-import.mjs \
  --base https://photos.juns.page \
  --key ~/.config/photo-import/ed25519.pem \
  list --hidden only
```

Uploads are hidden by default; add `--visible` to make a photo visible.
Upload output is one JSON line; `title` is the supplied override, or `null`
when the existing server pipeline selects the title from EXIF/AI.
List output is JSON; `--hidden` accepts `include` (default), `only`, or `exclude`.
Supported extensions: jpg, jpeg, png, heic, webp (case-insensitive on the client).
Image bytes go directly to R2 through a presigned PUT URL.

For `HTTPS_PROXY`, use Node 24 with its built-in environment proxy support:

```sh
HTTPS_PROXY=http://127.0.0.1:7897 node --use-env-proxy \
  scripts/photo-import.mjs \
  --base https://photos.juns.page \
  --key ~/.config/photo-import/ed25519.pem list
```

Node 22's default fetch does not honor `HTTPS_PROXY`; use Node 24 and the flag
when a proxy is required. No proxy dependency is installed.

Signed requests use `METHOD`, URL pathname (without query), Unix milliseconds,
and the SHA-256 hex digest of the exact request body, joined with newlines.
The signature is base64 Ed25519 in `x-import-signature`; the timestamp is in
`x-import-timestamp`. Server and client clocks must be within 300 seconds.
Per this protocol, query parameters are unsigned, and a signed request can be
replayed within that time window; there is no nonce or idempotency guarantee.
If an add request has an uncertain outcome, use `list` to read back before retrying.
