# Fork notes (Juns-g/exif-photo-blog)

Personal fork of [sambecker/exif-photo-blog](https://github.com/sambecker/exif-photo-blog) running at [photos.juns.page](https://photos.juns.page).
Forked from upstream `35f469e4`; upstream changes since then are not merged yet.

## Changes vs upstream

### 1. Signed import API (general purpose)

Lets a local script add photos without the browser admin session. New photos are **hidden by default**, so they can be reviewed in `/admin` before going public.

- Auth: Ed25519 request signatures (`src/import/auth.ts`). Headers `x-import-timestamp` (unix ms) and `x-import-signature` (base64) sign
  `METHOD\npathname\ntimestamp\nsha256(body)`; requests outside ±300 s or with a bad signature get `401`.
  The public key lives in source and can be overridden with the `IMPORT_PUBLIC_KEY` env var (PEM). The private key stays on the uploading machine.
- Endpoints (`app/api/import/`):
  - `POST /api/import/presign` `{extension}` → `{uploadUrl, putUrl}`; the client PUTs bytes straight to storage, which avoids Vercel's 4.5 MB body limit.
  - `POST /api/import/add` `{uploadUrl, title?, hidden? = true, tags?, excludeFromFeeds?}` runs the same pipeline as the admin "add upload": EXIF extraction, GPS handling per config, optimized sizes and revalidation. Only `upload-` objects on the configured storage are accepted.
  - `GET /api/import/photos?hidden=include|only|exclude` returns photos for readback and dedupe.
- `addUpload` moved from `src/photo/actions.ts` (`'use server'`) to `src/photo/add-upload.ts`, so it isn't exposed as a public server action. The admin actions behave the same as before.
- Client: `scripts/photo-import.mjs` (Node ≥ 22, no dependencies)

  ```sh
  node --use-env-proxy scripts/photo-import.mjs --base https://photos.example.com --key ~/.config/photo-import/ed25519.pem \
    upload photo.jpg --title 'Title'          # add --visible to publish immediately
  node scripts/photo-import.mjs --base ... --key ... list --hidden only
  ```

  Upload isn't idempotent. If a run fails partway, run `list` before retrying so you don't add duplicates.
- Test: `__tests__/import-auth.test.ts` covers valid signatures and rejection of a tampered body, wrong path, stale timestamp, missing header and wrong key.

### 2. Deployment-specific defaults (this site only)

- `src/app/config.ts`, `src/platforms/storage/cloudflare-r2.ts`, `next.config.ts`: Cloudflare R2 is the default storage, `photos.juns.page` the default domain and `r2.juns.page` the default public bucket domain, each used when the matching env var is unset. **Don't reuse these defaults.** Set the upstream env vars instead.
