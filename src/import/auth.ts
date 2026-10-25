import { createHash, verify } from 'node:crypto';

export const IMPORT_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAw1M/e7nutEGhBADzTh5kB5A615z440a8RyuQeWqzOW4=
-----END PUBLIC KEY-----`;

export const verifyImportRequest = (
  request: Pick<Request, 'method' | 'url' | 'headers'>,
  rawBody: Uint8Array,
  publicKey = IMPORT_PUBLIC_KEY,
  now = Date.now(),
): boolean => {
  const timestamp = request.headers.get('x-import-timestamp');
  const signature = request.headers.get('x-import-signature');
  if (
    !timestamp || !signature || !/^\d+$/.test(timestamp) ||
    !Number.isSafeInteger(Number(timestamp)) ||
    Math.abs(now - Number(timestamp)) > 300_000 ||
    !/^[A-Za-z0-9+/]{86}==$/.test(signature)
  ) {
    return false;
  }

  try {
    const pathname = new URL(request.url).pathname;
    const hash = createHash('sha256').update(rawBody).digest('hex');
    const message = `${request.method}\n${pathname}\n${timestamp}\n${hash}`;
    return verify(
      null,
      Buffer.from(message, 'utf8'),
      publicKey,
      Buffer.from(signature, 'base64'),
    );
  } catch {
    return false;
  }
};
