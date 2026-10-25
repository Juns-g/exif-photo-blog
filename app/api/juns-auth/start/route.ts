import { randomBytes, createHash } from 'node:crypto';
import { NextRequest, NextResponse } from 'next/server';
import {
  adminReturnPath,
  JUNS_AUTH_BINDING_COOKIE,
  JUNS_AUTH_COOKIE_OPTIONS,
  junsAuthOrigin,
} from '@/auth/juns-auth';

export async function GET(request: NextRequest) {
  if (!process.env.JUNS_AUTH_CLIENT_SECRET) {
    return new Response('SSO unavailable', {
      status: 503,
      headers: { 'Cache-Control': 'no-store' },
    });
  }
  const binding = randomBytes(32).toString('base64url');
  const url = new URL('/start', junsAuthOrigin());
  url.search = new URLSearchParams({
    client: 'photos',
    binding: createHash('sha256').update(binding).digest('hex'),
    path: adminReturnPath(
      request.nextUrl.searchParams.get('callbackUrl'),
      request.nextUrl.origin,
    ),
  }).toString();
  const response = NextResponse.redirect(url, 303);
  response.headers.set('Cache-Control', 'no-store');
  response.cookies.set(
    JUNS_AUTH_BINDING_COOKIE, binding, JUNS_AUTH_COOKIE_OPTIONS,
  );
  return response;
}
