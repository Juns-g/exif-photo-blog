import { cookies } from 'next/headers';
import { NextRequest, NextResponse } from 'next/server';
import { signInWithJunsAuth } from '@/auth/server';
import {
  JUNS_AUTH_BINDING_COOKIE,
  JUNS_AUTH_COOKIE_OPTIONS,
} from '@/auth/juns-auth';

export async function GET(request: NextRequest) {
  const headers = {
    'Cache-Control': 'no-store',
    'Referrer-Policy': 'no-referrer',
  };
  const jar = await cookies();
  const binding = jar.get(JUNS_AUTH_BINDING_COOKIE)?.value || '';
  jar.set(JUNS_AUTH_BINDING_COOKIE, '', {
    ...JUNS_AUTH_COOKIE_OPTIONS,
    maxAge: 0,
  });
  const params = request.nextUrl.searchParams;
  const state = params.get('state') || '';
  const code = params.get('code') || '';
  if (params.size !== 2 ||
    [...params.keys()].some(k => !['state', 'code'].includes(k)) ||
    [state, code, binding].some(v => !/^[A-Za-z0-9_-]{43}$/.test(v))) {
    return new Response('SSO failed', { status: 400, headers });
  }
  try {
    const path = await signInWithJunsAuth(state, code, binding);
    const response = NextResponse.redirect(new URL(path, request.url), 303);
    response.headers.set('Cache-Control', 'no-store');
    response.headers.set('Referrer-Policy', 'no-referrer');
    return response;
  } catch {
    return new Response('SSO failed', {
      status: 400,
      headers,
    });
  }
}
