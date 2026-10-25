import { isPathProtected } from '@/app/path';
import NextAuth, { NextAuthConfig, User } from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { encode } from 'next-auth/jwt';
import { isAdminReturnPath, junsAuthOrigin } from './juns-auth';

const authConfig = {
  providers: [
    Credentials({
      async authorize({ email, password }) {
        if (
          process.env.ADMIN_EMAIL && process.env.ADMIN_EMAIL === email &&
          process.env.ADMIN_PASSWORD && process.env.ADMIN_PASSWORD === password
        ) {
          const user: User = { email, name: 'Admin User' };
          return user;
        } else {
          return null;
        }
      },
    }),
  ],
  jwt: {
    encode(params) {
      const expires = params.token?.junsAuthExpires;
      return encode(typeof expires === 'number' ? {
        ...params,
        maxAge: Math.max(0, Math.floor(expires / 1000) -
          Math.floor(Date.now() / 1000)),
      } : params);
    },
  },
  callbacks: {
    jwt({ token, user }) {
      if (user && 'junsAuthExpires' in user) {
        token.junsAuthExpires = user.junsAuthExpires;
      }
      // Auth.js refreshes JWTs on reads; keep the upstream deadline fixed.
      if (typeof token.junsAuthExpires === 'number' &&
        Date.now() >= token.junsAuthExpires) return null;
      return token;
    },
    session({ session, token }) {
      if (typeof token.junsAuthExpires === 'number') {
        return {
          ...session,
          expires: new Date(token.junsAuthExpires).toISOString(),
        };
      }
      return session;
    },
    authorized({ auth, request }) {
      const { pathname } = request.nextUrl;

      const isUrlProtected = isPathProtected(pathname);
      const isUserLoggedIn = !!auth?.user;
      const isRequestAuthorized = !isUrlProtected || isUserLoggedIn;

      return isRequestAuthorized;
    },
  },
  pages: {
    signIn: '/sign-in',
  },
} satisfies NextAuthConfig;

export const {
  handlers: { GET, POST },
  signIn,
  signOut,
  auth,
} = NextAuth(authConfig);

export const signInWithJunsAuth = async (
  state: string,
  code: string,
  binding: string,
) => {
  const secret = process.env.JUNS_AUTH_CLIENT_SECRET;
  const email = process.env.ADMIN_EMAIL;
  if (!secret || !email) throw new Error('SSO unavailable');
  const response = await fetch(new URL('/token', junsAuthOrigin()), {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${secret}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ client: 'photos', state, code, binding }),
    cache: 'no-store',
    redirect: 'error',
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw new Error('SSO exchange failed');
  const result = await response.json();
  if (result.ok !== true || !isAdminReturnPath(result.path) ||
    !Number.isSafeInteger(result.expires) || result.expires <= Date.now() ||
    result.expires > Date.now() + 12 * 60 * 60 * 1000) {
    throw new Error('Invalid SSO response');
  }
  // This provider exists only for this server-side exchange. Public Auth.js
  // handlers never register it, so POSTed user/expiry fields cannot mint
  // a session.
  const { signIn: completeSignIn } = NextAuth({
    ...authConfig,
    providers: [Credentials({
      id: 'juns-passkey',
      authorize: () => ({
        email,
        name: 'Admin User',
        junsAuthExpires: result.expires,
      }),
    })],
  });
  await completeSignIn('juns-passkey', {
    redirect: false,
    redirectTo: result.path,
  });
  return result.path as string;
};

export const runAuthenticatedAdminServerAction = async <T>(
  callback: () => T,
): Promise<T> => {
  const session = await auth();
  if (session?.user) {
    return callback();
  } else {
    throw new Error('Unauthorized server action request');
  }
};
