export const JUNS_AUTH_BINDING_COOKIE = '__Host-juns-auth-binding';

export const JUNS_AUTH_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: true,
  sameSite: 'lax' as const,
  path: '/',
  maxAge: 300,
};

export const junsAuthOrigin = () =>
  process.env.JUNS_AUTH_ORIGIN || 'https://auth.juns.page';

export const isAdminReturnPath = (path: unknown): path is string => {
  if (typeof path !== 'string' || path.length > 1024 ||
    !/^\/admin(?:\/|\?|$)/.test(path)) return false;
  let decoded: string;
  try { decoded = decodeURIComponent(path); } catch { return false; }
  return /^\/admin(?:\/|\?|$)/.test(decoded) &&
    !/[\\:%#\u0000-\u0020\u007f]/.test(decoded) &&
    !decoded.includes('//') &&
    !decoded.split('?')[0].split('/').some(p => p === '.' || p === '..');
};

export const adminReturnPath = (value: string | null, origin: string) => {
  const path = value?.startsWith(origin + '/')
    ? value.slice(origin.length)
    : value;
  return isAdminReturnPath(path) ? path : '/admin/photos';
};
