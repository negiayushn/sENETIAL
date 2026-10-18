import { NextRequest, NextResponse } from 'next/server';

// Optimistic gate: only checks that a Better Auth session cookie exists.
// The API's AuthGuard is the real enforcement; an expired/forged cookie gets a 401 there and bounces to /login.
const COOKIES = ['better-auth.session_token', '__Secure-better-auth.session_token'];

export function proxy(req: NextRequest) {
  const hasSession = COOKIES.some((c) => req.cookies.has(c));
  const { pathname } = req.nextUrl;

  if (!hasSession && pathname !== '/login') {
    return NextResponse.redirect(new URL('/login', req.url));
  }
  if (hasSession && pathname === '/login') {
    return NextResponse.redirect(new URL('/dashboard', req.url));
  }
  return NextResponse.next();
}

export const config = { matcher: ['/', '/login', '/dashboard/:path*', '/targets/:path*', '/findings/:path*'] };
