import { createParamDecorator, ExecutionContext, SetMetadata } from '@nestjs/common';
import type { Request } from 'express';
import type { AuthSession } from './auth.service';

export const IS_PUBLIC_KEY = 'isPublic';
/** Opt a route (or controller) out of the global AuthGuard. */
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);

export type AuthedRequest = Request & { session: AuthSession };

export const CurrentUser = createParamDecorator((_: unknown, ctx: ExecutionContext) => {
  return ctx.switchToHttp().getRequest<AuthedRequest>().session.user;
});
