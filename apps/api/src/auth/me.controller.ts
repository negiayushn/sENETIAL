import { Controller, Get } from '@nestjs/common';
import { Public } from './decorators';
import { AuthService } from './auth.service';
import { CurrentUser } from './decorators';

@Controller()
export class MeController {
  constructor(private readonly auth: AuthService) {}

  @Get('me')
  me(@CurrentUser() user: { id: string; name: string; email: string; image?: string | null }) {
    return { id: user.id, name: user.name, email: user.email, image: user.image ?? null };
  }

  /** Lets the login page know which sign-in options exist without exposing secrets. */
  @Public()
  @Get('auth-config')
  config() {
    return { emailPassword: true, github: this.auth.githubEnabled };
  }
}
