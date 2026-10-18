import { Transform } from 'class-transformer';
import { IsFQDN, IsString } from 'class-validator';

export class CreateTargetDto {
  /** Bare hostname, e.g. "example.com" (no scheme, path or port). */
  @Transform(({ value }) => (typeof value === 'string' ? value.trim().toLowerCase() : value))
  @IsString()
  @IsFQDN({ require_tld: true, allow_underscores: false })
  hostname!: string;
}
