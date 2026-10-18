import { FindingSource, FindingStatus, Severity } from '@sentinel/db';
import { IsEnum, IsOptional } from 'class-validator';

export class ListFindingsQuery {
  @IsOptional()
  @IsEnum(FindingStatus)
  status?: FindingStatus;

  @IsOptional()
  @IsEnum(Severity)
  severity?: Severity;

  @IsOptional()
  @IsEnum(FindingSource)
  source?: FindingSource;
}
