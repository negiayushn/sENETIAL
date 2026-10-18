import { Module } from '@nestjs/common';
import { GithubController } from './github.controller';
import { GithubService } from './github.service';
import { RepositoriesController } from './repositories.controller';
import { RepositoriesService } from './repositories.service';

@Module({
  controllers: [GithubController, RepositoriesController],
  providers: [GithubService, RepositoriesService],
})
export class GithubModule {}
