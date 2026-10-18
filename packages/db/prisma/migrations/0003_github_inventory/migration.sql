-- CreateEnum
CREATE TYPE "InventoryStatus" AS ENUM ('NONE', 'QUEUED', 'RUNNING', 'SUCCEEDED', 'NO_LOCKFILE', 'FAILED');

-- CreateTable
CREATE TABLE "GithubInstallation" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "installationId" TEXT NOT NULL,
    "accountLogin" TEXT NOT NULL,
    "accountType" TEXT NOT NULL,
    "repositorySelection" TEXT NOT NULL,
    "suspendedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "GithubInstallation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Repository" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "installationId" TEXT NOT NULL,
    "githubRepoId" TEXT NOT NULL,
    "owner" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "fullName" TEXT NOT NULL,
    "defaultBranch" TEXT NOT NULL,
    "private" BOOLEAN NOT NULL DEFAULT false,
    "archived" BOOLEAN NOT NULL DEFAULT false,
    "inventoryStatus" "InventoryStatus" NOT NULL DEFAULT 'NONE',
    "inventoryError" TEXT,
    "lastInventorySha" TEXT,
    "lastInventoryAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Repository_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DependencySnapshot" (
    "id" TEXT NOT NULL,
    "repositoryId" TEXT NOT NULL,
    "commitSha" TEXT NOT NULL,
    "branch" TEXT NOT NULL,
    "lockfilePath" TEXT NOT NULL,
    "lockfileVersion" INTEGER NOT NULL,
    "packageCount" INTEGER NOT NULL,
    "directCount" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DependencySnapshot_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PackageInstance" (
    "id" TEXT NOT NULL,
    "snapshotId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "path" TEXT NOT NULL,
    "dev" BOOLEAN NOT NULL DEFAULT false,
    "optional" BOOLEAN NOT NULL DEFAULT false,
    "direct" BOOLEAN NOT NULL DEFAULT false,
    "source" TEXT NOT NULL DEFAULT 'registry',
    "requires" TEXT[],

    CONSTRAINT "PackageInstance_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "GithubInstallation_userId_idx" ON "GithubInstallation"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "GithubInstallation_userId_installationId_key" ON "GithubInstallation"("userId", "installationId");

-- CreateIndex
CREATE INDEX "Repository_userId_idx" ON "Repository"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "Repository_installationId_githubRepoId_key" ON "Repository"("installationId", "githubRepoId");

-- CreateIndex
CREATE INDEX "DependencySnapshot_repositoryId_createdAt_idx" ON "DependencySnapshot"("repositoryId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "DependencySnapshot_repositoryId_commitSha_lockfilePath_key" ON "DependencySnapshot"("repositoryId", "commitSha", "lockfilePath");

-- CreateIndex
CREATE INDEX "PackageInstance_snapshotId_idx" ON "PackageInstance"("snapshotId");

-- CreateIndex
CREATE INDEX "PackageInstance_name_idx" ON "PackageInstance"("name");

-- AddForeignKey
ALTER TABLE "GithubInstallation" ADD CONSTRAINT "GithubInstallation_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Repository" ADD CONSTRAINT "Repository_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Repository" ADD CONSTRAINT "Repository_installationId_fkey" FOREIGN KEY ("installationId") REFERENCES "GithubInstallation"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DependencySnapshot" ADD CONSTRAINT "DependencySnapshot_repositoryId_fkey" FOREIGN KEY ("repositoryId") REFERENCES "Repository"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PackageInstance" ADD CONSTRAINT "PackageInstance_snapshotId_fkey" FOREIGN KEY ("snapshotId") REFERENCES "DependencySnapshot"("id") ON DELETE CASCADE ON UPDATE CASCADE;
