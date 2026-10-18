-- CreateEnum
CREATE TYPE "MatchStatus" AS ENUM ('PENDING', 'RUNNING', 'DONE', 'FAILED');

-- AlterTable
ALTER TABLE "DependencySnapshot" ADD COLUMN     "matchError" TEXT,
ADD COLUMN     "matchStatus" "MatchStatus" NOT NULL DEFAULT 'PENDING',
ADD COLUMN     "matchSummary" JSONB,
ADD COLUMN     "matchedAt" TIMESTAMP(3);

-- AlterTable
ALTER TABLE "Finding" ADD COLUMN     "repositoryId" TEXT;

-- CreateTable
CREATE TABLE "Advisory" (
    "id" TEXT NOT NULL,
    "modified" TIMESTAMP(3) NOT NULL,
    "published" TIMESTAMP(3),
    "withdrawn" TIMESTAMP(3),
    "summary" TEXT,
    "details" TEXT,
    "aliases" TEXT[],
    "severity" "Severity",
    "severitySource" TEXT,
    "cvssScore" DOUBLE PRECISION,
    "cvssVector" TEXT,
    "affected" JSONB NOT NULL,
    "packageNames" TEXT[],
    "references" JSONB,
    "fetchedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Advisory_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Advisory_packageNames_idx" ON "Advisory" USING GIN ("packageNames");

-- CreateIndex
CREATE INDEX "Advisory_modified_idx" ON "Advisory"("modified");

-- CreateIndex
CREATE INDEX "Finding_repositoryId_idx" ON "Finding"("repositoryId");

-- AddForeignKey
ALTER TABLE "Finding" ADD CONSTRAINT "Finding_repositoryId_fkey" FOREIGN KEY ("repositoryId") REFERENCES "Repository"("id") ON DELETE CASCADE ON UPDATE CASCADE;
