/*
  Warnings:

  - The primary key for the `Account` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - You are about to drop the column `account_num` on the `Account` table. All the data in the column will be lost.
  - You are about to drop the column `account_status` on the `Account` table. All the data in the column will be lost.
  - You are about to drop the column `account_type` on the `Account` table. All the data in the column will be lost.
  - You are about to drop the column `created_at` on the `Account` table. All the data in the column will be lost.
  - You are about to drop the column `is_consent` on the `Account` table. All the data in the column will be lost.
  - You are about to drop the column `is_foreign_deposit` on the `Account` table. All the data in the column will be lost.
  - You are about to drop the column `is_minus` on the `Account` table. All the data in the column will be lost.
  - You are about to drop the column `org_code` on the `Account` table. All the data in the column will be lost.
  - You are about to drop the column `prod_name` on the `Account` table. All the data in the column will be lost.
  - You are about to drop the column `updated_at` on the `Account` table. All the data in the column will be lost.
  - The primary key for the `DepositAccount` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - You are about to drop the column `account_num` on the `DepositAccount` table. All the data in the column will be lost.
  - You are about to drop the column `balance_amt` on the `DepositAccount` table. All the data in the column will be lost.
  - You are about to drop the column `commit_amt` on the `DepositAccount` table. All the data in the column will be lost.
  - You are about to drop the column `currency_code` on the `DepositAccount` table. All the data in the column will be lost.
  - You are about to drop the column `deposit_id` on the `DepositAccount` table. All the data in the column will be lost.
  - You are about to drop the column `exp_date` on the `DepositAccount` table. All the data in the column will be lost.
  - You are about to drop the column `issue_date` on the `DepositAccount` table. All the data in the column will be lost.
  - You are about to drop the column `last_paid_in_cnt` on the `DepositAccount` table. All the data in the column will be lost.
  - You are about to drop the column `monthly_paid_in_amt` on the `DepositAccount` table. All the data in the column will be lost.
  - You are about to drop the column `offered_rate` on the `DepositAccount` table. All the data in the column will be lost.
  - You are about to drop the column `saving_method` on the `DepositAccount` table. All the data in the column will be lost.
  - You are about to drop the column `withdrawable_amt` on the `DepositAccount` table. All the data in the column will be lost.
  - You are about to drop the column `bankId` on the `Log` table. All the data in the column will be lost.
  - You are about to drop the column `organizationId` on the `User` table. All the data in the column will be lost.
  - A unique constraint covering the columns `[accountNum]` on the table `Account` will be added. If there are existing duplicate values, this will fail.
  - A unique constraint covering the columns `[depositId]` on the table `DepositAccount` will be added. If there are existing duplicate values, this will fail.
  - Added the required column `accountNum` to the `Account` table without a default value. This is not possible if the table is not empty.
  - Added the required column `accountStatus` to the `Account` table without a default value. This is not possible if the table is not empty.
  - Added the required column `accountType` to the `Account` table without a default value. This is not possible if the table is not empty.
  - Added the required column `firstName` to the `Account` table without a default value. This is not possible if the table is not empty.
  - Added the required column `lastName` to the `Account` table without a default value. This is not possible if the table is not empty.
  - Added the required column `orgCode` to the `Account` table without a default value. This is not possible if the table is not empty.
  - Added the required column `phoneNumber` to the `Account` table without a default value. This is not possible if the table is not empty.
  - Added the required column `pinCode` to the `Account` table without a default value. This is not possible if the table is not empty.
  - Added the required column `prodName` to the `Account` table without a default value. This is not possible if the table is not empty.
  - Added the required column `accountNum` to the `DepositAccount` table without a default value. This is not possible if the table is not empty.
  - Added the required column `balanceAmt` to the `DepositAccount` table without a default value. This is not possible if the table is not empty.
  - Added the required column `commitAmt` to the `DepositAccount` table without a default value. This is not possible if the table is not empty.
  - Added the required column `currencyCode` to the `DepositAccount` table without a default value. This is not possible if the table is not empty.
  - Added the required column `depositId` to the `DepositAccount` table without a default value. This is not possible if the table is not empty.
  - Added the required column `expDate` to the `DepositAccount` table without a default value. This is not possible if the table is not empty.
  - Added the required column `issueDate` to the `DepositAccount` table without a default value. This is not possible if the table is not empty.
  - Added the required column `lastPaidInCnt` to the `DepositAccount` table without a default value. This is not possible if the table is not empty.
  - Added the required column `monthlyPaidInAmt` to the `DepositAccount` table without a default value. This is not possible if the table is not empty.
  - Added the required column `offeredRate` to the `DepositAccount` table without a default value. This is not possible if the table is not empty.
  - Added the required column `savingMethod` to the `DepositAccount` table without a default value. This is not possible if the table is not empty.
  - Added the required column `withdrawableAmt` to the `DepositAccount` table without a default value. This is not possible if the table is not empty.
  - Added the required column `orgCode` to the `User` table without a default value. This is not possible if the table is not empty.

*/
-- DropForeignKey
ALTER TABLE "Account" DROP CONSTRAINT "Account_org_code_fkey";

-- DropForeignKey
ALTER TABLE "DepositAccount" DROP CONSTRAINT "DepositAccount_account_num_fkey";

-- DropForeignKey
ALTER TABLE "Log" DROP CONSTRAINT "Log_bankId_fkey";

-- DropForeignKey
ALTER TABLE "User" DROP CONSTRAINT "User_organizationId_fkey";

-- DropIndex
DROP INDEX "Account_account_num_key";

-- DropIndex
DROP INDEX "DepositAccount_deposit_id_key";

-- AlterTable
ALTER TABLE "Account" DROP CONSTRAINT "Account_pkey",
DROP COLUMN "account_num",
DROP COLUMN "account_status",
DROP COLUMN "account_type",
DROP COLUMN "created_at",
DROP COLUMN "is_consent",
DROP COLUMN "is_foreign_deposit",
DROP COLUMN "is_minus",
DROP COLUMN "org_code",
DROP COLUMN "prod_name",
DROP COLUMN "updated_at",
ADD COLUMN     "accountNum" TEXT NOT NULL,
ADD COLUMN     "accountStatus" TEXT NOT NULL,
ADD COLUMN     "accountType" TEXT NOT NULL,
ADD COLUMN     "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
ADD COLUMN     "firstName" TEXT NOT NULL,
ADD COLUMN     "isConsent" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "isForeignDeposit" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "isMinus" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "lastName" TEXT NOT NULL,
ADD COLUMN     "orgCode" TEXT NOT NULL,
ADD COLUMN     "phoneNumber" TEXT NOT NULL,
ADD COLUMN     "pinCode" TEXT NOT NULL,
ADD COLUMN     "prodName" TEXT NOT NULL,
ADD COLUMN     "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
ADD CONSTRAINT "Account_pkey" PRIMARY KEY ("accountNum");

-- AlterTable
ALTER TABLE "Certificate" ALTER COLUMN "consentType" SET DATA TYPE TEXT;

-- AlterTable
ALTER TABLE "DepositAccount" DROP CONSTRAINT "DepositAccount_pkey",
DROP COLUMN "account_num",
DROP COLUMN "balance_amt",
DROP COLUMN "commit_amt",
DROP COLUMN "currency_code",
DROP COLUMN "deposit_id",
DROP COLUMN "exp_date",
DROP COLUMN "issue_date",
DROP COLUMN "last_paid_in_cnt",
DROP COLUMN "monthly_paid_in_amt",
DROP COLUMN "offered_rate",
DROP COLUMN "saving_method",
DROP COLUMN "withdrawable_amt",
ADD COLUMN     "accountNum" TEXT NOT NULL,
ADD COLUMN     "balanceAmt" DECIMAL(65,30) NOT NULL,
ADD COLUMN     "commitAmt" DECIMAL(65,30) NOT NULL,
ADD COLUMN     "currencyCode" TEXT NOT NULL,
ADD COLUMN     "depositId" TEXT NOT NULL,
ADD COLUMN     "expDate" TIMESTAMP(3) NOT NULL,
ADD COLUMN     "issueDate" TIMESTAMP(3) NOT NULL,
ADD COLUMN     "lastPaidInCnt" INTEGER NOT NULL,
ADD COLUMN     "monthlyPaidInAmt" DECIMAL(65,30) NOT NULL,
ADD COLUMN     "offeredRate" DECIMAL(65,30) NOT NULL,
ADD COLUMN     "savingMethod" TEXT NOT NULL,
ADD COLUMN     "withdrawableAmt" DECIMAL(65,30) NOT NULL,
ADD CONSTRAINT "DepositAccount_pkey" PRIMARY KEY ("depositId");

-- AlterTable
ALTER TABLE "Log" DROP COLUMN "bankId",
ADD COLUMN     "orgCode" TEXT;

-- AlterTable
ALTER TABLE "User" DROP COLUMN "organizationId",
ADD COLUMN     "orgCode" TEXT NOT NULL;

-- CreateIndex
CREATE UNIQUE INDEX "Account_accountNum_key" ON "Account"("accountNum");

-- CreateIndex
CREATE UNIQUE INDEX "DepositAccount_depositId_key" ON "DepositAccount"("depositId");

-- AddForeignKey
ALTER TABLE "User" ADD CONSTRAINT "User_orgCode_fkey" FOREIGN KEY ("orgCode") REFERENCES "Organization"("orgCode") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Log" ADD CONSTRAINT "Log_orgCode_fkey" FOREIGN KEY ("orgCode") REFERENCES "Organization"("orgCode") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Account" ADD CONSTRAINT "Account_orgCode_fkey" FOREIGN KEY ("orgCode") REFERENCES "Organization"("orgCode") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DepositAccount" ADD CONSTRAINT "DepositAccount_accountNum_fkey" FOREIGN KEY ("accountNum") REFERENCES "Account"("accountNum") ON DELETE RESTRICT ON UPDATE CASCADE;
