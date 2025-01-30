-- CreateTable
CREATE TABLE "Organization" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "opType" TEXT NOT NULL,
    "orgCode" TEXT NOT NULL,
    "orgType" TEXT NOT NULL,
    "authType" TEXT NOT NULL,
    "industry" TEXT NOT NULL,
    "serialNum" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Organization_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "organizationId" TEXT NOT NULL,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Certificate" (
    "id" TEXT NOT NULL,
    "serialNumber" TEXT NOT NULL,
    "certTxId" TEXT NOT NULL,
    "signTxId" TEXT NOT NULL,
    "phoneNumber" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "userCI" TEXT NOT NULL,
    "requestTitle" TEXT NOT NULL,
    "consentType" INTEGER NOT NULL,
    "deviceCode" TEXT NOT NULL,
    "deviceBrowser" TEXT NOT NULL,
    "issuedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revoked" BOOLEAN NOT NULL DEFAULT false,
    "revokedAt" TIMESTAMP(3),
    "revocationReason" TEXT,
    "certificateAuthorityId" TEXT,

    CONSTRAINT "Certificate_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Consent" (
    "id" TEXT NOT NULL,
    "txId" TEXT NOT NULL,
    "consentTitle" TEXT NOT NULL,
    "consent" TEXT NOT NULL,
    "consentLen" INTEGER NOT NULL,
    "purpose" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "userId" TEXT NOT NULL,
    "certificateId" TEXT,

    CONSTRAINT "Consent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SignedConsent" (
    "id" TEXT NOT NULL,
    "txId" TEXT NOT NULL,
    "signedConsent" TEXT NOT NULL,
    "signedConsentLen" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "userId" TEXT NOT NULL,
    "certificateId" TEXT,

    CONSTRAINT "SignedConsent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Revocation" (
    "id" TEXT NOT NULL,
    "certificateId" TEXT NOT NULL,
    "revokedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "reason" TEXT,

    CONSTRAINT "Revocation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CertificateAuthority" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "privateKey" TEXT NOT NULL,
    "publicKey" TEXT NOT NULL,
    "certificateData" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CertificateAuthority_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OAuthClient" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "clientSecret" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "organizationId" TEXT NOT NULL,

    CONSTRAINT "OAuthClient_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Log" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "certificateId" TEXT,
    "bankId" TEXT,
    "actionType" TEXT NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "details" TEXT,

    CONSTRAINT "Log_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Account" (
    "account_num" TEXT NOT NULL,
    "org_code" TEXT NOT NULL,
    "seqno" SERIAL NOT NULL,
    "account_type" TEXT NOT NULL,
    "account_status" TEXT NOT NULL,
    "prod_name" TEXT NOT NULL,
    "is_consent" BOOLEAN NOT NULL DEFAULT false,
    "is_minus" BOOLEAN NOT NULL DEFAULT false,
    "is_foreign_deposit" BOOLEAN NOT NULL DEFAULT false,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "userId" TEXT,

    CONSTRAINT "Account_pkey" PRIMARY KEY ("account_num")
);

-- CreateTable
CREATE TABLE "DepositAccount" (
    "deposit_id" TEXT NOT NULL,
    "account_num" TEXT NOT NULL,
    "exp_date" TIMESTAMP(3) NOT NULL,
    "commit_amt" DECIMAL(65,30) NOT NULL,
    "issue_date" TIMESTAMP(3) NOT NULL,
    "currency_code" TEXT NOT NULL,
    "saving_method" TEXT NOT NULL,
    "monthly_paid_in_amt" DECIMAL(65,30) NOT NULL,
    "balance_amt" DECIMAL(65,30) NOT NULL,
    "offered_rate" DECIMAL(65,30) NOT NULL,
    "last_paid_in_cnt" INTEGER NOT NULL,
    "withdrawable_amt" DECIMAL(65,30) NOT NULL,

    CONSTRAINT "DepositAccount_pkey" PRIMARY KEY ("deposit_id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Organization_name_key" ON "Organization"("name");

-- CreateIndex
CREATE UNIQUE INDEX "Organization_orgCode_key" ON "Organization"("orgCode");

-- CreateIndex
CREATE UNIQUE INDEX "Organization_serialNum_key" ON "Organization"("serialNum");

-- CreateIndex
CREATE UNIQUE INDEX "User_name_key" ON "User"("name");

-- CreateIndex
CREATE UNIQUE INDEX "Certificate_serialNumber_key" ON "Certificate"("serialNumber");

-- CreateIndex
CREATE UNIQUE INDEX "Certificate_certTxId_key" ON "Certificate"("certTxId");

-- CreateIndex
CREATE UNIQUE INDEX "Certificate_signTxId_key" ON "Certificate"("signTxId");

-- CreateIndex
CREATE UNIQUE INDEX "Certificate_phoneNumber_key" ON "Certificate"("phoneNumber");

-- CreateIndex
CREATE UNIQUE INDEX "Consent_txId_key" ON "Consent"("txId");

-- CreateIndex
CREATE UNIQUE INDEX "Consent_certificateId_key" ON "Consent"("certificateId");

-- CreateIndex
CREATE UNIQUE INDEX "SignedConsent_txId_key" ON "SignedConsent"("txId");

-- CreateIndex
CREATE UNIQUE INDEX "SignedConsent_certificateId_key" ON "SignedConsent"("certificateId");

-- CreateIndex
CREATE UNIQUE INDEX "OAuthClient_clientId_key" ON "OAuthClient"("clientId");

-- CreateIndex
CREATE UNIQUE INDEX "OAuthClient_clientSecret_key" ON "OAuthClient"("clientSecret");

-- CreateIndex
CREATE UNIQUE INDEX "OAuthClient_organizationId_key" ON "OAuthClient"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "Account_account_num_key" ON "Account"("account_num");

-- CreateIndex
CREATE UNIQUE INDEX "Account_seqno_key" ON "Account"("seqno");

-- CreateIndex
CREATE UNIQUE INDEX "DepositAccount_deposit_id_key" ON "DepositAccount"("deposit_id");

-- AddForeignKey
ALTER TABLE "User" ADD CONSTRAINT "User_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Certificate" ADD CONSTRAINT "Certificate_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Certificate" ADD CONSTRAINT "Certificate_certificateAuthorityId_fkey" FOREIGN KEY ("certificateAuthorityId") REFERENCES "CertificateAuthority"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Consent" ADD CONSTRAINT "Consent_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Consent" ADD CONSTRAINT "Consent_certificateId_fkey" FOREIGN KEY ("certificateId") REFERENCES "Certificate"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SignedConsent" ADD CONSTRAINT "SignedConsent_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SignedConsent" ADD CONSTRAINT "SignedConsent_certificateId_fkey" FOREIGN KEY ("certificateId") REFERENCES "Certificate"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Revocation" ADD CONSTRAINT "Revocation_certificateId_fkey" FOREIGN KEY ("certificateId") REFERENCES "Certificate"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OAuthClient" ADD CONSTRAINT "OAuthClient_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Log" ADD CONSTRAINT "Log_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Log" ADD CONSTRAINT "Log_certificateId_fkey" FOREIGN KEY ("certificateId") REFERENCES "Certificate"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Log" ADD CONSTRAINT "Log_bankId_fkey" FOREIGN KEY ("bankId") REFERENCES "Organization"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Account" ADD CONSTRAINT "Account_org_code_fkey" FOREIGN KEY ("org_code") REFERENCES "Organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Account" ADD CONSTRAINT "Account_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DepositAccount" ADD CONSTRAINT "DepositAccount_account_num_fkey" FOREIGN KEY ("account_num") REFERENCES "Account"("account_num") ON DELETE RESTRICT ON UPDATE CASCADE;
