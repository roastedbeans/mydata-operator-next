export type Organization = {
	id: string;
	name: string;
	opType: string;
	orgCode: string;
	orgType: string;
	authType: string;
	industry: string;
	serialNum: string;
	createdAt: Date;
	updatedAt: Date;
};

export type User = {
	id: string;
	name: string;
	createdAt: Date;
	updatedAt: Date;
	organizationId: string;
	certificates?: Certificate;
	logs?: Log;
	organization: Organization;
};

export type Certificate = {
	id: string;
	serialNumber: string;
	certTxId: string;
	signTxId: string;
	phoneNumber: string;
	userId: string;
	userCI: string;
	requestTitle: string;
	consentType: number;
	deviceCode: string;
	deviceBrowser: string;
	issuedAt: Date;
	expiresAt: Date;
	revoked: boolean;
	revokedAt?: Date;
	revocationReason?: string;
	user: User;
	consentList?: Consent;
	logs?: Log;
	revocationEntries: Revocation[];
	signedConsentList?: SignedConsent;
};

export type Consent = {
	id: string;
	txId: string;
	consentTitle: string;
	consent: string;
	consentLen: number;
	createdAt: Date;
	updatedAt: Date;
	certificateId?: string;
	Certificate?: Certificate;
};

export type SignedConsent = {
	id: string;
	txId: string;
	signedConsent: string;
	signedConsentLen: number;
	createdAt: Date;
	updatedAt: Date;
	certificateId?: string;
	Certificate?: Certificate;
};

export type Revocation = {
	id: string;
	certificateId: string;
	revokedAt: Date;
	reason?: string;
	certificate: Certificate;
};

export type CertificateAuthority = {
	id: string;
	name: string;
	privateKey: string;
	publicKey: string;
	certificateData: string;
	createdAt: Date;
};

export type OAuthClient = {
	id: string;
	clientId: string;
	clientSecret: string;
	createdAt: Date;
	updatedAt: Date;
	organizationId: string;
	organization: Organization;
};

export type Log = {
	id: string;
	userId: string;
	certificateId?: string;
	action: string;
	timestamp: Date;
	details?: string;
	certificate?: Certificate;
	user: User;
};
