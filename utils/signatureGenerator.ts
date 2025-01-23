// app/api/utils/signatureGenerator.ts
import { v4 as uuidv4 } from 'uuid';
import * as crypto from 'crypto';

interface SignatureInput {
	consent: string;
	sign_tx_id: string;
	timestamp: string;
}

export function generateSignature(data: SignatureInput): string {
	// Create a basic signature payload
	const signaturePayload = {
		type: 'SignedConsent',
		version: '1.0',
		sign_tx_id: data.sign_tx_id,
		timestamp: data.timestamp,
	};

	// Convert to string and encode to base64
	const jsonString = JSON.stringify(signaturePayload);
	const base64Signature = Buffer.from(jsonString).toString('base64');

	// Make it URL-safe
	return base64Signature.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Helper function to create the full signature response
export function createSignatureResponse(consent: string, signTxId: string) {
	const timestamp = new Date().toISOString();

	const signedConsent = generateSignature({
		consent: consent,
		sign_tx_id: signTxId,
		timestamp,
	});

	return {
		signed_consent: signedConsent,
		signed_consent_len: signedConsent.length,
	};
}

// Helper function to create signed array of consent list
export function createSignedConsentList(consentList: string[], signTxId: string) {
	const signedConsentList = [];
	const timestamp = new Date().toISOString();

	for (const consent of consentList) {
		const signedConsent = generateSignature({
			consent: consent,
			sign_tx_id: signTxId,
			timestamp,
		});

		signedConsentList.push(signedConsent);
	}

	return { signedConsentList, signedConsentListCnt: signedConsentList.length };
}

export function generateCertTxId() {
	const timestamp = new Date()
		.toISOString()
		.replace(/[-:.TZ]/g, '')
		.slice(0, 14); // YYYYMMDDHHMMSS

	const id = uuidv4().replace(/-/g, ''); // Remove dashes from UUID
	return `${timestamp}${id}`.substring(0, 40); // Ensure it fits within 40 characters
}

// Function to sign transaction data (generate signature)
export function generateTxId(
	privateKey: string,
	transactionData: { action: string; tx_id: string; timestamp: string }
): string {
	// Stringify the transaction data
	const dataToSign = JSON.stringify(transactionData);

	// Create a signature using HMAC with SHA256
	const signature = crypto.createHmac('sha256', privateKey).update(dataToSign).digest('hex');

	return signature;
}
