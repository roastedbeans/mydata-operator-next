import { PrismaClient } from '@prisma/client';
import { faker } from '@faker-js/faker';
import dayjs from 'dayjs';

// Logger utility
const logger = {
	error: (message: string, error?: any) => {
		console.error(`[ERROR] ${message}`, error);
	},
	warn: (message: string) => {
		console.warn(`[WARN] ${message}`);
	},
	info: (message: string) => {
		console.info(`[INFO] ${message}`);
	},
};

// Custom error classes
class ValidationError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'ValidationError';
	}
}

class APIError extends Error {
	statusCode: number;
	errorCode: string;
	originalError: any;

	constructor(message: string, statusCode: number, errorCode: string, originalError?: any) {
		super(message);
		this.name = 'APIError';
		this.statusCode = statusCode;
		this.errorCode = errorCode;
		this.originalError = originalError;
	}
}

// Define types
export type BodyIA102 = {
	sign_tx_id: string;
	user_ci: string;
	real_name: string;
	phone_num: string;
	request_title: string;
	device_code: string;
	device_browser: string;
	return_app_scheme_url: string;
	consent_type: string;
	consent_cnt: number;
	consent_list: Consent[];
};

export type BodyIA103 = {
	cert_tx_id: string;
	sign_tx_id: string;
};

export type BodyIA002 = {
	tx_id: string;
	org_code: string;
	grant_type: string;
	client_id: string;
	client_secret: string;
	ca_code: string;
	username: string;
	request_type: string;
	password_len: string;
	password: string;
	auth_type: string;
	consent_type: string;
	consent_len: string;
	consent: string;
	signed_person_info_req_len: string;
	signed_person_info_req: string;
	consent_nonce: string;
	ucpid_nonce: string;
	cert_tx_id: string;
	service_id: string;
};

export type Consent = {
	tx_id: string;
	consent_title: string;
	consent: string;
	consent_len: number;
};

export type SignedConsent = {
	tx_id: string;
	signed_consent: string;
	signed_consent_len: number;
};

// Initialize Prisma and constants
const prisma = new PrismaClient();
const otherBankAPI = 'http://localhost:4000';
const otherOrgCode = 'anya123456';
const orgCode = 'bond123456';
const clientId = 'xv9gqz7mb4t2o5wcf8rjy6kphudsnea0l3ytkpdhqrvcxz1578';
const clientSecret = 'm4q7xv9zb2tgc8rjy6kphudsnea0l3ow5ytkpdhqrvcfz926bt';
const caCode = 'certauth00';
const orgSerialCode = 'bondserial00';

// Validation functions
const validateBodyIA102 = (body: BodyIA102): void => {
	if (!body.sign_tx_id) throw new ValidationError('sign_tx_id is required');
	if (!body.user_ci) throw new ValidationError('user_ci is required');
	if (!body.real_name) throw new ValidationError('real_name is required');
	if (!body.phone_num) throw new ValidationError('phone_num is required');
	if (!Array.isArray(body.consent_list)) throw new ValidationError('consent_list must be an array');
	if (body.consent_list.length === 0) throw new ValidationError('consent_list cannot be empty');
};

const validateBodyIA103 = (body: BodyIA103): void => {
	if (!body.cert_tx_id) throw new ValidationError('cert_tx_id is required');
	if (!body.sign_tx_id) throw new ValidationError('sign_tx_id is required');
};

const validateBodyIA002 = (body: BodyIA002): void => {
	if (!body.tx_id) throw new ValidationError('tx_id is required');
	if (!body.org_code) throw new ValidationError('org_code is required');
	if (!body.client_id) throw new ValidationError('client_id is required');
	if (!body.client_secret) throw new ValidationError('client_secret is required');
};

// Attack configuration interface
interface AttackConfiguration {
	type: string;
	payload: string;
	location: string;
}

// Generate malicious content with error handling
const generateMaliciousContent = (attackLocation: string[]): AttackConfiguration | null => {
	//all attack location: x-api-tran-id, X-CSRF-Token, Cookie, Set-Cookie, User-Agent, search_timestamp, client_id, client_secret, grant_type, scope, username, password, org_code, account_num, next, return_app_scheme_url, device_code, device_browser, consent_type, consent_cnt, consent_list, signed_person_info_req_len, signed_person_info_req, consent_nonce, ucpid_nonce, cert_tx_id, service_id
	try {
		const attackConfigurations = [
			...attackLocation
				.filter((location) => location !== 'Cookie') // explain why Cookie is excluded: Cookie injection is a separate attack
				.map((location) => ({
					type: 'XSS',
					payload: faker.helpers.arrayElement([
						'<script>alert("XSS")</script>',
						'<img src="x" onerror="alert(\'XSS\')">',
						'<script>alert(document.cookie)</script>',
					]),
					location,
				})),

			// SQLi attacks
			...attackLocation
				.filter((location) => location === 'search_timestamp')
				.map((location) => ({
					type: 'SQLi',
					payload: faker.helpers.arrayElement([
						"' OR '1'='1",
						"'; DROP TABLE users--",
						"' UNION SELECT * FROM accounts--",
					]),
					location,
				})),

			// Cookie manipulation
			...['Cookie', 'Set-Cookie'].map((location) => ({
				type: 'CookieInjection',
				payload: faker.helpers.arrayElement(['session=admin123; Path=/', 'isAdmin=true; HttpOnly']),
				location,
			})),

			// Directory traversal
			...attackLocation.map((location) => ({
				type: 'DirectoryTraversal',
				payload: faker.helpers.arrayElement(['../../../etc/passwd', '../../../../etc/hosts']),
				location,
			})),

			// XML external entity injection
			...attackLocation.map((location) => ({
				type: 'XXE',
				payload: faker.helpers.arrayElement([
					'<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
					'<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "http://example.com/xxe" >]><foo>&xxe;</foo>',
					'<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
				]),
				location,
			})),

			// Payload overflow attack
		];

		const shouldAttack = faker.datatype.boolean(0.3); // 30% attack chance
		return shouldAttack ? faker.helpers.arrayElement(attackConfigurations) : null;
	} catch (error) {
		logger.error('Error generating malicious content', error);
		return null;
	}
};

// Process payload with error handling
const processPayload = (value: any, attack: AttackConfiguration | null, location: string): string => {
	try {
		if (attack && attack.location === location) {
			return attack.payload;
		}
		return faker.datatype.boolean(0.98) ? value : faker.string.alphanumeric({ length: { min: 0, max: 20 } });
	} catch (error) {
		logger.error('Error processing payload', error);
		return value;
	}
};

// Generate transaction ID with error handling
export const generateTIN = (subject: string): string => {
	//subject classification code
	try {
		const date = new Date();
		// grant code 10 uppercase letters + numbers
		const grantCode = faker.string.alphanumeric(14).toUpperCase();

		const xApiTranId = `${orgCode}${subject}${grantCode}`;

		return xApiTranId;
	} catch (error) {
		logger.error('Error generating TIN', error);
		return '00000000000000';
	}
};

// Generate timestamp with error handling
export function timestamp(date: Date): string {
	try {
		return date
			.toISOString()
			.replace(/[-:.TZ]/g, '')
			.slice(0, 14);
	} catch (error) {
		logger.error('Error generating timestamp', error);
		return Date.now().toString();
	}
}

// Utility function for API calls
async function makeAPICall<T>(url: string, options: RequestInit, errorPrefix: string): Promise<T> {
	try {
		const response = await fetch(url, options);

		if (!response.ok) {
			throw new APIError(`${errorPrefix} failed`, response.status, response.statusText, await response.text());
		}

		return await response.json();
	} catch (error) {
		if (error instanceof APIError) {
			throw error;
		}
		throw new APIError(`${errorPrefix} failed`, 500, 'INTERNAL_ERROR', error);
	}
}

// Generate BodyIA102 with error handling
export const generateBodyIA102 = async (account: any): Promise<BodyIA102> => {
	try {
		if (!account) throw new ValidationError('Account is required');

		const caCode = faker.helpers.arrayElement(['certauth00']);
		const newTimestamp = timestamp(new Date());
		const serialNum = faker.helpers.arrayElement(['anyaserial00', 'bondserial00']);

		const signTxId = `${orgCode}_${caCode}_${newTimestamp}_${serialNum}`;
		const firstName = account.firstName;
		const lastName = account.lastName;

		if (!account.pinCode) throw new ValidationError('Account PIN code is required');
		const b64UserCI = Buffer.from(account.pinCode).toString('base64');

		const fullName = `${firstName} ${lastName}`;
		const phoneNum = account.phoneNumber;

		const requestTitle = faker.helpers.arrayElement([
			'Request for Consent to Use Personal Information',
			'Request for Consent to Use Personal Information for Marketing',
			'Request for Consent to Use Personal Information for Research',
		]);

		const deviceCode = faker.helpers.arrayElement(['PC', 'MO', 'TB']);
		const relayAgencyCode = faker.helpers.arrayElement(['RA20250001', 'RA20250002', 'RA20250003']);

		const consentTitles = [
			'Consent Request for Transmission',
			'Consent to Collection and Use of Personal Information',
			'Consent to Provide Personal Information',
		];

		const consentValues = ['consent-001', 'consent-002', 'consent-003'];
		const numConsents = faker.number.int({ min: 1, max: 3 });

		const consent_list = Array.from({ length: numConsents }, (_, index) => {
			const consent = faker.helpers.arrayElement(consentValues);
			const shaConsent = Buffer.from(consent).toString('base64');
			const txId = `MD_${orgCode}_${otherOrgCode}_${relayAgencyCode}_${caCode}_${newTimestamp}_${
				'XXAB0049000' + index
			}`;

			return {
				tx_id: txId,
				consent_title: consentTitles[index],
				consent: shaConsent,
				consent_len: shaConsent.length,
			};
		});

		const body: BodyIA102 = {
			sign_tx_id: signTxId,
			user_ci: b64UserCI,
			real_name: fullName,
			phone_num: processPayload(phoneNum, null, 'phone_num'),
			request_title: requestTitle,
			device_code: deviceCode,
			device_browser: 'WB',
			return_app_scheme_url: processPayload('https://anya-bank.com/return', null, 'return_app_scheme_url'),
			consent_type: '1',
			consent_cnt: consent_list.length,
			consent_list: consent_list,
		};

		validateBodyIA102(body);
		return body;
	} catch (error) {
		logger.error('Error generating BodyIA102', error);
		throw error;
	}
};

// Generate BodyIA002 with error handling
export const generateBodyIA002 = async (
	certTxId: string,
	consent_list: Consent[],
	signed_consent_list: SignedConsent[]
): Promise<BodyIA002> => {
	try {
		if (!certTxId) throw new ValidationError('certTxId is required');
		if (!consent_list?.length) throw new ValidationError('consent_list is required');
		if (!signed_consent_list?.length) throw new ValidationError('signed_consent_list is required');

		const txId = signed_consent_list[0].tx_id;
		const orgCode = txId.split('_')[1];
		const ipCode = txId.split('_')[1];
		const raCode = txId.split('_')[2];
		const caCode = txId.split('_')[3];

		const organization = await prisma.organization.findFirst({
			where: { orgCode: ipCode },
		});

		if (!organization) throw new ValidationError('Organization not found');

		const oAuthClient = await prisma.oAuthClient.findFirst({
			where: { organizationId: organization?.id },
		});

		if (!oAuthClient) throw new ValidationError('OAuth client not found');

		const certificate = await prisma.certificate.findFirst({
			where: { certTxId: certTxId },
		});

		if (!certificate) throw new ValidationError('Certificate not found');

		const account = await prisma.account.findFirst({
			where: { phoneNumber: certificate?.phoneNumber },
		});

		if (!account) throw new ValidationError('Account not found');

		const registrationDate = dayjs().format('DDMMYYYY');
		const serialNum = '0001';

		const generateNonce = () => {
			const letter = faker.string.alpha({ casing: 'upper', length: 1 });
			const year = dayjs().format('YYYY');
			const randomNumber = faker.number.int({ min: 100000000000000, max: 999999999999999 });
			return `${letter}${year}${randomNumber}`;
		};

		const b64PersonInfo = Buffer.from(account.firstName + account.lastName).toString('base64');
		const b64UserCI = Buffer.from(account.pinCode).toString('base64');
		const b64Password = Buffer.from('PASSWORD').toString('base64');

		const body: BodyIA002 = {
			tx_id: processPayload(txId, null, 'tx_id'),
			org_code: processPayload(orgCode, null, 'org_code'),
			grant_type: processPayload('password', null, 'grant_type'),
			client_id: processPayload(oAuthClient.clientId, null, 'client_id'),
			client_secret: processPayload(oAuthClient.clientSecret, null, 'client_secret'),
			ca_code: caCode,
			username: processPayload(b64UserCI, null, 'username'),
			request_type: '1',
			password_len: b64Password.length.toString(),
			password: processPayload(b64Password, null, 'password'),
			auth_type: '1',
			consent_type: '1',
			consent_len: consent_list[0].consent_len.toString(),
			consent: consent_list[0].consent,
			signed_person_info_req_len: b64PersonInfo.length.toString(),
			signed_person_info_req: b64PersonInfo,
			consent_nonce: generateNonce(),
			ucpid_nonce: generateNonce(),
			cert_tx_id: certTxId,
			service_id: processPayload(`${ipCode}${registrationDate}${serialNum}`, null, 'service_id'),
		};

		validateBodyIA002(body);
		return body;
	} catch (error) {
		logger.error('Error generating BodyIA002', error);
		throw error;
	}
};

// API call functions with error handling
export const getIA101 = async () => {
	const attackLocations = [
		'x-api-tran-id',
		'X-CSRF-Token',
		'Cookie',
		'Set-Cookie',
		'User-Agent',
		'client_id',
		'client_secret',
		'grant_type',
		'scope',
	];
	try {
		const attack = generateMaliciousContent(attackLocations);

		const options = {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
				'x-api-tran-id': processPayload(generateTIN('S'), attack, 'x-api-tran-id'),
				'X-CSRF-Token': processPayload('', attack, 'X-CSRF-Token'),
				Cookie: processPayload('', attack, 'Cookie'),
				'Set-Cookie': processPayload('', attack, 'Set-Cookie'),
				'User-Agent': processPayload('Mozilla/5.0', attack, 'User-Agent'),
				'attack-type': attack?.type || '',
			},
			body: new URLSearchParams({
				grant_type: processPayload('client_credentials', attack, 'grant_type'),
				client_id: processPayload(clientId, attack, 'client_id'),
				client_secret: processPayload(clientSecret, attack, 'client_secret'),
				scope: processPayload('ca', attack, 'scope'),
			}),
		};

		logger.info('Requesting token');
		return await makeAPICall('http://localhost:3000/api/oauth/2.0/token', options, 'Token request');
	} catch (error) {
		logger.error('Error in getIA101', error);
		throw error;
	}
};

const getIA102 = async (access_token: string, body: BodyIA102) => {
	const attackLocations = ['x-api-tran-id', 'X-CSRF-Token', 'Cookie', 'Set-Cookie', 'User-Agent'];
	try {
		if (!access_token) throw new ValidationError('Access token is required');
		validateBodyIA102(body);

		const attack = generateMaliciousContent(attackLocations);
		const options = {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${access_token}`,
				'x-api-tran-id': processPayload(generateTIN('S'), attack, 'x-api-tran-id'),
				'X-CSRF-Token': processPayload('', attack, 'X-CSRF-Token'),
				Cookie: processPayload('', attack, 'Cookie'),
				'Set-Cookie': processPayload('', attack, 'Set-Cookie'),
				'User-Agent': processPayload('Mozilla/5.0', attack, 'User-Agent'),
				'attack-type': attack?.type || '',
			},
			body: JSON.stringify(body),
		};

		logger.info('Requesting sign');
		return await makeAPICall('http://localhost:3000/api/ca/sign_request', options, 'Sign request');
	} catch (error) {
		logger.error('Error in getIA102', error);
		throw error;
	}
};

const getIA103 = async (access_token: string, body: BodyIA103) => {
	const attackLocations = ['x-api-tran-id', 'X-CSRF-Token', 'Cookie', 'Set-Cookie', 'User-Agent'];
	try {
		if (!access_token) throw new ValidationError('Access token is required');
		validateBodyIA103(body);

		const attack = generateMaliciousContent(attackLocations);
		const options = {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${access_token}`,
				'x-api-tran-id': processPayload(generateTIN('S'), attack, 'x-api-tran-id'),
				'X-CSRF-Token': processPayload('', attack, 'X-CSRF-Token'),
				Cookie: processPayload('', attack, 'Cookie'),
				'Set-Cookie': processPayload('', attack, 'Set-Cookie'),
				'User-Agent': processPayload('Mozilla/5.0', attack, 'User-Agent'),
				'attack-type': attack?.type || '',
			},
			body: JSON.stringify(body),
		};

		logger.info('Requesting sign result');
		return await makeAPICall('http://localhost:3000/api/ca/sign_result', options, 'Sign result request');
	} catch (error) {
		logger.error('Error in getIA103', error);
		throw error;
	}
};

const getIA002 = async (body: BodyIA002) => {
	const attackLocations = ['x-api-tran-id', 'X-CSRF-Token', 'Cookie', 'Set-Cookie', 'User-Agent'];
	try {
		validateBodyIA002(body);

		const attack = generateMaliciousContent(attackLocations);
		const options = {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
				'x-api-tran-id': processPayload(generateTIN('S'), attack, 'x-api-tran-id'),
				'X-CSRF-Token': processPayload('', attack, 'X-CSRF-Token'),
				Cookie: processPayload('', attack, 'Cookie'),
				'Set-Cookie': processPayload('', attack, 'Set-Cookie'),
				'User-Agent': processPayload('Mozilla/5.0', attack, 'User-Agent'),
				'attack-type': attack?.type || '',
			},
			body: new URLSearchParams(body),
		};

		logger.info('Requesting access token');
		return await makeAPICall(`${otherBankAPI}/api/oauth/2.0/token`, options, 'Access token request');
	} catch (error) {
		logger.error('Error in getIA002', error);
		throw error;
	}
};

const getAccountsBasic = async (orgCode: string, accountNum: string, access_token: string) => {
	const attackLocations = ['x-api-tran-id', 'X-CSRF-Token', 'Cookie', 'Set-Cookie', 'User-Agent'];
	try {
		if (!orgCode) throw new ValidationError('Organization code is required');
		if (!accountNum) throw new ValidationError('Account number is required');
		if (!access_token) throw new ValidationError('Access token is required');

		const attack = generateMaliciousContent(attackLocations);
		const options = {
			method: 'POST',
			headers: {
				Authorization: `Bearer ${access_token}`,
				'x-api-tran-id': processPayload(generateTIN('S'), attack, 'x-api-tran-id'),
				'X-CSRF-Token': processPayload('', attack, 'X-CSRF-Token'),
				Cookie: processPayload('', attack, 'Cookie'),
				'Set-Cookie': processPayload('', attack, 'Set-Cookie'),
				'User-Agent': processPayload('Mozilla/5.0', attack, 'User-Agent'),
				'attack-type': attack?.type || '',
			},
			body: JSON.stringify({
				org_code: otherOrgCode,
				account_num: accountNum,
				next: '0',
				search_timestamp: timestamp(new Date()),
			}),
		};

		logger.info('Requesting basic account information');
		return await makeAPICall(
			`${otherBankAPI}/api/v2/bank/accounts/deposit/basic`,
			options,
			'Basic account information request'
		);
	} catch (error) {
		logger.error('Error in getAccountsBasic', error);
		throw error;
	}
};

const getAccountsDetail = async (orgCode: string, accountNum: string, access_token: string) => {
	const attackLocations = ['x-api-tran-id', 'X-CSRF-Token', 'Cookie', 'Set-Cookie', 'User-Agent', 'search_timestamp'];
	try {
		if (!orgCode) throw new ValidationError('Organization code is required');
		if (!accountNum) throw new ValidationError('Account number is required');
		if (!access_token) throw new ValidationError('Access token is required');

		const attack = generateMaliciousContent(attackLocations);
		const options = {
			method: 'POST',
			headers: {
				Authorization: `Bearer ${access_token}`,
				'x-api-tran-id': processPayload(generateTIN('S'), attack, 'x-api-tran-id'),
				'X-CSRF-Token': processPayload('', attack, 'X-CSRF-Token'),
				Cookie: processPayload('', attack, 'Cookie'),
				'Set-Cookie': processPayload('', attack, 'Set-Cookie'),
				'User-Agent': processPayload('Mozilla/5.0', attack, 'User-Agent'),
				'attack-type': attack?.type || '',
			},
			body: JSON.stringify({
				org_code: otherOrgCode,
				account_num: accountNum,
				next: '0',
				search_timestamp: processPayload(timestamp(new Date()), attack, 'search_timestamp'),
			}),
		};

		logger.info('Requesting detailed account information');
		return await makeAPICall(
			`${otherBankAPI}/api/v2/bank/accounts/deposit/detail`,
			options,
			'Detailed account information request'
		);
	} catch (error) {
		logger.error('Error in getAccountsDetail', error);
		throw error;
	}
};

export async function getSupport001() {
	const attackLocations = [
		'x-api-tran-id',
		'X-CSRF-Token',
		'Cookie',
		'Set-Cookie',
		'User-Agent',
		'client_id',
		'client_secret',
		'grant_type',
		'scope',
	];
	try {
		const attack = generateMaliciousContent(attackLocations);
		const options = {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
				'x-api-tran-id': processPayload(generateTIN('S'), attack, 'x-api-tran-id'),
				'X-CSRF-Token': processPayload('', attack, 'X-CSRF-Token'),
				Cookie: processPayload('', attack, 'Cookie'),
				'Set-Cookie': processPayload('', attack, 'Set-Cookie'),
				'User-Agent': processPayload('Mozilla/5.0', attack, 'User-Agent'),
				'attack-type': attack?.type || '',
			},
			body: new URLSearchParams({
				grant_type: processPayload('client_credentials', attack, 'grant_type'),
				client_id: processPayload(clientId, attack, 'client_id'),
				client_secret: processPayload(clientSecret, attack, 'client_secret'),
				scope: processPayload('manage', attack, 'scope'),
			}),
		};

		logger.info('Requesting management token');
		return await makeAPICall('http://localhost:3000/api/v2/mgmts/oauth/2.0/token', options, 'Management token request');
	} catch (error) {
		logger.error('Error in getSupport001', error);
		throw error;
	}
}

export async function getSupport002() {
	const attackLocations = ['x-api-tran-id', 'Cookie', 'Set-Cookie', 'User-Agent', 'Authorization', 'search_timestamp'];
	try {
		const attack = generateMaliciousContent(attackLocations);
		const tokenResponse = (await getSupport001()) as { access_token: string };

		if (!tokenResponse?.access_token) {
			throw new APIError('Failed to obtain management token', 401, 'UNAUTHORIZED');
		}

		const options = {
			method: 'GET',
			headers: {
				'Content-Type': 'application/json',
				'x-api-tran-id': processPayload(generateTIN('S'), attack, 'x-api-tran-id'),
				Cookie: processPayload('', attack, 'Cookie'),
				'Set-Cookie': processPayload('', attack, 'Set-Cookie'),
				'User-Agent': processPayload('Mozilla/5.0', attack, 'User-Agent'),
				'attack-type': attack?.type || '',
				Authorization: `Bearer ${processPayload(tokenResponse.access_token, attack, 'Authorization')}`,
			},
		};

		return await makeAPICall(
			`http://localhost:3000/api/v2/mgmts/orgs?search_timestamp=${processPayload(
				timestamp(new Date()),
				attack,
				'search_timestamp'
			)}`,
			options,
			'Organization list request'
		);
	} catch (error) {
		logger.error('Error in getSupport002', error);
		throw error;
	}
}

// Main simulation function with comprehensive error handling
async function main() {
	try {
		const response = await getSupport002();

		const token = (await getIA101()) as { access_token: string };
		if (!token?.access_token) {
			throw new APIError('Failed to obtain access token', 401, 'UNAUTHORIZED');
		}

		// Add delay to simulate user interaction
		await new Promise((resolve) => setTimeout(resolve, 3000));

		// Fetch accounts with error handling
		const accounts = await prisma.account
			.findMany({
				where: { orgCode: orgCode },
			})
			.catch((error) => {
				throw new APIError('Failed to fetch accounts', 500, 'DATABASE_ERROR', error);
			});

		if (!accounts || accounts.length === 0) {
			throw new APIError('No accounts found', 404, 'NOT_FOUND');
		}

		const account = faker.helpers.arrayElement(accounts);
		const bodyIA102 = await generateBodyIA102(account);
		const responseIA102 = (await getIA102(token.access_token, bodyIA102)) as {
			cert_tx_id: string;
			sign_tx_id: string;
		};

		if (!responseIA102?.cert_tx_id) {
			throw new APIError('Invalid sign request response', 500, 'INVALID_RESPONSE');
		}

		await new Promise((resolve) => setTimeout(resolve, 4000));

		const bodyIA103: BodyIA103 = {
			sign_tx_id: bodyIA102.sign_tx_id,
			cert_tx_id: responseIA102.cert_tx_id,
		};

		const responseIA103 = (await getIA103(token.access_token, bodyIA103)) as { signed_consent_list: SignedConsent[] };
		if (!responseIA103?.signed_consent_list) {
			throw new APIError('Invalid sign result response', 500, 'INVALID_RESPONSE');
		}

		await new Promise((resolve) => setTimeout(resolve, 3000));

		const bodyIA002 = await generateBodyIA002(
			responseIA102.cert_tx_id,
			bodyIA102.consent_list,
			responseIA103.signed_consent_list
		);

		const responseIA002 = (await getIA002(bodyIA002)) as { access_token: string };
		if (!responseIA002?.access_token) {
			throw new APIError('Failed to obtain access token', 401, 'UNAUTHORIZED');
		}

		await new Promise((resolve) => setTimeout(resolve, 5000));

		// Fetch account details with randomization
		const isGetBasic = faker.datatype.boolean();
		const isGetDetail = faker.datatype.boolean();

		if (isGetBasic) {
			await getAccountsBasic(orgCode, account.accountNum, responseIA002.access_token);
			await new Promise((resolve) => setTimeout(resolve, 4000));
		}

		if (isGetDetail) {
			await getAccountsDetail(orgCode, account.accountNum, responseIA002.access_token);
			await new Promise((resolve) => setTimeout(resolve, 4000));
		}

		logger.info('Main process completed successfully');
	} catch (error) {
		if (error instanceof APIError) {
			logger.error(`API Error: ${error.message}`, {
				statusCode: error.statusCode,
				errorCode: error.errorCode,
				originalError: error.originalError,
			});
		} else if (error instanceof ValidationError) {
			logger.error(`Validation Error: ${error.message}`);
		} else {
			logger.error('Unexpected error in main function', error);
		}
		throw error;
	}
}

// Run iterations with retry logic
async function runIterations() {
	const iterations = 200;
	const delayBetweenIterations = 4000;
	const maxRetries = 1;

	for (let i = 0; i < iterations; i++) {
		let retries = 0;
		while (retries < maxRetries) {
			try {
				await main();
				logger.info(`Iteration ${i + 1} completed successfully`);
				break;
			} catch (error) {
				retries++;
				if (retries === maxRetries) {
					logger.error(`Iteration ${i + 1} failed after ${maxRetries} retries`, error);
					// Continue with next iteration instead of stopping completely
					break;
				}
				logger.warn(`Retry ${retries} for iteration ${i + 1}`);
				await new Promise((resolve) => setTimeout(resolve, 1000 * retries));
			}
		}
		await new Promise((resolve) => setTimeout(resolve, delayBetweenIterations));
	}

	logger.info('All iterations completed');
}

// Execute with proper error handling and cleanup
runIterations()
	.catch((error) => {
		logger.error('Fatal error in runIterations', error);
		process.exit(1);
	})
	.finally(async () => {
		try {
			await prisma.$disconnect();
			logger.info('Prisma disconnected successfully');
		} catch (error) {
			logger.error('Error disconnecting from Prisma', error);
			process.exit(1);
		}
	});
