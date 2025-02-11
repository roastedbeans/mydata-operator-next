import { PrismaClient } from '@prisma/client';
import { faker } from '@faker-js/faker';
import dayjs from 'dayjs';

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

const prisma = new PrismaClient();
const otherBankAPI = 'http://localhost:4000';
const orgCode = 'ORG2025002';
const otherOrgCode = 'ORG2025001';
const clientId = 'ORG2025002-CLIENT-ID';
const clientSecret = 'ORG2025002-CLIENT-SECRET';

// Attack configuration interface
interface AttackConfiguration {
	type: string;
	payload: string;
	location: string;
}

// Generate malicious content
const generateMaliciousContent = (): AttackConfiguration | null => {
	const attackConfigurations = [
		// XSS attacks
		...['User-Agent', 'X-CSRF-Token', 'Cookie', 'Set-Cookie'].map((location) => ({
			type: 'XSS',
			payload: faker.helpers.arrayElement([
				'<script>alert("XSS")</script>',
				'<img src="x" onerror="alert(\'XSS\')">',
				'"><script>alert(document.cookie)</script>',
			]),
			location,
		})),

		// SQLi attacks
		...['client_secret', 'grant_type', 'password', 'timestamp'].map((location) => ({
			type: 'SQLi',
			payload: faker.helpers.arrayElement(["' OR '1'='1", "'; DROP TABLE users--", "' UNION SELECT * FROM accounts--"]),
			location,
		})),

		// Cookie manipulation
		...['Cookie', 'Set-Cookie'].map((location) => ({
			type: 'CookieInjection',
			payload: faker.helpers.arrayElement(['session=admin123; Path=/', 'isAdmin=true; HttpOnly']),
			location,
		})),
	];

	const shouldAttack = faker.datatype.boolean(0.3); // 30% attack chance
	if (!shouldAttack) return null;

	return faker.helpers.arrayElement(attackConfigurations);
};

// Process payload with attack handling
const processPayload = (value: any, attack: AttackConfiguration | null, location: string): string => {
	if (attack && attack.location === location) {
		return attack.payload; // Bypass normal processing for attacks
	}
	return faker.datatype.boolean(0.98) ? value : '';
};

// Generate transaction ID
export const generateTIN = (prefix: string) => {
	const date = new Date();
	const timestamp = date
		.toISOString()
		.replace(/[-:.TZ]/g, '')
		.slice(0, 14); // YYYYMMDDHHMMSS
	return prefix + timestamp;
};

// Generate timestamp
export function timestamp(date: Date): string {
	return date
		.toISOString()
		.replace(/[-:.TZ]/g, '')
		.slice(0, 14); // YYYYMMDDHHMMSS
}

// Generate BodyIA102
export const generateBodyIA102 = async (account: any): Promise<BodyIA102> => {
	const caCode = faker.helpers.arrayElement(['CA20250001']);
	const newTimestamp = timestamp(new Date());
	const serialNum = faker.helpers.arrayElement(['BASA20240204', 'BABB20230106']);

	const signTxId = `${orgCode}_${caCode}_${newTimestamp}_${serialNum}`;
	const firstName = account.firstName;
	const lastName = account.lastName;
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
		const txId = `MD_${orgCode}_${otherOrgCode}_${relayAgencyCode}_${caCode}_${newTimestamp}_${'XXAB0049000' + index}`;

		return {
			tx_id: txId,
			consent_title: consentTitles[index],
			consent: shaConsent,
			consent_len: shaConsent.length,
		};
	});

	const return_app_scheme_url = `https://anya-bank.com/return`;

	return {
		sign_tx_id: signTxId,
		user_ci: b64UserCI,
		real_name: fullName,
		phone_num: processPayload(phoneNum, null, 'phone_num'),
		request_title: requestTitle,
		device_code: deviceCode,
		device_browser: 'WB',
		return_app_scheme_url: processPayload(return_app_scheme_url, null, 'return_app_scheme_url'),
		consent_type: '1',
		consent_cnt: consent_list.length,
		consent_list: consent_list,
	};
};

// Generate BodyIA002
export const generateBodyIA002 = async (
	certTxId: string,
	consent_list: Consent[],
	signed_consent_list: SignedConsent[]
): Promise<BodyIA002> => {
	const txId = signed_consent_list[0].tx_id;
	const orgCode = txId.split('_')[1];
	const ipCode = txId.split('_')[1];
	const raCode = txId.split('_')[2];
	const caCode = txId.split('_')[3];

	const organization = await prisma.organization.findFirst({
		where: { orgCode: ipCode },
	});

	const oAuthClient = await prisma.oAuthClient.findFirst({
		where: { organizationId: organization?.id },
	});

	const certificate = await prisma.certificate.findFirst({
		where: { certTxId: certTxId },
	});

	const account = await prisma.account.findFirst({
		where: { phoneNumber: certificate?.phoneNumber },
	});

	const registrationDate = dayjs().format('DDMMYYYY');
	const serialNum = '0001';

	const generateNonce = () => {
		const letter = faker.string.alpha({ casing: 'upper', length: 1 });
		const year = dayjs().format('YYYY');
		const randomNumber = faker.number.int({ min: 100000000000000, max: 999999999999999 });
		return `${letter}${year}${randomNumber}`;
	};

	const b64PersonInfo = account ? Buffer.from(account.firstName + account.lastName).toString('base64') : '';
	const b64UserCI = account ? Buffer.from(account.pinCode).toString('base64') : '';
	const b64Password = Buffer.from('PASSWORD').toString('base64');

	return {
		tx_id: processPayload(txId, null, 'tx_id'),
		org_code: processPayload(orgCode, null, 'org_code'),
		grant_type: processPayload('password', null, 'grant_type'),
		client_id: oAuthClient ? oAuthClient.clientId : '',
		client_secret: oAuthClient ? oAuthClient.clientSecret : '',
		ca_code: caCode,
		username: processPayload(b64UserCI, null, 'username'),
		request_type: '1',
		password_len: b64Password.length.toString(),
		password: b64Password,
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
};

// API call functions
export const getIA101 = async () => {
	const attack = generateMaliciousContent();

	const options = {
		method: 'POST',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded',
			'x-api-tran-id': processPayload(generateTIN('IA101'), attack, 'x-api-tran-id'),
			'X-CSRF-Token': processPayload('', attack, 'X-CSRF-Token'),
			Cookie: processPayload('', attack, 'Cookie'),
			'Set-Cookie': processPayload('', attack, 'Set-Cookie'),
			'User-Agent': processPayload('Mozilla/5.0', attack, 'User-Agent'),
			'attack-type': attack?.type || '',
		},
		body: new URLSearchParams({
			grant_type: processPayload('client_credential', attack, 'grant_type'),
			client_id: processPayload(clientId, attack, 'client_id'),
			client_secret: processPayload(clientSecret, attack, 'client_secret'),
			scope: processPayload('ca', attack, 'scope'),
		}),
	};

	console.log('Requesting token:', options);
	const response = await fetch('http://localhost:3000/api/oauth/2.0/token', options);

	if (!response.ok) console.error(`HTTP error on IA101! Status: ${response.status}`);
	return await response.json();
};

const getIA102 = async (access_token: string, body: BodyIA102) => {
	const attack = generateMaliciousContent();
	const options = {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			Authorization: `Bearer ${access_token}`,
			'x-api-tran-id': processPayload(generateTIN('IA102'), attack, 'x-api-tran-id'),
			'X-CSRF-Token': processPayload('', attack, 'X-CSRF-Token'),
			Cookie: processPayload('', attack, 'Cookie'),
			'Set-Cookie': processPayload('', attack, 'Set-Cookie'),
			'User-Agent': processPayload('Mozilla/5.0', attack, 'User-Agent'),
			'attack-type': attack?.type || '',
		},
		body: JSON.stringify(body),
	};

	console.log('Requesting sign:', options);
	const response = await fetch(`http://localhost:3000/api/ca/sign_request`, options);

	if (!response.ok) console.error(`HTTP error! Status: ${response.status}`);
	return await response.json();
};

// Similar updates for getIA103, getIA002, getSupport001, getSupport002
// ... (rest of the API functions follow the same pattern)
const getIA103 = async (access_token: string, body: BodyIA103) => {
	const attack = generateMaliciousContent();
	const options = {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			Authorization: `Bearer ${access_token}`,
			'x-api-tran-id': processPayload(generateTIN('IA103'), attack, 'x-api-tran-id'),
			'X-CSRF-Token': processPayload('', attack, 'X-CSRF-Token'),
			Cookie: processPayload('', attack, 'Cookie'),
			'Set-Cookie': processPayload('', attack, 'Set-Cookie'),
			'User-Agent': processPayload('Mozilla/5.0', attack, 'User-Agent'),
			'attack-type': attack?.type || '',
		},
		body: JSON.stringify(body),
	};

	console.log('Requesting sign result:', options);
	const response = await fetch(`http://localhost:3000/api/ca/sign_result`, options);

	if (!response.ok) console.error(`HTTP error! Status: ${response.status}`);
	return await response.json();
};

const getIA002 = async (body: BodyIA002) => {
	const attack = generateMaliciousContent();
	const options = {
		method: 'POST',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded',
			'x-api-tran-id': processPayload(generateTIN('IA002'), attack, 'x-api-tran-id'),
			'X-CSRF-Token': processPayload('', attack, 'X-CSRF-Token'),
			Cookie: processPayload('', attack, 'Cookie'),
			'Set-Cookie': processPayload('', attack, 'Set-Cookie'),
			'User-Agent': processPayload('Mozilla/5.0', attack, 'User-Agent'),
			'attack-type': attack?.type || '',
		},
		body: new URLSearchParams(body),
	};

	console.log('Requesting access token:', options);
	const response = await fetch(`${otherBankAPI}/api/oauth/2.0/token`, options);

	if (!response.ok) console.error(`HTTP error! Status: ${response.status}`);
	return await response.json();
};

const getAccountsBasic = async (orgCode: string, accountNum: string, access_token: string) => {
	const attack = generateMaliciousContent();
	const options = {
		method: 'POST',
		headers: {
			Authorization: `Bearer ${access_token}`,
			'x-api-tran-id': processPayload(generateTIN('ADB01'), attack, 'x-api-tran-id'),
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

	console.log('Requesting basic account information:', options);
	const response = await fetch(`${otherBankAPI}/api/v2/bank/accounts/deposit/basic`, options);

	if (!response.ok) console.error(`HTTP error! Status: ${response.status}`);
	return await response.json();
};

const getAccountsDetail = async (orgCode: string, accountNum: string, access_token: string) => {
	const attack = generateMaliciousContent();
	const options = {
		method: 'POST',
		headers: {
			Authorization: `Bearer ${access_token}`,
			'x-api-tran-id': processPayload(generateTIN('ADD01'), attack, 'x-api-tran-id'),
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

	console.log('Requesting detailed account information:', options);
	const response = await fetch(`${otherBankAPI}/api/v2/bank/accounts/deposit/detail`, options);

	if (!response.ok) console.error(`HTTP error! Status: ${response.status}`);
	return await response.json();
};

// getSupport001: Request token for management API
export async function getSupport001() {
	const attack = generateMaliciousContent();

	const options = {
		method: 'POST',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded',
			'x-api-tran-id': processPayload(generateTIN('SU001'), attack, 'x-api-tran-id'),
			'X-CSRF-Token': processPayload('', attack, 'X-CSRF-Token'),
			Cookie: processPayload('', attack, 'Cookie'),
			'Set-Cookie': processPayload('', attack, 'Set-Cookie'),
			'User-Agent': processPayload('Mozilla/5.0', attack, 'User-Agent'),
			'attack-type': attack?.type || '',
		},
		body: new URLSearchParams({
			grant_type: processPayload('client_credential', attack, 'grant_type'),
			client_id: processPayload(clientId, attack, 'client_id'),
			client_secret: processPayload(clientSecret, attack, 'client_secret'),
			scope: processPayload('manage', attack, 'scope'),
		}),
	};

	console.log('Requesting management token:', options);
	const response = await fetch('http://localhost:3000/api/v2/mgmts/oauth/2.0/token', options);

	if (!response.ok) console.error(`HTTP error on Support001! Status: ${response.status}`);
	return await response.json();
}

// getSupport002: Fetch organization list
export async function getSupport002() {
	const attack = generateMaliciousContent();

	const token = await getSupport001();
	const { access_token } = token;

	const options = {
		method: 'GET',
		headers: {
			'Content-Type': 'application/json',
			'x-api-tran-id': processPayload(generateTIN('SU002'), attack, 'x-api-tran-id'),
			Cookie: processPayload('', attack, 'Cookie'),
			'Set-Cookie': processPayload('', attack, 'Set-Cookie'),
			'User-Agent': processPayload('Mozilla/5.0', attack, 'User-Agent'),
			'attack-type': attack?.type || '',
			Authorization: `Bearer ${processPayload(access_token, attack, 'Authorization')}`,
		},
	};

	console.log('Fetching organization list:', options);
	const response = await fetch(
		`http://localhost:3000/api/v2/mgmts/orgs?search_timestamp=${processPayload(
			timestamp(new Date()),
			attack,
			'timestamp'
		)}`,
		options
	);

	if (!response.ok) console.error(`HTTP error on Support002! Status: ${response.status}`);
	return await response.json();
}

// Main simulation function
async function main() {
	const response = await getSupport002();

	// Simulate user flow
	const token = await getIA101();
	const { access_token } = token;

	if (!access_token) console.error('Error fetching access token in IA101');

	// Add delay to simulate user interaction
	await new Promise((resolve) => setTimeout(resolve, 500));

	// Fetch accounts
	const accounts = await prisma.account.findMany({
		where: { orgCode: orgCode },
	});

	if (!accounts) console.error('Error fetching accounts');

	const account = faker.helpers.arrayElement(accounts);
	const bodyIA102 = await generateBodyIA102(account);

	const responseIA102 = await getIA102(access_token, bodyIA102);
	if (!responseIA102) console.error('Error sign request in IA102');

	await new Promise((resolve) => setTimeout(resolve, 500));

	const bodyIA103: BodyIA103 = {
		sign_tx_id: bodyIA102.sign_tx_id,
		cert_tx_id: responseIA102.cert_tx_id,
	};

	const responseIA103 = await getIA103(access_token, bodyIA103);
	if (!responseIA103) console.error('Error sign result in IA103');

	await new Promise((resolve) => setTimeout(resolve, 500));

	const certTxId = responseIA102.cert_tx_id;
	const signedConsentList = responseIA103.signed_consent_list;
	const consentList = bodyIA102.consent_list;

	const bodyIA002 = await generateBodyIA002(certTxId, consentList, signedConsentList);
	const responseIA002 = await getIA002(bodyIA002);

	if (!responseIA002) console.error('Error request for access token in IA002');

	await new Promise((resolve) => setTimeout(resolve, 500));

	// Fetch account details
	const isGetBasic = faker.datatype.boolean();
	const isGetDetail = faker.datatype.boolean();

	if (isGetBasic) {
		const accountsBasic = await getAccountsBasic(orgCode, account.accountNum, responseIA002.access_token);
		if (!accountsBasic) console.error('Error fetching basic account information');
		await new Promise((resolve) => setTimeout(resolve, 500));
	}

	if (isGetDetail) {
		const accountsDetail = await getAccountsDetail(orgCode, account.accountNum, responseIA002.access_token);
		if (!accountsDetail) console.error('Error fetching detailed account information');
		await new Promise((resolve) => setTimeout(resolve, 500));
	}
}

// Run iterations
async function runIterations() {
	const iterations = 200;
	const delayBetweenIterations = 1000;

	for (let i = 0; i < iterations; i++) {
		await main();
		console.log(`Iteration ${i + 1} completed.`);

		await new Promise((resolve) => setTimeout(resolve, delayBetweenIterations));
	}

	console.log('All iterations completed.');
}

// Execute
runIterations()
	.catch((e) => {
		console.error('Error during iterations:', e);
	})
	.finally(async () => {
		await prisma.$disconnect();
	});
