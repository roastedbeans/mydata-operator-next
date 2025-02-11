import { PrismaClient } from '@prisma/client';
import { faker } from '@faker-js/faker';
import dayjs from 'dayjs';
import type { BodyIA102, BodyIA103, BodyIA002, Consent } from './simulate';

const prisma = new PrismaClient();
const otherBankAPI = 'http://localhost:4200';
const orgCode = 'ORG2025001';
const otherOrgCode = 'ORG2025002';
const clientId = 'ORG2025001-CLIENT-ID';
const clientSecret = 'ORG2025001-CLIENT-SECRET';

// Helper function to generate malicious content
const generateMaliciousContent = () => {
	const xssPayloads = [
		'<script>alert("XSS")</script>',
		'<img src="x" onerror="alert(\'XSS\')">',
		'"><script>alert(document.cookie)</script>',
		'<svg onload="alert(1)">',
		'javascript:alert("XSS")//',
	];

	const maliciousCookieHeaders = [
		'session="+alert(1)+"; Domain=.target.com',
		'auth=admin; Path=/; HttpOnly=false',
		'isAdmin=true; SameSite=None',
		'_ga="><script>alert(1)</script>',
		'JSESSIONID=1234; secure=false',
		"token=' OR 1=1--",
		"role=user'; role=admin",
	];

	const sqlInjectionPayloads = [
		"' OR '1'='1",
		"'; DROP TABLE users--",
		"' UNION SELECT * FROM accounts--",
		"' OR '1'='1' --",
		"admin'--",
	];

	const xxePayloads = [
		'<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
		'<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///dev/random">]><foo>&xxe;</foo>',
	];

	const directoryTraversalPayloads = [
		'../../../etc/passwd',
		'..\\..\\..\\windows\\system32\\cmd.exe',
		'%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
		'....//....//....//etc/passwd',
	];

	const ssrfPayloads = [
		'http://localhost:22',
		'http://169.254.169.254/latest/meta-data/',
		'http://127.0.0.1:3306',
		'file:///etc/passwd',
	];

	const cookieInjectionPayloads = [
		'document.cookie="session=admin123"',
		'javascript:void(document.cookie="userRole=admin")',
		'document.cookie="isAdmin=true; path=/"',
	];

	return {
		xssPayloads: faker.helpers.arrayElement(xssPayloads),
		sqlInjectionPayloads: faker.helpers.arrayElement(sqlInjectionPayloads),
		xxePayloads: faker.helpers.arrayElement(xxePayloads),
		directoryTraversalPayloads: faker.helpers.arrayElement(directoryTraversalPayloads),
		ssrfPayloads: faker.helpers.arrayElement(ssrfPayloads),
		cookieInjectionPayloads: faker.helpers.arrayElement(cookieInjectionPayloads),
		maliciousCookieHeaders: faker.helpers.arrayElement(maliciousCookieHeaders),
	};
};

// Modified function to generate malicious IA102 body
const generateMaliciousBodyIA102 = async () => {
	const maliciousContent = generateMaliciousContent();
	const account = await prisma.account.findFirst();

	if (!account) throw new Error('No account found');

	const emptyFields = faker.helpers.arrayElements(
		[
			'sign_tx_id',
			'user_ci',
			'real_name',
			'phone_num',
			'request_title',
			'device_code',
			'device_browser',
			'return_app_scheme_url',
		],
		faker.number.int({ min: 1, max: 3 })
	);

	const caCode = faker.helpers.arrayElement(['CA20250001', maliciousContent.sqlInjectionPayloads]);
	const newTimestamp = dayjs().format('YYYYMMDDHHmmss');
	const serialNum = faker.helpers.arrayElement(['BASA20240204', maliciousContent.xssPayloads]);

	const signTxId = `${orgCode}_${caCode}_${newTimestamp}_${serialNum}`;

	// Generate malicious consent list
	const consent_list: Consent[] = Array.from({ length: faker.number.int({ min: 1, max: 5 }) }, () => ({
		tx_id: maliciousContent.xssPayloads,
		consent_title: maliciousContent.sqlInjectionPayloads,
		consent: maliciousContent.xxePayloads,
		consent_len: faker.number.int({ min: 100, max: 1000 }),
	}));

	const body: Partial<BodyIA102> = {
		sign_tx_id: emptyFields.includes('sign_tx_id') ? '' : signTxId,
		user_ci: emptyFields.includes('user_ci') ? '' : maliciousContent.xssPayloads,
		real_name: emptyFields.includes('real_name') ? '' : maliciousContent.sqlInjectionPayloads,
		phone_num: emptyFields.includes('phone_num') ? '' : maliciousContent.xssPayloads,
		request_title: emptyFields.includes('request_title') ? '' : maliciousContent.xxePayloads,
		device_code: emptyFields.includes('device_code') ? '' : maliciousContent.directoryTraversalPayloads,
		device_browser: emptyFields.includes('device_browser') ? '' : maliciousContent.ssrfPayloads,
		return_app_scheme_url: emptyFields.includes('return_app_scheme_url')
			? ''
			: maliciousContent.cookieInjectionPayloads,
		consent_type: faker.helpers.arrayElement(['1', '2', '', maliciousContent.sqlInjectionPayloads]),
		consent_cnt: consent_list.length,
		consent_list,
	};

	return body;
};

// Modified function to generate malicious IA002 body
const generateMaliciousBodyIA002 = async (certTxId: string) => {
	const maliciousContent = generateMaliciousContent();

	const emptyFields = faker.helpers.arrayElements(
		['tx_id', 'org_code', 'client_id', 'client_secret', 'username', 'password'],
		faker.number.int({ min: 1, max: 3 })
	);

	const body: Partial<BodyIA002> = {
		tx_id: emptyFields.includes('tx_id') ? '' : maliciousContent.xssPayloads,
		org_code: emptyFields.includes('org_code') ? '' : maliciousContent.sqlInjectionPayloads,
		grant_type: faker.helpers.arrayElement(['password', maliciousContent.sqlInjectionPayloads, '']),
		client_id: emptyFields.includes('client_id') ? '' : maliciousContent.xxePayloads,
		client_secret: emptyFields.includes('client_secret') ? '' : maliciousContent.directoryTraversalPayloads,
		ca_code: maliciousContent.ssrfPayloads,
		username: emptyFields.includes('username') ? '' : maliciousContent.xssPayloads,
		request_type: faker.helpers.arrayElement(['1', '2', '', maliciousContent.sqlInjectionPayloads]),
		password_len: faker.helpers.arrayElement(['10', '', maliciousContent.sqlInjectionPayloads]),
		password: emptyFields.includes('password') ? '' : maliciousContent.cookieInjectionPayloads,
		auth_type: faker.helpers.arrayElement(['1', '2', '', maliciousContent.sqlInjectionPayloads]),
		consent_type: faker.helpers.arrayElement(['1', '2', '', maliciousContent.xxePayloads]),
		cert_tx_id: certTxId,
		service_id: maliciousContent.directoryTraversalPayloads,
	};

	return body;
};

// Function to test CSRF vulnerability
const testCSRF = async (accessToken: string) => {
	const maliciousContent = generateMaliciousContent();

	// Generate malicious headers including cookie injection
	const maliciousHeaders = {
		Origin: faker.internet.url(),
		Referer: faker.internet.url(),
		'X-CSRF-Token': faker.helpers.arrayElement(['', 'invalid_token', maliciousContent.xssPayloads]),
		Cookie: maliciousContent.maliciousCookieHeaders,
		'Set-Cookie': maliciousContent.maliciousCookieHeaders,
		'X-Forwarded-For': faker.internet.ip(),
		'X-Forwarded-Host': faker.internet.domainName(),
		'User-Agent': faker.helpers.arrayElement([
			'"><script>alert(1)</script>',
			`' OR '1'='1`,
			maliciousContent.xssPayloads,
		]),
	};

	// Attempt CSRF attack on various endpoints
	const endpoints = [
		'/api/ca/sign_request',
		'/api/ca/sign_result',
		'/api/oauth/2.0/token',
		'/api/v2/bank/accounts/deposit/basic',
		'/api/v2/bank/accounts/deposit/detail',
	];

	for (const endpoint of endpoints) {
		let baseURL = 'http://localhost:3000';
		if (endpoint === '/api/v2/bank/accounts/deposit/basic' || endpoint === '/api/v2/bank/accounts/deposit/detail') {
			baseURL = 'http://localhost:4000';
		}
		try {
			const response = await fetch(`${baseURL}${endpoint}`, {
				method: 'POST',
				headers: {
					...maliciousHeaders,
					Authorization: `Bearer ${accessToken}`,
					'Content-Type': 'application/json',
				},
				body: JSON.stringify({
					malicious_data: maliciousContent.xssPayloads,
				}),
			});

			console.log(`CSRF test for ${endpoint}:`, response.status);
		} catch (error) {
			console.error(`CSRF test failed for ${endpoint}:`, error);
		}
	}
};

// Main attack simulation function
async function simulateAttacks() {
	try {
		// Get access token
		const tokenResponse = await fetch('http://localhost:3000/api/oauth/2.0/token', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
			},
			body: new URLSearchParams({
				grant_type: 'client_credential',
				client_id: clientId,
				client_secret: clientSecret,
				scope: 'ca',
			}),
		});

		const { access_token } = await tokenResponse.json();

		// Attack simulation for IA102
		// Test IA102 with malicious payloads
		const maliciousBodyIA102 = await generateMaliciousBodyIA102();
		const ia102Response = await fetch('http://localhost:3000/api/ca/sign_request', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${access_token}`,
			},
			body: JSON.stringify(maliciousBodyIA102),
		});

		console.log('IA102 Attack Response:', ia102Response.status);

		// Test IA002 with malicious payloads
		const maliciousBodyIA002 = await generateMaliciousBodyIA002('fake_cert_tx_id');
		const ia002Response = await fetch(`${otherBankAPI}/api/oauth/2.0/token`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
			},
			body: new URLSearchParams(maliciousBodyIA002 as Record<string, string>),
		});

		console.log('IA002 Attack Response:', ia002Response.status);

		// Test CSRF vulnerability
		await testCSRF(access_token);

		// Test SSRF vulnerability
		const ssrfPayloads = [
			'http://169.254.169.254/latest/meta-data/',
			'http://localhost:22',
			'file:///etc/passwd',
			'http://internal-service/',
		];

		for (const payload of ssrfPayloads) {
			try {
				const ssrfResponse = await fetch('http://localhost:3000/api/ca/sign_request', {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						Authorization: `Bearer ${access_token}`,
					},
					body: JSON.stringify({
						...maliciousBodyIA102,
						return_app_scheme_url: payload,
					}),
				});

				console.log(`SSRF test for ${payload}:`, ssrfResponse.status);
			} catch (error) {
				console.error(`SSRF test failed for ${payload}:`, error);
			}
		}
	} catch (error) {
		console.error('Attack simulation failed:', error);
	}
}

// Run attack simulations
async function runAttackSimulations() {
	const iterations = 100; // Number of attack iterations
	const delayBetweenAttacks = 2000; // Delay between attacks in milliseconds

	for (let i = 0; i < iterations; i++) {
		try {
			await simulateAttacks();
			console.log(`Attack iteration ${i + 1} completed.`);
		} catch (error) {
			console.error(`Error in attack iteration ${i + 1}:`, error);
		}

		// Add delay between attacks
		await new Promise((resolve) => setTimeout(resolve, delayBetweenAttacks));
	}

	console.log('All attack simulations completed.');
}

// Run the attack simulations
runAttackSimulations()
	.catch((e) => {
		console.error('Error during attack simulations:', e);
		process.exit(1);
	})
	.finally(async () => {
		await prisma.$disconnect();
	});
