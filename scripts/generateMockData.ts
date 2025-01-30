import { BodyIA102 } from '@/types/body-types';
import { faker } from '@faker-js/faker';
import { timestamp } from '@/utils/formatTimestamp';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();
export const generateBodyIA102 = async () => {
	const orgCode = faker.helpers.arrayElement(['ORG2025001']);

	// Fetch accounts that belong to the organization
	const accounts = await prisma.account.findMany({
		where: {
			orgCode: orgCode,
		},
	});

	const caCode = faker.helpers.arrayElement(['CA20250001']);
	const newTimestamp = timestamp(new Date());
	const serialNum = faker.helpers.arrayElement(['BASA20240204', 'BABB20230106']);

	const signTxId = `${orgCode}_${caCode}_${newTimestamp}_${serialNum}`;

	const account = faker.helpers.arrayElement(accounts);

	const firstName = account.firstName;
	const lastName = account.lastName;
	const b64UserCI = Buffer.from(account.pinCode).toString('base64');

	const fullName = `${lastName} ${firstName}`;
	const phoneNum = account.phoneNumber;

	// Generate request title based on bank request for consent
	const requestTitle = faker.helpers.arrayElement([
		'Request for Consent to Use Personal Information',
		'Request for Consent to Use Personal Information for Marketing',
		'Request for Consent to Use Personal Information for Research',
		'Request for Consent to Use Personal Information for Service Improvement',
		'Request for Consent to Use Personal Information for Service Development',
	]);

	const consentTitles = [
		'Consent Request for Transmission',
		'Consent to Collection and Use of Personal Information',
		'Consent to Provide Personal Information',
	];

	const deviceCode = faker.helpers.arrayElement(['PC', 'MO', 'TB']);

	const relayAgencyCode = faker.helpers.arrayElement([
		'RA20250001',
		'RA20250002',
		'RA20250003',
		'RA20250004',
		'RA20250005',
	]);

	const consentValues = ['consent-001', 'consent-002', 'consent-003', 'consent-004', 'consent-005'];

	// Randomly determine how many consents to generate (1 to 3)
	const numConsents = faker.number.int({ min: 1, max: 3 });

	// Generate consent_list dynamically
	const consent_list = Array.from({ length: numConsents }, (_, index) => {
		const consent = faker.helpers.arrayElement(consentValues);
		const shaConsent = Buffer.from(consent).toString('base64');

		return {
			tx_id: `MD_${orgCode}_${relayAgencyCode}_${caCode}_${newTimestamp}_${serialNum}_${index + 1}`,
			consent_title: consentTitles[index], // Ensure unique title for each
			consent: shaConsent,
			consent_len: shaConsent.length,
		};
	});

	console.log('Consent List:', consent_list);

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
