import { BodyIA102 } from '@/types/body-types';
import { faker } from '@faker-js/faker';
import { timestamp } from '@/utils/formatTimestamp';

export const generateBodyIA102 = () => {
	const orgId = faker.helpers.arrayElement(['ORG2025001', 'ORG2025002']);
	const caId = faker.helpers.arrayElement(['CA2025001']);
	const newTimestamp = timestamp(new Date());
	const serialNum = faker.helpers.arrayElement(['BASA20240204', 'BABB20230106']);

	const signTxId = `${orgId}_${caId}_${newTimestamp}_${serialNum}`;

	const firstName = faker.person.firstName();
	const lastName = faker.person.lastName();
	const b64UserCI = Buffer.from(firstName.toUpperCase()).toString('base64');

	const fullName = `${lastName} ${firstName}`;
	const phoneNum = '+8210' + faker.string.numeric(8);

	// Generate request title based on bank request for consent
	const requestTitle = faker.helpers.arrayElement([
		'Request for Consent to Use Personal Information',
		'Request for Consent to Use Personal Information for Marketing',
		'Request for Consent to Use Personal Information for Research',
		'Request for Consent to Use Personal Information for Service Improvement',
		'Request for Consent to Use Personal Information for Service Development',
	]);

	const deviceCode = faker.helpers.arrayElement(['PC', 'MO', 'TB']);

	const body: BodyIA102 = {
		sign_tx_id: signTxId,
		user_ci: b64UserCI,
		real_name: fullName,
		phone_num: phoneNum,
		request_title: requestTitle,
		device_code: deviceCode,
		device_browser: 'string',
		return_app_scheme_url: 'string',
		consent_type: 'string',
		consent_cnt: 'string',
		consent_list: [
			{
				tx_id: 'string',
				consent_title: 'string',
				consent: 'string',
				consent_len: 0,
			},
		],
	};
	return body;
};
