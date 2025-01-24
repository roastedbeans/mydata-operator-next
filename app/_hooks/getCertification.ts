import { generateTIN } from '@/utils/generateTIN';

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

export const getIA102 = async () => {
	const token = await getIA101();

	const { access_token } = token;

	const options = {
		method: 'GET',
		headers: {
			'Access-Control-Allow-Origin': '*',
			'Content-Type': 'application/json',
			'x-api-tran-id': generateTIN('IA102'),
			Authorization: `Bearer ${access_token}`,
		},
	};

	const response = await fetch(`http://localhost:3000/api/ca/sign_request`, options);

	if (!response.ok) {
		// Handle HTTP errors
		throw new Error(`HTTP error! Status: ${response.status}`);
	}

	const res = await response.json();

	return res;
};
