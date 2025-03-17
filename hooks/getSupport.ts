import React from 'react';
import { generateTIN } from '../utils/generateTIN';

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
				client_id: process.env.NEXT_PUBLIC_BOND_CLIENT_ID || '',
				client_secret: process.env.NEXT_PUBLIC_BOND_CLIENT_SECRET || '',
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
			Authorization: `Bearer ${access_token}`,
			'x-api-tran-id': generateTIN('SU002'),
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
