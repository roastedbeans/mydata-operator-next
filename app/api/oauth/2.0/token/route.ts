import { NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import { getResponseMessage } from '@/constants/responseMessages';
import { initializeCsv, logRequestToCsv } from '@/utils/generateCSV';

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secure-secret'; // Replace with your secure environment variable

export async function POST(req: Request) {
	await initializeCsv();

	try {
		// Parse and validate headers
		const headers = req.headers;
		const xApiTranId = headers.get('x-api-tran-id');

		if (!xApiTranId || xApiTranId.length > 25) {
			return NextResponse.json(getResponseMessage('INVALID_API_TRAN_ID'), { status: 400 });
		}

		// Parse body
		const body = await req.formData();
		const txId = body.get('tx_id');
		const orgCode = body.get('org_code');
		const grantType = body.get('grant_type');
		const clientId = body.get('client_id');
		const clientSecret = body.get('client_secret');
		const caCode = body.get('ca_code');
		const username = body.get('username');
		const requestType = body.get('request_type');
		const passwordLen = body.get('password_len');
		const password = body.get('password');
		const authType = body.get('auth_type');
		const consentType = body.get('consent_type');
		const consentLen = body.get('consent_len');
		const consent = body.get('consent');
		const signedPersonInfoReqLen = body.get('signed_person_info_req_len');
		const signedPersonInfoReq = body.get('signed_person_info_req');
		const consentNonce = body.get('consent_nonce');
		const ucpidNonce = body.get('ucpid_nonce');
		const certTxId = body.get('cert_tx_id');
		const serviceId = body.get('service_id');

		// Validate body parameters
		if (grantType !== 'password' || !clientId || !clientSecret) {
			await logRequestToCsv('bank.ca', JSON.stringify(getResponseMessage('INVALID_PARAMETERS')));
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		// Authenticate client using Supabase via Prisma
		const client = await prisma.oAuthClient.findUnique({
			where: { clientId: clientId as string },
		});

		if (!client || client.clientSecret !== clientSecret) {
			await logRequestToCsv('bank.ca', JSON.stringify(getResponseMessage('INVALID_PARAMETERS')));
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 401 });
		}

		if (
			!txId ||
			!orgCode ||
			!caCode ||
			!username ||
			!requestType ||
			!passwordLen ||
			!password ||
			!authType ||
			!consentType ||
			!consentLen ||
			!consent ||
			!signedPersonInfoReqLen ||
			!signedPersonInfoReq ||
			!consentNonce ||
			!ucpidNonce ||
			!certTxId ||
			!serviceId
		) {
			await logRequestToCsv('bank.ca', JSON.stringify(getResponseMessage('INVALID_PARAMETERS')));
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		if ((txId as string).length > 74) {
			await logRequestToCsv('bank.ca', JSON.stringify(getResponseMessage('INVALID_PARAMETERS')));
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		if ((orgCode as string).length > 10) {
			await logRequestToCsv('bank.ca', JSON.stringify(getResponseMessage('INVALID_PARAMETERS')));
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		if ((grantType as string) != 'password') {
			await logRequestToCsv('bank.ca', JSON.stringify(getResponseMessage('INVALID_PARAMETERS')));
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		if ((caCode as string).length > 10) {
			await logRequestToCsv('bank.ca', JSON.stringify(getResponseMessage('INVALID_PARAMETERS')));
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		if ((username as string).length > 100) {
			await logRequestToCsv('bank.ca', JSON.stringify(getResponseMessage('INVALID_PARAMETERS')));
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		if ((requestType as string) !== '0' && (requestType as string) !== '1') {
			await logRequestToCsv('bank.ca', JSON.stringify(getResponseMessage('INVALID_PARAMETERS')));
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		if ((passwordLen as string).length > 5) {
			await logRequestToCsv('bank.ca', JSON.stringify(getResponseMessage('INVALID_PARAMETERS')));
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		if ((password as string).length > 10000) {
			await logRequestToCsv('bank.ca', JSON.stringify(getResponseMessage('INVALID_PARAMETERS')));
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		if ((authType as string) !== '0' && (authType as string) !== '1') {
			await logRequestToCsv('bank.ca', JSON.stringify(getResponseMessage('INVALID_PARAMETERS')));
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		if ((consentType as string) !== '0' && (consentType as string) !== '1') {
			await logRequestToCsv('bank.ca', JSON.stringify(getResponseMessage('INVALID_PARAMETERS')));
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		if ((consentLen as string).length > 5) {
			await logRequestToCsv('bank.ca', JSON.stringify(getResponseMessage('INVALID_PARAMETERS')));
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		if ((consent as string).length > 7000) {
			await logRequestToCsv('bank.ca', JSON.stringify(getResponseMessage('INVALID_PARAMETERS')));
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		if ((signedPersonInfoReqLen as string).length > 5) {
			await logRequestToCsv('bank.ca', JSON.stringify(getResponseMessage('INVALID_PARAMETERS')));
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		if ((signedPersonInfoReq as string).length > 1000) {
			await logRequestToCsv('bank.ca', JSON.stringify(getResponseMessage('INVALID_PARAMETERS')));
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		if ((consentNonce as string).length > 30) {
			await logRequestToCsv('bank.ca', JSON.stringify(getResponseMessage('INVALID_PARAMETERS')));
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		if ((ucpidNonce as string).length > 30) {
			await logRequestToCsv('bank.ca', JSON.stringify(getResponseMessage('INVALID_PARAMETERS')));
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		if ((certTxId as string).length > 40) {
			await logRequestToCsv('bank.ca', JSON.stringify(getResponseMessage('INVALID_PARAMETERS')));
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		if ((serviceId as string).length > 22) {
			await logRequestToCsv('bank.ca', JSON.stringify(getResponseMessage('INVALID_PARAMETERS')));
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		// Generate JWT token
		const accessToken = generateAccessToken(clientId as string, 'ip');

		const refreshToken = generateRefreshToken(clientId as string, 'ip');

		const responseData = {
			rsp_code: getResponseMessage('SUCCESS').code,
			rsp_msg: getResponseMessage('SUCCESS').message,
			tx_id: txId,
			token_type: 'Bearer',
			access_token: accessToken, // access token
			expires_in: 3600, // token expiry in seconds (1 hour)
			refresh_token: refreshToken, // refresh token
			refresh_token_expires_in: 86400, // refresh token expiry in seconds (1 day)

			// timestamp: timestamp(new Date()),
		};

		await logRequestToCsv('bank.ca', JSON.stringify(responseData));

		return NextResponse.json(responseData, { status: 200 });
	} catch (error) {
		await logRequestToCsv('bank.ca', JSON.stringify(getResponseMessage('INTERNAL_SERVER_ERROR')));
		console.error('Error in token generation:', error);
		return NextResponse.json(getResponseMessage('INTERNAL_SERVER_ERROR'), { status: 500 });
	} finally {
		await prisma.$disconnect();
	}
}

// JWT Token generation function
function generateAccessToken(clientId: string, scope: string): string {
	// Generate the JWT payload
	const payload = {
		iss: process.env.PUBLIC_NEXT_ORG_CODE, // Issuer: Institution code
		aud: clientId, // Audience: Replace with appropriate institution code
		jti: crypto.randomUUID(), // Unique token identifier
		exp: Math.floor(Date.now() / 1000) + 3600, // Expiry time (1 hour from now)
		scope: scope, // Scope of access
	};

	return jwt.sign(payload, JWT_SECRET);
}

function generateRefreshToken(clientId: string, scope: string): string {
	// Generate the JWT payload
	const payload = {
		iss: process.env.PUBLIC_NEXT_ORG_CODE, // Issuer: Institution code
		aud: clientId, // Audience: Replace with appropriate institution code
		jti: crypto.randomUUID(), // Unique token identifier
		exp: Math.floor(Date.now() / 1000) + 86400, // Expiry time (1 day from now)
		scope: scope, // Scope of access
	};

	return jwt.sign(payload, JWT_SECRET);
}
