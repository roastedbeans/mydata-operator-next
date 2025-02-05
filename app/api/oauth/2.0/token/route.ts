import { NextRequest, NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import { getResponseMessage } from '@/constants/responseMessages';
import { logger } from '@/utils/generateCSV';

const prisma = new PrismaClient();
const JWT_SECRET: string = process.env.JWT_SECRET || 'your-secure-secret';

interface RequestBody {
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
}

export async function POST(req: NextRequest): Promise<NextResponse> {
	const headers = req.headers;
	const headersList = Object.fromEntries(headers.entries());
	const authorization = headers.get('Authorization');
	const xApiTranId = headers.get('x-api-tran-id');
	const method = req.method;
	const url = req.nextUrl.toString();
	const query = Object.fromEntries(req.nextUrl.searchParams);

	const reqBody = await req.formData();
	const body: RequestBody = Object.fromEntries(reqBody) as unknown as RequestBody;

	const request = {
		method,
		url,
		query,
		headers: headersList,
	};

	try {
		if (!xApiTranId || xApiTranId.length > 25) {
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('INVALID_PARAMETERS')),
				'400'
			);
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		if (body.grant_type !== 'password' || !body.client_id || !body.client_secret) {
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('INVALID_PARAMETERS')),
				'400'
			);
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 400 });
		}

		const client = await prisma.oAuthClient.findUnique({ where: { clientId: body.client_id } });
		if (!client || client.clientSecret !== body.client_secret) {
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('INVALID_PARAMETERS')),
				'401'
			);
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 401 });
		}

		if (!isValidRequest(body)) {
			return NextResponse.json(getResponseMessage('INVALID_PARAMETERS'), { status: 401 });
		}

		const accessToken = generateToken(body.client_id, 'ip', 3600);
		const refreshToken = generateToken(body.client_id, 'ip', 86400);

		const responseData = {
			rsp_code: getResponseMessage('SUCCESS').code,
			rsp_msg: getResponseMessage('SUCCESS').message,
			tx_id: body.tx_id,
			token_type: 'Bearer',
			access_token: accessToken,
			expires_in: 3600,
			refresh_token: refreshToken,
			refresh_token_expires_in: 86400,
		};

		await logger(JSON.stringify(request), JSON.stringify(body), JSON.stringify(responseData), '200');
		return NextResponse.json(responseData, { status: 200 });
	} catch (error) {
		console.error('Error in token generation:', error);
		await logger(JSON.stringify(request), JSON.stringify(body), JSON.stringify(error), '500');
		return NextResponse.json(getResponseMessage('INVALID_API_TRAN_ID'), { status: 400 });
	} finally {
		await prisma.$disconnect();
	}
}

function generateToken(clientId: string, scope: string, expiresIn: number): string {
	const payload = {
		iss: process.env.PUBLIC_NEXT_ORG_CODE,
		aud: clientId,
		jti: crypto.randomUUID(),
		exp: Math.floor(Date.now() / 1000) + expiresIn,
		scope,
	};
	return jwt.sign(payload, JWT_SECRET);
}

function isValidRequest(body: RequestBody): boolean {
	return (
		body.tx_id.length <= 74 &&
		body.org_code.length <= 10 &&
		body.grant_type === 'password' &&
		body.ca_code.length <= 10 &&
		body.username.length <= 100 &&
		['0', '1'].includes(body.request_type) &&
		body.password_len.length <= 5 &&
		body.password.length <= 10000 &&
		['0', '1'].includes(body.auth_type) &&
		['0', '1'].includes(body.consent_type) &&
		body.consent_len.length <= 5 &&
		body.consent.length <= 7000 &&
		body.signed_person_info_req_len.length <= 5 &&
		body.signed_person_info_req.length <= 1000 &&
		body.consent_nonce.length <= 30 &&
		body.ucpid_nonce.length <= 30 &&
		body.cert_tx_id.length <= 40 &&
		body.service_id.length <= 22
	);
}
