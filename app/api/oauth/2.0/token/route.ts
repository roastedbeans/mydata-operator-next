import { NextResponse } from 'next/server';
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

export async function POST(req: Request): Promise<NextResponse> {
	try {
		const headers = req.headers;
		const xApiTranId = headers.get('x-api-tran-id');
		const body: FormData = await req.formData();
		const jsonBody: RequestBody = Object.fromEntries(body) as unknown as RequestBody;

		if (!xApiTranId || xApiTranId.length > 25) {
			return respondWithError(req, jsonBody, 'INVALID_API_TRAN_ID', 400);
		}

		if (jsonBody.grant_type !== 'password' || !jsonBody.client_id || !jsonBody.client_secret) {
			return respondWithError(req, jsonBody, 'INVALID_PARAMETERS', 400);
		}

		const client = await prisma.oAuthClient.findUnique({ where: { clientId: jsonBody.client_id } });
		if (!client || client.clientSecret !== jsonBody.client_secret) {
			return respondWithError(req, jsonBody, 'UNAUTHORIZED', 401);
		}

		if (!isValidRequest(jsonBody)) {
			return respondWithError(req, jsonBody, 'INVALID_PARAMETERS', 400);
		}

		const accessToken = generateToken(jsonBody.client_id, 'ip', 3600);
		const refreshToken = generateToken(jsonBody.client_id, 'ip', 86400);

		const responseData = {
			rsp_code: getResponseMessage('SUCCESS').code,
			rsp_msg: getResponseMessage('SUCCESS').message,
			tx_id: jsonBody.tx_id,
			token_type: 'Bearer',
			access_token: accessToken,
			expires_in: 3600,
			refresh_token: refreshToken,
			refresh_token_expires_in: 86400,
		};

		await logger(JSON.stringify(req), JSON.stringify(jsonBody), JSON.stringify(responseData), '200');
		return NextResponse.json(responseData, { status: 200 });
	} catch (error) {
		console.error('Error in token generation:', error);
		return respondWithError(req, {}, 'INTERNAL_SERVER_ERROR', 500);
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

async function respondWithError(
	req: Request,
	body: Partial<RequestBody>,
	errorCode: any,
	statusCode: number
): Promise<NextResponse> {
	const errorResponse = getResponseMessage(errorCode);
	await logger(JSON.stringify(req), JSON.stringify(body), JSON.stringify(errorResponse), statusCode.toString());
	return NextResponse.json(errorResponse, { status: statusCode });
}
