import { NextRequest, NextResponse } from 'next/server';
import { PrismaClient } from '@prisma/client';
import { getResponseContent, getResponseMessage, ResponseData } from '@/constants/responseMessages';
import jwt from 'jsonwebtoken';
import { logger } from '@/utils/generateCSV';
import { timestamp } from '@/utils/formatTimestamp';

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secure-secret';

export async function POST(req: NextRequest) {
	const headers = req.headers;
	const headersList = Object.fromEntries(headers.entries());
	const authorization = headers.get('Authorization');
	const xApiTranId = headers.get('x-api-tran-id');
	const xApiType = headers.get('x-api-type');
	const method = req.method;
	const url = req.nextUrl.toString();
	const query = Object.fromEntries(req.nextUrl.searchParams);

	const body = await req.json();
	const { org_code, account_num, next, search_timestamp } = body;

	const request = {
		method,
		url,
		query,
		headers: headersList,
		body,
	};

	try {
		if (!authorization || !authorization.startsWith('Bearer ')) {
			const responseData: ResponseData = {
				headers: {
					contentType: 'application/json;charset=UTF-8',
					xApiTranId: xApiTranId || '',
				},
				body: getResponseMessage('UNAUTHORIZED'),
			};
			const response = getResponseContent(responseData);
			await logger(JSON.stringify(request), JSON.stringify(response), 401);
			return NextResponse.json(response, { status: 401 });
		}

		// Extract the token
		const token = authorization.split(' ')[1];
		let decodedToken;

		try {
			decodedToken = jwt.verify(token, JWT_SECRET);
		} catch (error) {
			const responseData: ResponseData = {
				headers: {
					contentType: 'application/json;charset=UTF-8',
					xApiTranId: xApiTranId || '',
				},
				body: getResponseMessage('INVALID_TOKEN'),
			};
			const response = getResponseContent(responseData);
			await logger(JSON.stringify(request), JSON.stringify(response), 403);
			return NextResponse.json(response, { status: 403 });
		}

		// Validate x-api-tran-id
		if (!xApiTranId || xApiTranId.length > 25) {
			const responseData: ResponseData = {
				headers: {
					contentType: 'application/json;charset=UTF-8',
					xApiTranId: xApiTranId || '',
				},
				body: getResponseMessage('INVALID_API_TRAN_ID'),
			};
			const response = getResponseContent(responseData);
			await logger(JSON.stringify(request), JSON.stringify(response), 400);
			return NextResponse.json(response, { status: 400 });
		}

		if (!xApiType || (xApiType !== 'regular' && xApiType !== 'irregular')) {
			const responseData: ResponseData = {
				headers: {
					contentType: 'application/json;charset=UTF-8',
					xApiTranId: xApiTranId || '',
				},
				body: getResponseMessage('INVALID_PARAMETERS'),
			};
			const response = getResponseContent(responseData);
			await logger(JSON.stringify(request), JSON.stringify(response), 400);
			return NextResponse.json(response, { status: 400 });
		}

		const accounts = await prisma.account.findUnique({
			where: {
				accountNum: account_num as string,
			},
		});

		if (!accounts) {
			const responseData: ResponseData = {
				headers: {
					contentType: 'application/json;charset=UTF-8',
					xApiTranId: xApiTranId || '',
				},
				body: getResponseMessage('SUCCESS_WITH_NO_DATA'),
			};
			const response = getResponseContent(responseData);
			return NextResponse.json(response, { status: 200 });
		}
		const depositAccounts = await prisma.depositAccount.findMany({
			where: {
				accountNum: account_num as string,
			},
		});

		if (depositAccounts.length === 0) {
			const responseData: ResponseData = {
				headers: {
					contentType: 'application/json;charset=UTF-8',
					xApiTranId: xApiTranId || '',
				},
				body: getResponseMessage('SUCCESS_WITH_NO_DATA'),
			};
			const response = getResponseContent(responseData);
			return NextResponse.json(response, { status: 200 });
		}
		const detailList = depositAccounts.map((account) => {
			return {
				currency_code: account.currencyCode,
				balance_amt: account.balanceAmt,
				withdrawable_amt: account.withdrawableAmt,
				offered_rate: account.offeredRate,
				last_paid_in_cnt: account.lastPaidInCnt,
			};
		});

		const responseData: ResponseData = {
			headers: {
				contentType: 'application/json;charset=UTF-8',
				xApiTranId: xApiTranId || '',
			},
			body: {
				rsp_code: getResponseMessage('SUCCESS').code,
				rsp_msg: getResponseMessage('SUCCESS').message,
				search_timestamp: timestamp(new Date()),
				detail_cnt: detailList.length,
				detailList: detailList,
			},
		};

		await logger(JSON.stringify(request), JSON.stringify(responseData), 200);

		return NextResponse.json(responseData, { status: 200 });
	} catch (error) {
		const responseData: ResponseData = {
			headers: {
				contentType: 'application/json;charset=UTF-8',
				xApiTranId: xApiTranId || '',
			},
			body: getResponseMessage('INTERNAL_SERVER_ERROR'),
		};
		const response = getResponseContent(responseData);
		await logger(JSON.stringify(request), JSON.stringify(response), 400);
		return NextResponse.json(response, { status: 400 });
	}
}
