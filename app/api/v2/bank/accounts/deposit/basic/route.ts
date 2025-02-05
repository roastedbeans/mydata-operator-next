import { NextRequest, NextResponse } from 'next/server';
import { PrismaClient } from '@prisma/client';
import { getResponseMessage } from '@/constants/responseMessages';
import jwt from 'jsonwebtoken';
import { logger } from '@/utils/generateCSV';

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
	};

	try {
		if (!authorization?.startsWith('Bearer ')) {
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('UNAUTHORIZED')),
				'401'
			);
			return NextResponse.json(getResponseMessage('UNAUTHORIZED'), { status: 401 });
		}

		// Extract the token
		const token = authorization.split(' ')[1];
		let decodedToken;

		try {
			decodedToken = jwt.verify(token, JWT_SECRET);
		} catch (error) {
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('INVALID_TOKEN')),
				'403'
			);
			return NextResponse.json(getResponseMessage('INVALID_TOKEN'), { status: 403 });
		}

		// Validate x-api-tran-id
		if (!xApiTranId || xApiTranId.length > 25) {
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('INVALID_API_TRAN_ID')),
				'400'
			);
			return NextResponse.json(getResponseMessage('INVALID_API_TRAN_ID'), { status: 400 });
		}

		if (!xApiType || (xApiType !== 'regular' && xApiType !== 'irregular')) {
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('INVALID_API_TYPE')),
				'400'
			);
			return NextResponse.json(getResponseMessage('INVALID_API_TYPE'), { status: 400 });
		}

		const accounts = await prisma.account.findUnique({
			where: {
				accountNum: account_num as string,
			},
		});

		if (!accounts) {
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('SUCCESS_WITH_NO_DATA')),
				'200'
			);
			return NextResponse.json(getResponseMessage('SUCCESS_WITH_NO_DATA'), { status: 200 });
		}

		const depositAccounts = await prisma.depositAccount.findMany({
			where: {
				accountNum: account_num as string,
			},
		});

		if (depositAccounts.length === 0) {
			await logger(
				JSON.stringify(request),
				JSON.stringify(body),
				JSON.stringify(getResponseMessage('SUCCESS_WITH_NO_DATA')),
				'200'
			);
			return NextResponse.json(getResponseMessage('SUCCESS_WITH_NO_DATA'), { status: 200 });
		}

		const basicList = depositAccounts.map((account) => {
			return {
				currency_code: account.currencyCode,
				saving_method: account.savingMethod,
				issue_date: account.issueDate,
				exp_date: account.expDate,
				commit_amt: account.commitAmt,
				monthly_paid_in_amt: account.monthlyPaidInAmt,
			};
		});

		const timestamp = new Date().toISOString();
		const responseData = {
			rsp_code: getResponseMessage('SUCCESS').code,
			rsp_msg: getResponseMessage('SUCCESS').message,
			search_timestamp: timestamp,
			basic_cnt: basicList.length,
			basicList: basicList,
		};

		await logger(JSON.stringify(request), JSON.stringify(body), JSON.stringify(responseData), '200');

		return NextResponse.json(responseData, { status: 200 });
	} catch (error) {
		await logger(JSON.stringify(request), JSON.stringify(body), JSON.stringify(error), '400');
		return NextResponse.json(getResponseMessage('INTERNAL_SERVER_ERROR'), { status: 400 });
	}
}
