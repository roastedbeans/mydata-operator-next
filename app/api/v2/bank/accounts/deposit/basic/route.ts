import { NextRequest, NextResponse } from 'next/server';
import { PrismaClient } from '@prisma/client';
import { getResponseMessage } from '@/constants/responseMessages';
import jwt from 'jsonwebtoken';
import { initializeCsv, logRequestToCsv } from '@/utils/generateCSV';

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secure-secret';

export async function POST(req: NextRequest) {
	await initializeCsv();

	try {
		const headers = req.headers;
		const authorization = headers.get('Authorization');
		const xApiTranId = headers.get('x-api-tran-id'); // e.g. 1234567890123456789012345
		const xApiType = headers.get('x-api-type'); // e.g. regular / irregular

		if (!authorization || !authorization.startsWith('Bearer ')) {
			await logRequestToCsv('bank.deposit', JSON.stringify(getResponseMessage('UNAUTHORIZED')));
			return NextResponse.json(getResponseMessage('UNAUTHORIZED'), { status: 401 });
		}

		// Extract the token
		const token = authorization.split(' ')[1];
		let decodedToken;

		try {
			decodedToken = jwt.verify(token, JWT_SECRET);
		} catch (error) {
			await logRequestToCsv('bank.deposit', JSON.stringify(getResponseMessage('INVALID_TOKEN')));
			return NextResponse.json(getResponseMessage('INVALID_TOKEN'), { status: 403 });
		}

		// Validate x-api-tran-id
		if (!xApiTranId || xApiTranId.length > 25) {
			await logRequestToCsv('bank.deposit', JSON.stringify(getResponseMessage('INVALID_API_TRAN_ID')));
			return NextResponse.json(getResponseMessage('INVALID_API_TRAN_ID'), { status: 400 });
		}

		if (!xApiType || (xApiType !== 'regular' && xApiType !== 'irregular')) {
			await logRequestToCsv('bank.deposit', JSON.stringify(getResponseMessage('INVALID_API_TYPE')));
			return NextResponse.json(getResponseMessage('INVALID_API_TYPE'), { status: 400 });
		}

		// Validate request body
		const body = await req.json();
		const { org_code, account_num, next, search_timestamp } = body;

		console.log('next: ', next);
		console.log('search_timestamp: ', search_timestamp);
		console.log('org_code: ', org_code);
		console.log('account_num: ', account_num);

		const accounts = await prisma.account.findUnique({
			where: {
				accountNum: account_num as string,
			},
		});

		if (!accounts) {
			await logRequestToCsv('bank.deposit', JSON.stringify(getResponseMessage('SUCCESS_WITH_NO_DATA')));
			return NextResponse.json(getResponseMessage('SUCCESS_WITH_NO_DATA'), { status: 200 });
		}

		const depositAccounts = await prisma.depositAccount.findMany({
			where: {
				accountNum: account_num as string,
			},
		});

		if (depositAccounts.length === 0) {
			await logRequestToCsv('bank.deposit', JSON.stringify(getResponseMessage('SUCCESS_WITH_NO_DATA')));
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

		await logRequestToCsv('bank.deposit', JSON.stringify(responseData));

		return NextResponse.json(responseData, { status: 200 });
	} catch (error) {
		await logRequestToCsv('bank.deposit', JSON.stringify(getResponseMessage('INTERNAL_SERVER_ERROR')));
		return NextResponse.json(getResponseMessage('INTERNAL_SERVER_ERROR'), { status: 400 });
	}
}
