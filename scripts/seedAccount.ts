import { PrismaClient } from '@prisma/client';
import { faker } from '@faker-js/faker';

const prisma = new PrismaClient();

async function main() {
	const accounts = [];
	const depositAccounts = [];

	// Helper function to generate dates within a reasonable range
	const generateDate = () =>
		faker.date.between({
			from: '2023-01-01',
			to: '2025-01-20',
		});

	for (let i = 0; i < 500; i++) {
		const accountNum = faker.string.numeric(10); // Generate 10-digit account number
		const account = {
			account_num: accountNum,
			org_code: faker.helpers.arrayElement(['ORG2025001', 'ORG2025002']),
			account_type: faker.helpers.arrayElement(['TYPE_1001']), // Deposit Account
			account_status: faker.helpers.arrayElement(['STATUS_01', 'STATUS_02', 'STATUS_03']),
			prod_name: faker.helpers.arrayElement([
				'Personal Savings Account',
				'Personal Checking Account',
				'Youth Housing',
				'Dream Subscription',
				'Future Savings',
				'Professional Savings',
			]),
			is_consent: faker.datatype.boolean(),
			is_minus: faker.datatype.boolean(),
			is_foreign_deposit: faker.datatype.boolean(),
			created_at: generateDate(),
			updated_at: generateDate(),
		};
		accounts.push(account);

		const balance = faker.number.float({ min: 3000, max: 1000000, fractionDigits: 3 });
		const withdrawable = faker.number.float({ min: balance - 3000, max: balance, fractionDigits: 3 });

		// Creating DepositAccount for TYPE_1001
		if (account.account_type === 'TYPE_1001') {
			const depositAccount = {
				deposit_id: faker.string.uuid(),
				account_num: account.account_num,
				exp_date: faker.date.future(),
				commit_amt: faker.number.float({ min: 50000, max: 1000000, fractionDigits: 3 }),
				issue_date: generateDate(),
				currency_code: faker.helpers.arrayElement(['KRW', 'USD', 'PHP']),
				saving_method: faker.helpers.arrayElement(['METHOD_01', 'METHOD_02', 'METHOD_03']),
				monthly_paid_in_amt: faker.number.float({ min: 100, max: 5000, fractionDigits: 3 }),
				balance_amt: balance,
				withdrawable_amt: withdrawable,
				offered_rate: faker.number.float({ min: 0.01, max: 0.05, fractionDigits: 3 }),
				last_paid_in_cnt: faker.number.int({ min: 0, max: 12 }),
			};
			depositAccounts.push(depositAccount);
		}
	}

	// Batch insert all records
	await prisma.account.createMany({
		data: accounts,
	});

	await prisma.depositAccount.createMany({
		data: depositAccounts,
	});

	console.log('Seeding completed successfully');
}

main()
	.catch((e) => {
		console.error(e);
		process.exit(1);
	})
	.finally(async () => {
		await prisma.$disconnect();
	});
