import { PrismaClient } from '@prisma/client';
import { faker } from '@faker-js/faker';

const prisma = new PrismaClient();

async function main() {
	// Create at least one bank (Organization)
	// const orgCode = faker.string.alphanumeric(10); // Generate a unique org_code
	// const name = faker.company.name(); // Generate a random bank name
	// const opType = faker.helpers.arrayElement(['I', 'M', 'D']); // I - New, M - Modify, D - Delete
	// const orgType = faker.helpers.arrayElement(['01', '03', '05']); // 01 - Information Provider, 03 - Business Operator, 05 - Integrated Cert Agency
	// const authType = faker.helpers.arrayElement(['01', '02']); // 01 - Integrated Auth, 02 - Integrated Auth / Individual Auth
	// const industry = faker.helpers.arrayElement(['bank', 'card', 'invest', 'insu']); // e.g. bank, card, invest, insu
	// const serialNum = faker.helpers.arrayElement(['BOAB20240201', 'BOBB20240202']); // Add serialNum as required by the schema

	try {
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
			const firstName = faker.person.firstName();
			const lastName = faker.person.lastName();
			const pinCode = faker.string.numeric(6);

			const account = {
				accountNum: accountNum,
				firstName: firstName,
				lastName: lastName,
				phoneNumber: '+8210' + faker.string.numeric(8),
				pinCode: pinCode,
				orgCode: faker.helpers.arrayElement(['ORG2025001', 'ORG2025002']), // Use the org_code generated above
				accountType: faker.helpers.arrayElement(['TYPE_1001']), // Deposit Account
				accountStatus: faker.helpers.arrayElement(['STATUS_01', 'STATUS_02', 'STATUS_03']),
				prodName: faker.helpers.arrayElement([
					'Personal Savings Account',
					'Personal Checking Account',
					'Youth Housing',
					'Dream Subscription',
					'Future Savings',
					'Professional Savings',
				]),
				isConsent: faker.datatype.boolean(),
				isMinus: faker.datatype.boolean(),
				isForeignDeposit: faker.datatype.boolean(),
				createdAt: generateDate(),
				updatedAt: generateDate(),
			};
			accounts.push(account);

			const balance = faker.number.float({ min: 3000, max: 1000000, fractionDigits: 3 });
			const withdrawable = faker.number.float({ min: balance - 3000, max: balance, fractionDigits: 3 });

			// Creating DepositAccount for TYPE_1001
			if (account.accountType === 'TYPE_1001') {
				const depositAccount = {
					depositId: faker.string.uuid(),
					accountNum: account.accountNum,
					expDate: faker.date.future(),
					commitAmt: faker.number.float({ min: 50000, max: 1000000, fractionDigits: 3 }),
					issueDate: generateDate(),
					currencyCode: faker.helpers.arrayElement(['KRW', 'USD', 'PHP']),
					savingMethod: faker.helpers.arrayElement(['METHOD_01', 'METHOD_02', 'METHOD_03']),
					monthlyPaidInAmt: faker.number.float({ min: 100, max: 5000, fractionDigits: 3 }),
					balanceAmt: balance,
					withdrawableAmt: withdrawable,
					offeredRate: faker.number.float({ min: 0.01, max: 0.05, fractionDigits: 3 }),
					lastPaidInCnt: faker.number.int({ min: 0, max: 12 }),
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
	} catch (error) {
		console.error('Error in seeding:', error);
	}
}

main()
	.catch((e) => {
		console.error(e);
		process.exit(1);
	})
	.finally(async () => {
		await prisma.$disconnect();
	});
