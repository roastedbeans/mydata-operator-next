'use client';

import { getSupport002 } from '@/app/_hooks/getSupport';
import { Button } from '@heroui/button';
import { Card, CardBody, CardFooter } from '@heroui/card';
import React from 'react';
import { Organization } from '@/types/data-types';
import { Checkbox } from '@heroui/checkbox';

const CertifySection = () => {
	const [orgs, setOrgs] = React.useState<Organization[]>([]);
	const [selectedOrgs, setSelectedOrgs] = React.useState<string[]>([]);

	const handleGetToken = async () => {
		const data = await getSupport002();

		if (!data) return;

		const orgs = data?.org_list.filter((org: Organization) => org.orgCode !== process.env.NEXT_PUBLIC_ORG_CODE);
		setOrgs(orgs);
	};

	console.log('orgs:', selectedOrgs);

	return (
		<div className='flex h-screen items-start justify-start flex-col gap-8 p-16'>
			<Button onPress={handleGetToken}>Get Orgs</Button>
			<h2 className='font-semibold'>Available Banks</h2>
			<Card className='max-w-3xl w-full min-h-72 justify-start items-start'>
				<CardBody className='flex gap-4'>
					{orgs?.map((org) => (
						<Checkbox
							onChange={() =>
								setSelectedOrgs((prev) =>
									prev.includes(org?.id) ? prev.filter((id) => id !== org?.id) : [...prev, org?.id]
								)
							}
							checked={selectedOrgs.includes(org?.id)}
							key={org?.id}
							className='w-fit'>
							{org?.name}
						</Checkbox>
					))}
				</CardBody>
				<CardFooter className='flex justify-center'>
					<Button
						disableRipple
						disabled={selectedOrgs.length === 0}
						color={selectedOrgs.length === 0 ? 'default' : 'primary'}>
						Connect
					</Button>
				</CardFooter>
			</Card>
		</div>
	);
};

export default CertifySection;
