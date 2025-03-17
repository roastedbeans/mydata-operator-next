import { Link } from '@heroui/link';
import {
	Navbar,
	NavbarBrand,
	NavbarContent,
	NavbarItem,
	NavbarMenuToggle,
	NavbarMenu,
	NavbarMenuItem,
} from '@heroui/navbar';

export default function NavbarMain() {
	const bankName = process.env.NEXT_PUBLIC_BOND_ORG_NAME;

	return (
		<Navbar>
			<NavbarBrand>
				<p className='font-bold text-inherit'>{bankName}</p>
			</NavbarBrand>
			<NavbarContent
				className='hidden sm:flex gap-4'
				justify='center'>
				<NavbarItem>
					<Link
						underline='always'
						color='foreground'
						href='/account/mydata'>
						Mydata
					</Link>
				</NavbarItem>
			</NavbarContent>
			<NavbarContent justify='end'></NavbarContent>
		</Navbar>
	);
}
