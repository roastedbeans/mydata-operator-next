export const generateTIN = (prefix: string) => {
	const date = new Date();

	const timestamp = date
		.toISOString()
		.replace(/[-:.TZ]/g, '')
		.slice(0, 14); // YYYYMMDDHHMMSS

	return prefix + timestamp;
};
