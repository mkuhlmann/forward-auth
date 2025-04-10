import { createHmac } from 'crypto';

export class CookieJar {
	private key: string;

	constructor(key: string) {
		this.key = key;
	}

	sign(value: string): string {
		return createHmac('sha256', this.key).update(value).digest('base64url');
	}

	verify(value: string, signature: string): boolean {
		return this.sign(value) === signature;
	}
}
