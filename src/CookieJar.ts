import { createHmac, timingSafeEqual } from 'crypto';

export class CookieJar {
	private key: string;

	constructor(key: string) {
		this.key = key;
	}

	sign(value: string): string {
		return createHmac('sha256', this.key).update(value).digest('base64url');
	}

	verify(value: string, signature: string): boolean {
		try {
			const correctSignature = this.sign(value);
			const a = Buffer.from(correctSignature, 'base64url');
			const b = Buffer.from(signature, 'base64url');
			// Use timingSafeEqual to prevent timing attacks
			return a.length === b.length && timingSafeEqual(a, b);
		} catch {
			return false;
		}
	}
}
