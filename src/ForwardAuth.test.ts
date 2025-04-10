import { describe, expect, beforeAll, afterAll, test, beforeEach } from 'bun:test';
import { Server } from 'bun';
import { runForwardAuth } from './ForwardAuth';

// Test configuration
const config = {
	listen_host: '0.0.0.0',
	listen_port: 8080,
	redirect_code: 302,
	app_key: 'THIS_SHOULD_BE_CHANGED',
	authorize_url: 'http://127.0.0.1:8081/login',
	token_url: 'http://127.0.0.1:8081/token',
	userinfo_url: 'http://127.0.0.1:8081/userinfo',
	client_id: 'clientId',
	client_secret: 'clientSecret',
	allowed_users: 'testOkUser',
	scopes: 'test',
	cookie_name: '__auth',
	cookie_age: 604800,
};

// Initialize the forward auth service
const forwardAuthService = runForwardAuth(config);

// Cookie storage for tests
class TestCookieJar {
	cookies: Map<string, string> = new Map();

	setCookie(cookieStr: string, domain: string) {
		const cookie = cookieStr.split(';')[0];
		const [name, value] = cookie.split('=');
		this.cookies.set(name, value);
	}

	getCookieHeader(): string {
		return Array.from(this.cookies.entries())
			.map(([name, value]) => `${name}=${value}`)
			.join('; ');
	}
}

// Create cookie jar for tests
let cookieJar = new TestCookieJar();

// Custom fetch function that handles cookies
const testFetch = async (url: string, options: RequestInit = {}): Promise<Response> => {
	if (!options.headers) {
		options.headers = {};
	}

	// Add cookies to request
	const cookieHeader = cookieJar.getCookieHeader();
	if (cookieHeader) {
		options.headers = {
			...options.headers,
			Cookie: cookieHeader,
		};
	}

	// Default to not following redirects
	if (!('redirect' in options)) {
		options.redirect = 'manual';
	}

	// Perform the fetch
	const response = await fetch(url, options);

	// Store any cookies from the response
	const setCookieHeader = response.headers.get('Set-Cookie');
	if (setCookieHeader) {
		// Simple parsing, in a real app would need more robust handling
		cookieJar.setCookie(setCookieHeader, new URL(url).hostname);
	}

	return response;
};

// Mock OAuth server state
let currentUser = 'testOkUser';
let mockOAuthServer: Server;

// Setup mock OAuth server
beforeAll(() => {
	mockOAuthServer = Bun.serve({
		port: 8081,
		hostname: '127.0.0.1',
		fetch(req) {
			const url = new URL(req.url);

			if (url.pathname === '/login') {
				return new Response('/login');
			} else if (url.pathname === '/token') {
				return new Response(JSON.stringify({ access_token: currentUser }), {
					headers: { 'Content-Type': 'application/json' },
				});
			} else if (url.pathname === '/userinfo') {
				const authHeader = req.headers.get('authorization') || '';
				const token = authHeader.split(' ')[1];
				return new Response(JSON.stringify({ name: 'Test User', sub: currentUser }), {
					headers: { 'Content-Type': 'application/json' },
				});
			}

			return new Response('Not Found', { status: 404 });
		},
	});
});

afterAll(() => {
	// Clean up servers
	mockOAuthServer.stop();
	forwardAuthService.server.stop();
});

describe('Unauthenticated user', () => {
	let response: Response;

	beforeAll(async () => {
		response = await testFetch('http://127.0.0.1:8080/auth', {
			headers: {
				'x-forwarded-proto': 'http',
				'x-forwarded-host': 'app',
				'x-forwarded-uri': '/redirect/to/here',
			},
		});
	});

	test('should be redirected to OAuth login', () => {
		expect(response.headers.get('location')?.startsWith('http://127.0.0.1:8081/login')).toBe(true);
	});

	test('should be a 302 redirection', () => {
		expect(response.status).toBe(302);
	});

	test('can have custom redirect code', async () => {
		response = await testFetch('http://127.0.0.1:8080/auth?redirect_code=403', {
			headers: {
				'x-forwarded-proto': 'http',
				'x-forwarded-host': 'app',
				'x-forwarded-uri': '/redirect/to/here',
			},
		});

		expect(response.status).toBe(403);
	});

	test('redirected URL includes state parameter', () => {
		const locationHeader = response.headers.get('location') || '';
		const match = locationHeader.match(/state=([\w_-]+)$/i);
		expect(match?.length).toBe(2);
		expect(match?.[1] || '').toBeTruthy();
	});
});

describe('valid user calling OAuth callback', () => {
	test('should not be accepted with invalid state', async () => {
		const response = await testFetch('http://127.0.0.1:8080/auth', {
			headers: {
				'x-forwarded-proto': 'http',
				'x-forwarded-host': '127.0.0.1:8080',
				'x-forwarded-uri': '/_auth/callback?code=test&state=invalid',
			},
		});

		const text = await response.text();
		expect(text).toBe('invalid state');
	});

	test('should be redirected to intended destination', async () => {
		const _response = await testFetch('http://127.0.0.1:8080/auth', {
			headers: {
				'x-forwarded-proto': 'http',
				'x-forwarded-host': 'app',
				'x-forwarded-uri': '/redirect/to/here',
			},
		});

		const locationHeader = _response.headers.get('location') || '';
		const match = locationHeader.match(/state=([\w_-]+)$/i);
		const oauthState = match?.[1] || '';

		const response = await testFetch('http://127.0.0.1:8080/auth', {
			headers: {
				'x-forwarded-proto': 'http',
				'x-forwarded-host': '127.0.0.1:8080',
				'x-forwarded-uri': `/_auth/callback?code=test&state=${oauthState}`,
			},
		});

		expect(response.headers.get('location')).toBe('http://app/redirect/to/here');
	});

	test('should be accepted on subsequent requests', async () => {
		const response = await testFetch('http://127.0.0.1:8080/auth', {
			redirect: 'manual',
		});
		expect(response.status).toBe(200);
	});
});

describe('Invalid user calling OAuth callback', () => {
	test('should be declined', async () => {
		const _response = await testFetch('http://127.0.0.1:8080/auth', {
			headers: {
				'x-forwarded-proto': 'http',
				'x-forwarded-host': 'app',
				'x-forwarded-uri': '/redirect/to/here',
			},
		});

		const locationHeader = _response.headers.get('location') || '';
		const match = locationHeader.match(/state=([\w_-]+)$/i);
		const oauthState = match?.[1] || '';

		currentUser = 'testFailUser';

		const response = await testFetch('http://127.0.0.1:8080/auth', {
			headers: {
				'x-forwarded-proto': 'http',
				'x-forwarded-host': '127.0.0.1:8080',
				'x-forwarded-uri': `/_auth/callback?code=test&state=${oauthState}`,
			},
		});

		expect(response.status).toBe(401);
	});
});
