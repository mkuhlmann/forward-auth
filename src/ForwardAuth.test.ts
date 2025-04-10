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
	log_level: 4,
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
			} else if (url.pathname === '/.well-known/openid-configuration') {
				// OpenID Discovery document
				return new Response(
					JSON.stringify({
						issuer: 'http://127.0.0.1:8081',
						authorization_endpoint: 'http://127.0.0.1:8081/discovery-login',
						token_endpoint: 'http://127.0.0.1:8081/discovery-token',
						userinfo_endpoint: 'http://127.0.0.1:8081/discovery-userinfo',
						response_types_supported: ['code'],
						subject_types_supported: ['public'],
						id_token_signing_alg_values_supported: ['RS256'],
					}),
					{
						headers: { 'Content-Type': 'application/json' },
					}
				);
			} else if (url.pathname === '/discovery-login') {
				return new Response('/discovery-login');
			} else if (url.pathname === '/discovery-token') {
				return new Response(JSON.stringify({ access_token: currentUser }), {
					headers: { 'Content-Type': 'application/json' },
				});
			} else if (url.pathname === '/discovery-userinfo') {
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
		cookieJar = new TestCookieJar();
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

describe('OIDC Discovery functionality', () => {
	beforeEach(() => {
		cookieJar = new TestCookieJar();
	});

	test('should fetch and use discovery document endpoints', async () => {
		// Request with discovery_url param pointing to our mock server
		const response = await testFetch('http://127.0.0.1:8080/auth?discovery_url=http://127.0.0.1:8081', {
			headers: {
				'x-forwarded-proto': 'http',
				'x-forwarded-host': 'app',
				'x-forwarded-uri': '/redirect/to/here',
			},
		});

		// Verify the authorization endpoint from discovery is used
		const locationHeader = response.headers.get('location') || '';
		expect(locationHeader.startsWith('http://127.0.0.1:8081/discovery-login')).toBe(true);
	});

	test('should use explicit URLs over discovery document values', async () => {
		// Request with both discovery_url and explicit authorize_url
		const response = await testFetch('http://127.0.0.1:8080/auth?discovery_url=http://127.0.0.1:8081&authorize_url=http://explicit-override.example.com/authorize', {
			headers: {
				'x-forwarded-proto': 'http',
				'x-forwarded-host': 'app',
				'x-forwarded-uri': '/redirect/to/here',
			},
		});

		// Verify the explicit authorization endpoint is used instead of the one from discovery
		const locationHeader = response.headers.get('location') || '';
		expect(locationHeader.startsWith('http://explicit-override.example.com/authorize')).toBe(true);
	});

	test('should complete full OAuth flow with discovery document', async () => {
		// 1. Initial auth request with discovery URL
		const authResponse = await testFetch('http://127.0.0.1:8080/auth?discovery_url=http://127.0.0.1:8081', {
			headers: {
				'x-forwarded-proto': 'http',
				'x-forwarded-host': 'app',
				'x-forwarded-uri': '/protected-page',
			},
		});

		// 2. Extract the state parameter from the redirect URL
		const locationHeader = authResponse.headers.get('location') || '';
		const stateMatch = locationHeader.match(/state=([\w_-]+)/i);
		const oauthState = stateMatch?.[1] || '';
		expect(oauthState).toBeTruthy();

		// 3. Simulate OAuth callback
		currentUser = 'testOkUser'; // Ensure user is allowed
		const callbackResponse = await testFetch('http://127.0.0.1:8080/auth', {
			headers: {
				'x-forwarded-proto': 'http',
				'x-forwarded-host': '127.0.0.1:8080',
				'x-forwarded-uri': `/_auth/callback?code=test-code&state=${oauthState}`,
			},
		});

		// 4. Verify successful redirect back to original page
		expect(callbackResponse.status).toBe(302);
		expect(callbackResponse.headers.get('location')).toBe('http://app/protected-page');

		// 5. Verify subsequent auth checks succeed
		const subsequentResponse = await testFetch('http://127.0.0.1:8080/auth', {
			redirect: 'manual',
		});
		expect(subsequentResponse.status).toBe(200);
	});

	test('should handle non-existent discovery endpoint gracefully', async () => {
		// Request with discovery_url param pointing to a non-existent endpoint
		const response = await testFetch('http://127.0.0.1:8080/auth?discovery_url=http://non-existent.example.com', {
			headers: {
				'x-forwarded-proto': 'http',
				'x-forwarded-host': 'app',
				'x-forwarded-uri': '/redirect/to/here',
			},
		});

		// Should fall back to default endpoints
		const locationHeader = response.headers.get('location') || '';
		expect(locationHeader.startsWith('http://127.0.0.1:8081/login')).toBe(true);
	});

	test('should handle discovery document without required endpoints', async () => {
		// Create a temporary server with incomplete discovery document
		const incompleteServer = Bun.serve({
			port: 8082,
			hostname: '127.0.0.1',
			fetch(req) {
				const url = new URL(req.url);
				if (url.pathname === '/.well-known/openid-configuration') {
					// Missing endpoints
					return new Response(
						JSON.stringify({
							issuer: 'http://127.0.0.1:8082',
							// No authorization_endpoint
							token_endpoint: 'http://127.0.0.1:8082/token',
							// No userinfo_endpoint
						}),
						{
							headers: { 'Content-Type': 'application/json' },
						}
					);
				}
				return new Response('Not Found', { status: 404 });
			},
		});

		try {
			// Request with discovery_url pointing to incomplete discovery document
			const response = await testFetch('http://127.0.0.1:8080/auth?discovery_url=http://127.0.0.1:8082', {
				headers: {
					'x-forwarded-proto': 'http',
					'x-forwarded-host': 'app',
					'x-forwarded-uri': '/redirect/to/here',
				},
			});

			// Should fall back to default endpoints where discovery is incomplete
			const locationHeader = response.headers.get('location') || '';
			expect(locationHeader.startsWith('http://127.0.0.1:8081/login')).toBe(true);
		} finally {
			incompleteServer.stop();
		}
	});
});
