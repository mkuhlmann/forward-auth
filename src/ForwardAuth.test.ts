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
	callback_centralised: true,
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

	// Requests arrive via the reverse proxy, which always sets the forwarded headers
	options.headers = {
		'x-forwarded-proto': 'http',
		'x-forwarded-host': 'app',
		...options.headers,
	};

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
let currentName = 'Test User';
let mockOAuthServer: Server<unknown>;

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
				return new Response(JSON.stringify({ name: currentName, sub: currentUser }), {
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
				return new Response(JSON.stringify({ name: currentName, sub: currentUser }), {
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
				'x-forwarded-host': 'app',
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
				'x-forwarded-host': 'app',
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
				'x-forwarded-host': 'app',
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
				'x-forwarded-host': 'app',
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

describe('Centralized callback mode', () => {
	// Separate forward-auth instance with centralized callback enabled.
	// Primary auth on 8084, callback server on 8083.
	// cookie_insecure=true so http:// origins are accepted in the state.
	const centralConfig = {
		listen_host: '127.0.0.1',
		listen_port: 8084,
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
		cookie_insecure: true,
		callback_port: 8083,
		callback_url: 'http://127.0.0.1:8083/callback',
		callback_centralised: true,
		callback_allowed_domains: '127.0.0.1',
		log_level: 4,
	};

	const centralService = runForwardAuth(centralConfig);
	let centralCookieJar = new TestCookieJar();

	const centralFetch = async (url: string, options: RequestInit = {}): Promise<Response> => {
		if (!options.headers) options.headers = {};
		const cookieHeader = centralCookieJar.getCookieHeader();
		if (cookieHeader) {
			options.headers = { ...options.headers, Cookie: cookieHeader };
		}
		if (!('redirect' in options)) options.redirect = 'manual';
		const response = await fetch(url, options);
		const setCookieHeader = response.headers.get('Set-Cookie');
		if (setCookieHeader) {
			centralCookieJar.setCookie(setCookieHeader, new URL(url).hostname);
		}
		return response;
	};

	afterAll(() => {
		centralService.server.stop();
		centralService.callbackServer?.stop();
	});

	beforeEach(() => {
		centralCookieJar = new TestCookieJar();
		currentUser = 'testOkUser';
	});

	test('OAuth state parameter is a signed token (not a plain UUID)', async () => {
		const response = await centralFetch('http://127.0.0.1:8084/auth', {
			headers: {
				'x-forwarded-proto': 'http',
				'x-forwarded-host': '127.0.0.1:8084',
				'x-forwarded-uri': '/protected',
			},
		});

		expect(response.status).toBe(302);
		const location = response.headers.get('location') || '';
		expect(location.startsWith('http://127.0.0.1:8081/login')).toBe(true);

		// State should be a signed token: base64url.signature (contains a dot)
		const stateMatch = location.match(/[?&]state=([^&]+)/);
		const stateParam = stateMatch ? decodeURIComponent(stateMatch[1]) : '';
		expect(stateParam).toContain('.');
	});

	test('callback server returns 400 when code or state is missing', async () => {
		const noCode = await fetch('http://127.0.0.1:8083/callback?state=something', { redirect: 'manual' });
		expect(noCode.status).toBe(400);

		const noState = await fetch('http://127.0.0.1:8083/callback?code=something', { redirect: 'manual' });
		expect(noState.status).toBe(400);
	});

	test('callback server returns 400 for tampered state', async () => {
		const response = await fetch('http://127.0.0.1:8083/callback?code=test&state=tampered.signature', { redirect: 'manual' });
		expect(response.status).toBe(400);
		expect(await response.text()).toBe('invalid state');
	});

	test('primary server returns 400 for tampered handoff token', async () => {
		// First get a valid session cookie with a state nonce
		const authResponse = await centralFetch('http://127.0.0.1:8084/auth', {
			headers: {
				'x-forwarded-proto': 'http',
				'x-forwarded-host': '127.0.0.1:8084',
				'x-forwarded-uri': '/protected',
			},
		});
		expect(authResponse.status).toBe(302);

		// Submit a tampered handoff token
		const response = await centralFetch('http://127.0.0.1:8084/auth', {
			headers: {
				'x-forwarded-proto': 'http',
				'x-forwarded-host': '127.0.0.1:8084',
				'x-forwarded-uri': '/_auth/callback?handoff=tampered.signature',
			},
		});
		expect(response.status).toBe(400);
		expect(await response.text()).toBe('invalid handoff token');
	});

	test('primary server returns 400 when handoff UUID does not match session state (CSRF)', async () => {
		// Get a session cookie for one auth attempt (which stores a uuid as state)
		const authResponse = await centralFetch('http://127.0.0.1:8084/auth', {
			headers: {
				'x-forwarded-proto': 'http',
				'x-forwarded-host': '127.0.0.1:8084',
				'x-forwarded-uri': '/protected',
			},
		});
		expect(authResponse.status).toBe(302);

		// Simulate the callback server producing a handoff for a DIFFERENT uuid
		// We do this by hitting the callback with a valid-looking but wrong state.
		// Since we can't forge a signed state, let's use a fresh auth attempt's state
		// from a separate cookie jar and try to use it with the original session.
		const otherJar = new TestCookieJar();
		const otherAuth = await fetch('http://127.0.0.1:8084/auth', {
			redirect: 'manual',
			headers: {
				'x-forwarded-proto': 'http',
				'x-forwarded-host': '127.0.0.1:8084',
				'x-forwarded-uri': '/protected',
			},
		});
		const otherState = otherAuth.headers.get('location')?.match(/[?&]state=([^&]+)/)?.[1] || '';
		const decodedOtherState = decodeURIComponent(otherState);
		const otherSetCookie = otherAuth.headers.get('Set-Cookie') || '';
		otherJar.setCookie(otherSetCookie, '127.0.0.1');

		// Process this other state through the callback server
		const cbResponse = await fetch(`http://127.0.0.1:8083/callback?code=test&state=${encodeURIComponent(decodedOtherState)}`, { redirect: 'manual' });
		expect(cbResponse.status).toBe(302);
		const handoffUrl = cbResponse.headers.get('location') || '';
		const handoffParam = handoffUrl.match(/[?&]handoff=([^&]+)/)?.[1] || '';

		// Now try to use that handoff with the ORIGINAL session cookie (different uuid → CSRF failure)
		const response = await centralFetch('http://127.0.0.1:8084/auth', {
			headers: {
				'x-forwarded-proto': 'http',
				'x-forwarded-host': '127.0.0.1:8084',
				'x-forwarded-uri': `/_auth/callback?handoff=${handoffParam}`,
			},
		});
		expect(response.status).toBe(400);
		expect(await response.text()).toBe('invalid state');
	});

	test('full happy-path: auth → callback server → handoff → session set', async () => {
		// Step 1: Initial auth request
		const authResponse = await centralFetch('http://127.0.0.1:8084/auth', {
			headers: {
				'x-forwarded-proto': 'http',
				'x-forwarded-host': '127.0.0.1:8084',
				'x-forwarded-uri': '/my-protected-page',
			},
		});
		expect(authResponse.status).toBe(302);
		const oauthRedirect = authResponse.headers.get('location') || '';
		expect(oauthRedirect).toContain('redirect_uri=http%3A%2F%2F127.0.0.1%3A8083%2Fcallback');

		// Step 2: Extract state and simulate OAuth provider redirecting to callback server
		const stateMatch = oauthRedirect.match(/[?&]state=([^&]+)/);
		const stateParam = stateMatch?.[1] || '';
		expect(stateParam).toBeTruthy();

		// Step 3: Hit the callback server (simulating the browser following the OAuth redirect)
		const cbResponse = await fetch(
			`http://127.0.0.1:8083/callback?code=test&state=${stateParam}`,
			{ redirect: 'manual' },
		);
		expect(cbResponse.status).toBe(302);
		const handoffRedirect = cbResponse.headers.get('location') || '';
		// Should redirect back to the originating service's /_auth/callback
		expect(handoffRedirect).toContain('127.0.0.1:8084/_auth/callback?handoff=');

		// Step 4: The reverse proxy forwards /_auth/callback to the primary server
		const handoffParam = handoffRedirect.match(/[?&]handoff=([^&]+)/)?.[1] || '';
		const finalResponse = await centralFetch('http://127.0.0.1:8084/auth', {
			headers: {
				'x-forwarded-proto': 'http',
				'x-forwarded-host': '127.0.0.1:8084',
				'x-forwarded-uri': `/_auth/callback?handoff=${handoffParam}`,
			},
		});
		expect(finalResponse.status).toBe(302);
		expect(finalResponse.headers.get('location')).toBe('http://127.0.0.1:8084/my-protected-page');

		// Step 5: Subsequent request should be authenticated
		const subsequentResponse = await centralFetch('http://127.0.0.1:8084/auth', { redirect: 'manual' });
		expect(subsequentResponse.status).toBe(200);
	});

	test('disallowed user is rejected at primary server during handoff', async () => {
		// Step 1: auth → get signed state
		const authResponse = await centralFetch('http://127.0.0.1:8084/auth', {
			headers: {
				'x-forwarded-proto': 'http',
				'x-forwarded-host': '127.0.0.1:8084',
				'x-forwarded-uri': '/protected',
			},
		});
		const stateParam = authResponse.headers.get('location')?.match(/[?&]state=([^&]+)/)?.[1] || '';

		// Step 2: callback server processes with a disallowed user
		currentUser = 'testFailUser';
		const cbResponse = await fetch(
			`http://127.0.0.1:8083/callback?code=test&state=${stateParam}`,
			{ redirect: 'manual' },
		);
		expect(cbResponse.status).toBe(302);
		const handoffParam = cbResponse.headers.get('location')?.match(/[?&]handoff=([^&]+)/)?.[1] || '';

		// Step 3: primary server rejects the disallowed user
		const finalResponse = await centralFetch('http://127.0.0.1:8084/auth', {
			headers: {
				'x-forwarded-proto': 'http',
				'x-forwarded-host': '127.0.0.1:8084',
				'x-forwarded-uri': `/_auth/callback?handoff=${handoffParam}`,
			},
		});
		expect(finalResponse.status).toBe(401);
	});

	const centralState = async (host: string) => {
		const authResponse = await centralFetch('http://127.0.0.1:8084/auth', {
			headers: { 'x-forwarded-proto': 'http', 'x-forwarded-host': host, 'x-forwarded-uri': '/protected' },
		});
		return authResponse.headers.get('location')?.match(/[?&]state=([^&]+)/)?.[1] || '';
	};

	test('callback server refuses to hand off to an origin outside CALLBACK_ALLOWED_DOMAINS', async () => {
		const stateParam = await centralState('evil.example');
		const cbResponse = await fetch(`http://127.0.0.1:8083/callback?code=test&state=${stateParam}`, { redirect: 'manual' });
		expect(cbResponse.status).toBe(400);
		expect(cbResponse.headers.get('location')).toBeNull();
	});

	test('handoff token cannot be used as a session cookie', async () => {
		const stateParam = await centralState('127.0.0.1:8084');
		const cbResponse = await fetch(`http://127.0.0.1:8083/callback?code=test&state=${stateParam}`, { redirect: 'manual' });
		const handoffParam = decodeURIComponent(cbResponse.headers.get('location')?.match(/[?&]handoff=([^&]+)/)?.[1] || '');
		expect(handoffParam).toBeTruthy();

		const response = await fetch('http://127.0.0.1:8084/auth', {
			redirect: 'manual',
			headers: { Cookie: `__auth=${handoffParam}`, 'x-forwarded-proto': 'http', 'x-forwarded-host': '127.0.0.1:8084' },
		});
		expect(response.status).toBe(302);
	});

	test('state token cannot be used as a handoff token', async () => {
		const stateParam = decodeURIComponent(await centralState('127.0.0.1:8084'));
		const response = await centralFetch('http://127.0.0.1:8084/auth', {
			headers: {
				'x-forwarded-proto': 'http',
				'x-forwarded-host': '127.0.0.1:8084',
				'x-forwarded-uri': `/_auth/callback?handoff=${encodeURIComponent(stateParam)}`,
			},
		});
		expect(response.status).toBe(400);
		expect(await response.text()).toBe('invalid handoff token');
	});
});

describe('Session hardening', () => {
	const login = async (host = 'app') => {
		cookieJar = new TestCookieJar();
		currentUser = 'testOkUser';
		const authResponse = await testFetch('http://127.0.0.1:8080/auth', {
			headers: { 'x-forwarded-host': host, 'x-forwarded-uri': '/' },
		});
		const oauthState = authResponse.headers.get('location')?.match(/state=([\w_-]+)$/i)?.[1] || '';
		const callbackResponse = await testFetch('http://127.0.0.1:8080/auth', {
			headers: { 'x-forwarded-host': host, 'x-forwarded-uri': `/_auth/callback?code=test&state=${oauthState}` },
		});
		expect(callbackResponse.status).toBe(302);
	};

	afterAll(() => {
		currentName = 'Test User';
	});

	test('session cookie is rejected on a different host', async () => {
		await login('app');
		const sameHost = await testFetch('http://127.0.0.1:8080/auth', { headers: { 'x-forwarded-host': 'app' } });
		expect(sameHost.status).toBe(200);

		const otherHost = await testFetch('http://127.0.0.1:8080/auth', {
			headers: { 'x-forwarded-host': 'other-app', 'x-forwarded-uri': '/' },
		});
		expect(otherHost.status).toBe(302);
	});

	test('allowed_users is enforced on every auth check, not only at login', async () => {
		await login();
		const response = await testFetch('http://127.0.0.1:8080/auth?allowed_users=someoneElse');
		expect(response.status).toBe(401);
	});

	test('logged-in session rejects a callback without state (login CSRF)', async () => {
		await login();
		const response = await testFetch('http://127.0.0.1:8080/auth', {
			headers: { 'x-forwarded-uri': '/_auth/callback?code=attackerCode' },
		});
		expect(response.status).toBe(400);
		expect(await response.text()).toBe('invalid state');
	});

	test('user info with non-latin1 characters is passed as valid JSON', async () => {
		currentName = 'Łukasz 日本';
		await login();
		const response = await testFetch('http://127.0.0.1:8080/auth');
		expect(response.status).toBe(200);
		expect(JSON.parse(response.headers.get('x-auth-info') || '{}').name).toBe('Łukasz 日本');
	});

	test('invalid redirect_code override is ignored', async () => {
		cookieJar = new TestCookieJar();
		const response = await testFetch('http://127.0.0.1:8080/auth?redirect_code=abc', {
			headers: { 'x-forwarded-uri': '/' },
		});
		expect(response.status).toBe(302);
	});

	test('auth responses are not cacheable', async () => {
		const response = await testFetch('http://127.0.0.1:8080/auth', { headers: { 'x-forwarded-uri': '/' } });
		expect(response.headers.get('cache-control')).toBe('no-store');
	});
});
