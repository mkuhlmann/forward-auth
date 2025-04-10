import { Server, type Serve } from 'bun';
import { CookieJar } from './CookieJar';
import Log from './Log';

interface User {
	sub: string;
	[key: string]: any;
}

interface Session {
	user?: User;
	state?: string;
	redirect?: string;
}

interface Config {
	listen_host: string;
	listen_port: number;
	redirect_code: number;
	app_key: string;
	authorize_url: string;
	token_url: string;
	userinfo_url: string;
	client_id: string | null;
	client_secret: string | null;
	allowed_users: string | null;
	scopes: string | null;
	cookie_name: string;
	cookie_age: number;
}

interface TokenResponse {
	access_token: string;
	token_type?: string;
	expires_in?: number;
	refresh_token?: string;
	scope?: string;
}

class ForwardAuth {
	config: Config;
	log: Log;
	cookieJar: CookieJar;

	constructor(config: Config, log: Log) {
		this.config = config;
		this.log = log;
		this.cookieJar = new CookieJar(config.app_key);
	}

	async handleAuthCheck(req: Request, url: URL): Promise<Response> {
		const session = await this.getSession(req);

		if (session.user && session.user.sub) {
			// user is logged in, return 200 and set headers
			const user = session.user;

			const headers = new Headers({
				'X-Auth-User': user.sub,
				'X-Auth-Info': JSON.stringify(user),
			});

			return this.setSessionCookie(
				new Response('auth ok, id=' + user.sub, {
					status: 200,
					headers,
				}),
				session
			);
		} else {
			// user is not logged in, redirect to oauth endpoint
			return this.handleOAuthRedirect(req, url, session);
		}
	}

	async handleOAuthRedirect(req: Request, url: URL, session: Session): Promise<Response> {
		const query = Object.fromEntries(url.searchParams);
		const config = this.getQueryConfig(query);

		if (!config.client_id || !config.client_secret) {
			this.log.error('handleOAuthRedirect :: invalid clientId and/or clientSecret supplied.');
			return new Response('invalid request', { status: 401 });
		}

		const state = Bun.randomUUIDv7('base64url');
		const scope = config.scopes || '';

		const redirectUri = this.getRedirectUri(req);

		session.state = state;

		const forwardedUri = this.getForwardedUri(req);
		if (forwardedUri) {
			session.redirect = forwardedUri.href;
		}

		const redirectUrl = `${config.authorize_url}?client_id=${config.client_id}&redirect_uri=${redirectUri}&response_type=code&scope=${scope}&state=${state}`;

		return this.setSessionCookie(
			new Response(null, {
				status: config.redirect_code,
				headers: { Location: redirectUrl },
			}),
			session
		);
	}

	async handleOAuthCallback(browserQuery: Record<string, string>, req: Request): Promise<Response> {
		const session = await this.getSession(req);

		if (!browserQuery.code) {
			return new Response('invalid code', { status: 400 });
		}

		if (browserQuery.state != session.state) {
			const ip = req.headers.get('x-forwarded-for') || 'unknown';
			this.log.info(`handleOAuthCallback :: invalid state from ${ip}`);
			return new Response('invalid state', { status: 400 });
		}

		delete session.state;
		const query = Object.fromEntries(new URL(req.url).searchParams);
		const config = this.getQueryConfig(query);

		const tokenResponse = await fetch(config.token_url, {
			method: 'POST',
			body: new URLSearchParams({
				client_id: config.client_id || '',
				client_secret: config.client_secret || '',
				code: browserQuery.code,
				grant_type: 'authorization_code',
				redirect_uri: this.getRedirectUri(req),
			}),
		});

		const json: TokenResponse = await tokenResponse.json();

		if (!json || !json.access_token) {
			return new Response('invalid access_token', { status: 401 });
		}

		const userinfoResponse = await fetch(config.userinfo_url, {
			headers: {
				authorization: 'Bearer ' + json.access_token,
			},
		});

		const userinfo: User = await userinfoResponse.json();

		if (config.allowed_users) {
			const allowedUsers = config.allowed_users.split(',');
			if (allowedUsers.indexOf(userinfo.sub) === -1) {
				return new Response('user not allowed', { status: 401 });
			}
		}

		session.user = userinfo;

		const redirect = session.redirect || this.getOrigin(req);

		return this.setSessionCookie(
			new Response(null, {
				status: config.redirect_code,
				headers: { Location: redirect },
			}),
			session
		);
	}

	getRedirectUri(req: Request): string {
		return this.getOrigin(req) + '/_auth/callback';
	}

	getOrigin(req: Request): string {
		const host = req.headers.get('host') || '';
		const proto = req.headers.get('x-forwarded-proto') || 'http';
		return `${proto}://${host}`;
	}

	getForwardedUri(req: Request): URL | null {
		const uri = req.headers.get('x-forwarded-uri');
		const host = req.headers.get('x-forwarded-host');
		const proto = req.headers.get('x-forwarded-proto');

		if (uri && host && proto) {
			return new URL(`${proto}://${host}${uri}`);
		}
		return null;
	}

	getQueryConfig(query: Record<string, string>): Config {
		const config = { ...this.config };

		if (query.client_id) config.client_id = query.client_id;
		if (query.client_secret) config.client_secret = query.client_secret;
		if (query.scopes) config.scopes = query.scopes;
		if (query.redirect_code) config.redirect_code = parseInt(query.redirect_code);

		if (query.allowed_users) {
			config.allowed_users = query.allowed_users;
		}

		return config;
	}

	async getSession(req: Request): Promise<Session> {
		const cookieHeader = req.headers.get('cookie');
		if (!cookieHeader) return {};

		const cookies = Object.fromEntries(
			cookieHeader.split(';').map((cookie) => {
				const [name, value] = cookie.trim().split('=');
				return [name, value];
			})
		);

		const cookie = cookies[this.config.cookie_name];
		if (!cookie) return {};

		try {
			const parts = cookie.split('.');
			if (parts.length !== 2) return {};

			if (this.cookieJar.verify(parts[0], parts[1])) {
				return JSON.parse(Buffer.from(parts[0], 'base64url').toString());
			}
		} catch (e) {
			this.log.error('Error parsing session cookie', e);
		}

		return {};
	}

	setSessionCookie(response: Response, session: Session): Response {
		const sessionEncoded = Buffer.from(JSON.stringify(session)).toString('base64url');
		const signature = this.cookieJar.sign(sessionEncoded);
		const cookie = `${this.config.cookie_name}=${sessionEncoded}.${signature}; Max-Age=${this.config.cookie_age}; Path=/; HttpOnly; SameSite=Lax`;

		response.headers.append('Set-Cookie', cookie);
		return response;
	}

	unixtime(): number {
		return Math.floor(Date.now() / 1000);
	}
}

export function runForwardAuth(config: Config) {
	const log = new Log();
	const forwardAuth = new ForwardAuth(config, log);

	const server = Bun.serve({
		port: config.listen_port,
		hostname: config.listen_host,
		async fetch(req) {
			const url = new URL(req.url);

			// Check if this is an OAuth callback
			const forwardedUri = forwardAuth.getForwardedUri(req);
			if (forwardedUri && forwardedUri.pathname === '/_auth/callback') {
				// We need code from the real URL the browser sends
				const query = Object.fromEntries(forwardedUri.searchParams);
				return await forwardAuth.handleOAuthCallback(query, req);
			}
			// Proceed to auth check
			else if (url.pathname === '/auth') {
				return await forwardAuth.handleAuthCheck(req, url);
			}

			// Default response for unexpected routes
			return new Response('Not found', { status: 404 });
		},
	});

	log.info(`forwardAuth :: listening on http://${config.listen_host}:${config.listen_port}`);

	return { server, forwardAuth, log };
}
