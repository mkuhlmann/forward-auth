import { Server, type Serve } from 'bun';
import { CookieJar } from './CookieJar';
import Log, { LogLevel } from './Log';

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
	discovery_url?: string;
	client_id?: string;
	client_secret?: string;
	allowed_users?: string;
	scopes?: string;
	cookie_name: string;
	cookie_age: number;
	cookie_insecure: boolean;
	log_level: LogLevel;
}

interface TokenResponse {
	access_token: string;
	token_type?: string;
	expires_in?: number;
	refresh_token?: string;
	scope?: string;
}

interface OIDCDiscoveryDocument {
	authorization_endpoint: string;
	token_endpoint: string;
	userinfo_endpoint: string;
	[key: string]: any;
}

class ForwardAuth {
	config: Config;
	log: Log;
	cookieJar: CookieJar;
	discoveryCache: Map<string, OIDCDiscoveryDocument>;
	discoveryCacheTime: Map<string, number>;

	constructor(config: Config, log: Log) {
		this.config = config;
		this.log = log;
		this.cookieJar = new CookieJar(config.app_key);
		this.discoveryCache = new Map();
		this.discoveryCacheTime = new Map();
	}

	async handleAuthCheck(req: Request, url: URL): Promise<Response> {
		this.log.debug('handleAuthCheck :: Checking authentication status', req);
		const session = await this.getSession(req);

		if (session.user && session.user.sub) {
			// user is logged in, return 200 and set headers
			const user = session.user;
			this.log.debug(`handleAuthCheck :: User authenticated, id=${user.sub}`, req);

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
			this.log.debug('handleAuthCheck :: User not authenticated, redirecting to OAuth', req);
			return this.handleOAuthRedirect(req, url, session);
		}
	}

	async handleOAuthRedirect(req: Request, url: URL, session: Session): Promise<Response> {
		this.log.debug('handleOAuthRedirect :: Starting OAuth redirection flow', req);
		const query = Object.fromEntries(url.searchParams);
		const config = await this.getConfigWithDiscovery(query);

		if (!config.client_id || !config.client_secret) {
			this.log.error('handleOAuthRedirect :: Missing client_id or client_secret', req);
			return new Response('invalid request', { status: 401 });
		}

		const state = Bun.randomUUIDv7('base64url');
		const scope = config.scopes || '';

		const redirectUri = this.getRedirectUri(req);

		session.state = state;

		const forwardedUri = this.getForwardedUri(req);
		if (forwardedUri) {
			session.redirect = forwardedUri.href;
			this.log.debug(`handleOAuthRedirect :: Setting redirect destination to ${forwardedUri.href}`, req);
		}

		const redirectUrl = `${config.authorize_url}?client_id=${config.client_id}&redirect_uri=${redirectUri}&response_type=code&scope=${scope}&state=${state}`;

		this.log.info(`handleOAuthRedirect :: Redirecting to ${redirectUrl}`, req);

		return this.setSessionCookie(
			new Response(null, {
				status: config.redirect_code,
				headers: { Location: redirectUrl },
			}),
			session
		);
	}

	async handleOAuthCallback(browserQuery: Record<string, string>, req: Request): Promise<Response> {
		this.log.debug('handleOAuthCallback :: Processing OAuth callback', req);
		const session = await this.getSession(req);

		if (!browserQuery.code) {
			this.log.warn('handleOAuthCallback :: Missing authorization code', req);
			return new Response('invalid code', { status: 400 });
		}

		if (browserQuery.state != session.state) {
			const ip = req.headers.get('x-forwarded-for') || 'unknown';
			this.log.warn(`handleOAuthCallback :: Invalid state from IP ${ip}`, req);
			return new Response('invalid state', { status: 400 });
		}

		delete session.state;
		this.log.debug('handleOAuthCallback :: State validated, exchanging code for token', req);

		const query = Object.fromEntries(new URL(req.url).searchParams);
		const config = await this.getConfigWithDiscovery(query);

		try {
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
				this.log.error('handleOAuthCallback :: Invalid or missing access token', req);
				return new Response('invalid access_token', { status: 401 });
			}

			this.log.debug('handleOAuthCallback :: Got access token, fetching user info', req);
			const userinfoResponse = await fetch(config.userinfo_url, {
				headers: {
					authorization: 'Bearer ' + json.access_token,
				},
			});

			const userinfo: User = await userinfoResponse.json();
			this.log.debug(`handleOAuthCallback :: User info retrieved, user=${userinfo.sub}`, req);

			if (config.allowed_users) {
				const allowedUsers = config.allowed_users.split(',');
				if (allowedUsers.indexOf(userinfo.sub) === -1) {
					this.log.warn(`handleOAuthCallback :: User ${userinfo.sub} not in allowed users list`, req);
					return new Response('user not allowed', { status: 401 });
				}
			}

			session.user = userinfo;
			const redirect = session.redirect || this.getOrigin(req);
			this.log.info(`handleOAuthCallback :: Authentication successful for user ${userinfo.sub}, redirecting to ${redirect}`, req);

			return this.setSessionCookie(
				new Response(null, {
					status: config.redirect_code,
					headers: { Location: redirect },
				}),
				session
			);
		} catch (error) {
			this.log.error('handleOAuthCallback :: Error during token/userinfo exchange', error, req);
			return new Response('authentication error', { status: 500 });
		}
	}

	getRedirectUri(req: Request): string {
		const uri = this.getOrigin(req) + '/_auth/callback';
		this.log.debug(`getRedirectUri :: Callback URI: ${uri}`, req);
		return uri;
	}

	getOrigin(req: Request): string {
		const host = req.headers.get('x-forwarded-host') || req.headers.get('host') || '';
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

		this.log.debug('getForwardedUri :: Missing forwarded headers', req);
		return null;
	}

	async fetchOIDCDiscoveryDocument(discoveryUrl: string): Promise<OIDCDiscoveryDocument | null> {
		this.log.debug(`fetchOIDCDiscoveryDocument :: Fetching discovery document from ${discoveryUrl}`);
		try {
			// Check cache first (cache for 1 hour)
			const now = this.unixtime();
			const cachedTime = this.discoveryCacheTime.get(discoveryUrl) || 0;

			if (this.discoveryCache.has(discoveryUrl) && now - cachedTime < 3600) {
				this.log.debug(`fetchOIDCDiscoveryDocument :: Using cached discovery document for ${discoveryUrl}`);
				return this.discoveryCache.get(discoveryUrl) || null;
			}

			// Ensure the URL ends with /.well-known/openid-configuration if not provided
			let fullUrl = discoveryUrl;
			if (!discoveryUrl.endsWith('/.well-known/openid-configuration')) {
				fullUrl = discoveryUrl.endsWith('/') ? `${discoveryUrl}.well-known/openid-configuration` : `${discoveryUrl}/.well-known/openid-configuration`;
			}

			this.log.debug(`fetchOIDCDiscoveryDocument :: Fetching from ${fullUrl}`);
			const response = await fetch(fullUrl);

			if (!response.ok) {
				this.log.error(`fetchOIDCDiscoveryDocument :: Failed to fetch: ${response.status} ${response.statusText}`);
				return null;
			}

			const document = (await response.json()) as OIDCDiscoveryDocument;
			this.log.debug(`fetchOIDCDiscoveryDocument :: Successfully fetched discovery document from ${discoveryUrl}`);

			// Cache the result
			this.discoveryCache.set(discoveryUrl, document);
			this.discoveryCacheTime.set(discoveryUrl, now);

			return document;
		} catch (error) {
			this.log.error('fetchOIDCDiscoveryDocument :: Error fetching document', error);
			return null;
		}
	}

	getQueryConfig(query: Record<string, string>): Config {
		this.log.debug(`getQueryConfig :: Processing query parameters for config override: ${JSON.stringify(query)}`);
		const config = { ...this.config };

		if (query.client_id) config.client_id = query.client_id;
		if (query.client_secret) config.client_secret = query.client_secret;
		if (query.scopes) config.scopes = query.scopes;
		if (query.redirect_code) config.redirect_code = parseInt(query.redirect_code);
		if (query.authorize_url) config.authorize_url = query.authorize_url;
		if (query.token_url) config.token_url = query.token_url;
		if (query.userinfo_url) config.userinfo_url = query.userinfo_url;
		if (query.discovery_url) config.discovery_url = query.discovery_url;

		if (query.allowed_users) {
			config.allowed_users = query.allowed_users;
		}

		return config;
	}

	async getConfigWithDiscovery(query: Record<string, string>): Promise<Config> {
		this.log.debug('getConfigWithDiscovery :: Getting configuration with potential discovery');
		const config = this.getQueryConfig(query);

		// If discovery_url is provided, try to fetch OIDC endpoints
		if (config.discovery_url) {
			this.log.info(`getConfigWithDiscovery :: Using discovery URL: ${config.discovery_url}`);
			const discoveryDoc = await this.fetchOIDCDiscoveryDocument(config.discovery_url);

			if (discoveryDoc) {
				this.log.debug('getConfigWithDiscovery :: Successfully retrieved discovery document');
				// Only override if values are not explicitly provided in query
				if (!query.authorize_url && discoveryDoc.authorization_endpoint) {
					config.authorize_url = discoveryDoc.authorization_endpoint;
					this.log.debug(`getConfigWithDiscovery :: Using discovered authorize_url: ${config.authorize_url}`);
				}

				if (!query.token_url && discoveryDoc.token_endpoint) {
					config.token_url = discoveryDoc.token_endpoint;
					this.log.debug(`getConfigWithDiscovery :: Using discovered token_url: ${config.token_url}`);
				}

				if (!query.userinfo_url && discoveryDoc.userinfo_endpoint) {
					config.userinfo_url = discoveryDoc.userinfo_endpoint;
					this.log.debug(`getConfigWithDiscovery :: Using discovered userinfo_url: ${config.userinfo_url}`);
				}
			} else {
				this.log.warn(`getConfigWithDiscovery :: Failed to retrieve discovery document from ${config.discovery_url}`);
			}
		}

		return config;
	}

	async getSession(req: Request): Promise<Session> {
		this.log.debug('getSession :: Retrieving session from cookies', req);
		const cookieHeader = req.headers.get('cookie');
		if (!cookieHeader) {
			this.log.debug('getSession :: No cookie header found', req);
			return {};
		}

		const cookies = Object.fromEntries(
			cookieHeader.split(';').map((cookie) => {
				const [name, value] = cookie.trim().split('=');
				return [name, value];
			})
		);

		const cookie = cookies[this.config.cookie_name];
		if (!cookie) {
			this.log.debug(`getSession :: Cookie ${this.config.cookie_name} not found`, req);
			return {};
		}

		try {
			const parts = cookie.split('.');
			if (parts.length !== 2) {
				this.log.warn('getSession :: Invalid cookie format', req);
				return {};
			}

			if (this.cookieJar.verify(parts[0], parts[1])) {
				const session = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
				this.log.debug(`getSession :: Valid session found${session.user ? ` for user ${session.user.sub}` : ''}`, req);
				return session;
			} else {
				this.log.warn('getSession :: Invalid cookie signature', req);
			}
		} catch (e) {
			this.log.error('getSession :: Error parsing session cookie', e, req);
		}

		return {};
	}

	setSessionCookie(response: Response, session: Session): Response {
		this.log.debug(`setSessionCookie :: Setting session cookie${session.user ? ` for user ${session.user.sub}` : ''}`);
		const sessionEncoded = Buffer.from(JSON.stringify(session)).toString('base64url');
		const signature = this.cookieJar.sign(sessionEncoded);
		const secureFlag = this.config.cookie_insecure ? '' : '; Secure';
		const cookie = `${this.config.cookie_name}=${sessionEncoded}.${signature}; Max-Age=${this.config.cookie_age}; Path=/; HttpOnly; SameSite=Lax${secureFlag}`;

		response.headers.append('Set-Cookie', cookie);
		return response;
	}

	unixtime(): number {
		return Math.floor(Date.now() / 1000);
	}
}

export function runForwardAuth(config: Config) {
	const log = new Log();
	log.setLogLevel(config.log_level);
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
