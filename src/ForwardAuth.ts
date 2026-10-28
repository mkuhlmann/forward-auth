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
	aud: string; // origin (proto://host) the session was issued for
	exp: number; // Unix timestamp in seconds
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
	cookie_insecure?: boolean;
	callback_port?: number;
	callback_url?: string;
	callback_centralised: boolean;
	callback_allowed_domains?: string;
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

// Payload embedded in the OAuth state parameter when centralized callback is enabled.
// Signed with APP_KEY so origin cannot be tampered with.
interface CentralizedState {
	uuid: string; // the session state nonce (also stored in session cookie)
	origin: string; // e.g. "https://app-a.example.com"
	exp: number;
}

// Payload the callback server sends back to the originating service.
// Signed with APP_KEY so user info cannot be tampered with.
interface HandoffPayload {
	uuid: string; // must match session.state for CSRF protection
	aud: string; // origin the handoff is intended for
	user: User; // authenticated user info from the userinfo endpoint
	exp: number;
}

// Every signed token carries its purpose in the HMAC input, so a token minted for
// one purpose (e.g. a handoff token in a URL) can never be replayed as another (e.g. a session cookie).
type TokenPurpose = 'session' | 'state' | 'handoff';

const STATE_TTL = 15 * 60; // time a user has to complete the login at the IdP
const HANDOFF_TTL = 2 * 60; // time between callback server redirect and handoff
const FETCH_TIMEOUT_MS = 10_000;
const DISCOVERY_CACHE_TTL = 3600;
const DISCOVERY_CACHE_MAX_ENTRIES = 100;

export function isValidRedirectCode(code: number): boolean {
	return Number.isInteger(code) && ((code >= 300 && code <= 399) || code === 401 || code === 403);
}

class ForwardAuth {
	config: Config;
	log: Log;
	cookieJar: CookieJar;
	discoveryCache: Map<string, { document: OIDCDiscoveryDocument; fetchedAt: number }>;

	constructor(config: Config, log: Log) {
		this.config = config;
		this.log = log;
		this.cookieJar = new CookieJar(config.app_key);
		this.discoveryCache = new Map();
	}

	// Encode a payload as base64url(JSON).hmac(purpose.base64url(JSON))
	private signToken(purpose: TokenPurpose, payload: { exp: number }): string {
		const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
		return `${encoded}.${this.cookieJar.sign(`${purpose}.${encoded}`)}`;
	}

	// Verify and decode a token produced by signToken. Returns null on bad signature, wrong purpose or expiry.
	private verifyToken<T extends { exp: number }>(purpose: TokenPurpose, token: string): T | null {
		const dot = token.lastIndexOf('.');
		if (dot === -1) return null;
		const encoded = token.slice(0, dot);
		const sig = token.slice(dot + 1);
		if (!this.cookieJar.verify(`${purpose}.${encoded}`, sig)) return null;
		try {
			const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString()) as T;
			if (!payload || typeof payload.exp !== 'number' || payload.exp < this.unixtime()) return null;
			return payload;
		} catch {
			return null;
		}
	}

	isUserAllowed(config: Config, sub: string): boolean {
		if (!config.allowed_users) return true;
		const allowedUsers = config.allowed_users
			.split(',')
			.map((u) => u.trim())
			.filter(Boolean);
		return allowedUsers.length === 0 || allowedUsers.includes(sub);
	}

	isAllowedCallbackHost(hostname: string): boolean {
		if (!this.config.callback_allowed_domains) return true;
		return this.config.callback_allowed_domains
			.split(',')
			.map((d) => d.trim().toLowerCase())
			.filter(Boolean)
			.some((d) => hostname === d || hostname.endsWith('.' + d));
	}

	async handleAuthCheck(req: Request, url: URL): Promise<Response> {
		this.log.debug('handleAuthCheck :: Checking authentication status', req);
		const session = await this.getSession(req);

		if (session && session.user && session.user.sub) {
			const user = session.user;

			// allowed_users may differ per protected service (query override), so it must be
			// enforced on every check, not only when the session was created.
			const config = this.getQueryConfig(Object.fromEntries(url.searchParams));
			if (!this.isUserAllowed(config, user.sub)) {
				this.log.warn(`handleAuthCheck :: User ${user.sub} not in allowed users list`, req);
				return new Response('user not allowed', { status: 401 });
			}

			// user is logged in, return 200 and set headers
			this.log.debug(`handleAuthCheck :: User authenticated, id=${user.sub}`, req);

			const headers = new Headers({
				'X-Auth-User': user.sub,
				'X-Forwarded-User': user.sub,
				// header values must be latin1, so escape everything else; the result is still valid JSON
				'X-Auth-Info': JSON.stringify(user).replace(/[\u007f-￿]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')),
			});

			return this.setSessionCookie(
				new Response('auth ok, id=' + user.sub, {
					status: 200,
					headers,
				}),
				session,
			);
		} else {
			// user is not logged in, redirect to oauth endpoint
			this.log.debug('handleAuthCheck :: User not authenticated, redirecting to OAuth', req);
			return this.handleOAuthRedirect(req, url);
		}
	}

	async handleOAuthRedirect(req: Request, url: URL): Promise<Response> {
		this.log.debug('handleOAuthRedirect :: Starting OAuth redirection flow', req);
		const query = Object.fromEntries(url.searchParams);
		const config = await this.getConfigWithDiscovery(query);

		if (!config.client_id || !config.client_secret) {
			this.log.error('handleOAuthRedirect :: Missing client_id or client_secret', req);
			return new Response('invalid request', { status: 401 });
		}

		let authorizeUrl: URL;
		try {
			authorizeUrl = new URL(config.authorize_url);
		} catch {
			this.log.error(`handleOAuthRedirect :: Invalid or missing authorize_url: ${config.authorize_url}`, req);
			return new Response('invalid configuration', { status: 500 });
		}

		const uuid = Bun.randomUUIDv7('base64url');
		const origin = this.getOrigin(req);

		// Session cookie always stores the raw uuid as state
		const session: Session = {
			state: uuid,
			aud: origin,
			exp: this.unixtime() + this.config.cookie_age,
		};

		const forwardedUri = this.getForwardedUri(req);
		if (forwardedUri) {
			session.redirect = forwardedUri.href;
			this.log.debug(`handleOAuthRedirect :: Setting redirect destination to ${forwardedUri.href}`, req);
		}

		// In centralized mode, embed the service origin in the OAuth state parameter (signed).
		// In direct mode, the state parameter is just the plain uuid.
		let oauthState: string;
		if (this.isCentralised(config)) {
			const centralizedState: CentralizedState = {
				uuid,
				origin,
				exp: this.unixtime() + STATE_TTL,
			};
			oauthState = this.signToken('state', centralizedState);
			this.log.debug('handleOAuthRedirect :: Using centralized callback, signed state token', req);
		} else {
			oauthState = uuid;
		}

		authorizeUrl.searchParams.set('client_id', config.client_id);
		authorizeUrl.searchParams.set('redirect_uri', this.getRedirectUri(req, config));
		authorizeUrl.searchParams.set('response_type', 'code');
		authorizeUrl.searchParams.set('scope', config.scopes || '');
		authorizeUrl.searchParams.set('state', oauthState);
		const redirectUrl = authorizeUrl.href;

		this.log.info(`handleOAuthRedirect :: Redirecting to ${redirectUrl}`, req);

		return this.setSessionCookie(
			new Response(null, {
				status: config.redirect_code,
				headers: { Location: redirectUrl },
			}),
			session,
		);
	}

	async handleOAuthCallback(browserQuery: Record<string, string>, req: Request): Promise<Response> {
		this.log.debug('handleOAuthCallback :: Processing OAuth callback', req);

		// Centralized handoff path: the callback server already exchanged the code
		// and is handing off the authenticated user to this service domain.
		if (browserQuery.handoff) {
			return this.handleHandoff(browserQuery.handoff, req);
		}

		const session = await this.getSession(req);

		if (!browserQuery.code) {
			this.log.warn('handleOAuthCallback :: Missing authorization code', req);
			return new Response('invalid code', { status: 400 });
		}

		// session.state must be present: an already logged-in session has no state, and comparing
		// undefined to a missing state param would otherwise let an attacker inject their own code.
		if (!session || !session.state || browserQuery.state !== session.state) {
			const ip = req.headers.get('x-forwarded-for') || 'unknown';
			this.log.warn(`handleOAuthCallback :: Invalid state from IP ${ip}`, req);
			return new Response('invalid state', { status: 400 });
		}

		delete session.state;
		this.log.debug('handleOAuthCallback :: State validated, exchanging code for token', req);

		const query = Object.fromEntries(new URL(req.url).searchParams);
		const config = await this.getConfigWithDiscovery(query);

		const userinfo = await this.exchangeCode(config, browserQuery.code, this.getRedirectUri(req, config), req, 'handleOAuthCallback');
		if (userinfo instanceof Response) return userinfo;

		if (!this.isUserAllowed(config, userinfo.sub)) {
			this.log.warn(`handleOAuthCallback :: User ${userinfo.sub} not in allowed users list`, req);
			return new Response('user not allowed', { status: 401 });
		}

		session.user = userinfo;
		const redirect = session.redirect || this.getOrigin(req);
		delete session.redirect;
		this.log.info(`handleOAuthCallback :: Authentication successful for user ${userinfo.sub}, redirecting to ${redirect}`, req);

		return this.setSessionCookie(
			new Response(null, {
				status: config.redirect_code,
				headers: { Location: redirect },
			}),
			session,
		);
	}

	// Handle the handoff from the centralized callback server.
	// Verifies the signed handoff token, CSRF-checks uuid vs session.state,
	// validates allowed_users, and sets the session cookie.
	private async handleHandoff(handoffToken: string, req: Request): Promise<Response> {
		this.log.debug('handleHandoff :: Processing centralized handoff', req);

		const session = await this.getSession(req);
		if (!session) {
			this.log.warn('handleHandoff :: No session cookie present', req);
			return new Response('invalid session', { status: 400 });
		}

		const handoff = this.verifyToken<HandoffPayload>('handoff', handoffToken);
		if (!handoff) {
			const ip = req.headers.get('x-forwarded-for') || 'unknown';
			this.log.warn(`handleHandoff :: Invalid or expired handoff token from IP ${ip}`, req);
			return new Response('invalid handoff token', { status: 400 });
		}

		// CSRF check: the uuid in the handoff must match the state nonce in the session cookie.
		// The session cookie is scoped to the originating service domain, so a CSRF attacker
		// cannot produce a handoff token that matches the cookie of a different user's session.
		if (!session.state || handoff.uuid !== session.state || handoff.aud !== session.aud) {
			const ip = req.headers.get('x-forwarded-for') || 'unknown';
			this.log.warn(`handleHandoff :: UUID or audience mismatch (CSRF protection) from IP ${ip}`, req);
			return new Response('invalid state', { status: 400 });
		}

		delete session.state;

		const userinfo = handoff.user;
		if (!userinfo || !userinfo.sub) {
			this.log.error('handleHandoff :: Handoff payload missing user sub', req);
			return new Response('invalid user info', { status: 401 });
		}

		// allowed_users must be enforced here on the primary server because per-request
		// query param overrides (e.g. ?allowed_users=alice) are not available on the
		// callback server — they only arrive via the reverse proxy on the /auth route.
		const config = this.getQueryConfig(Object.fromEntries(new URL(req.url).searchParams));
		if (!this.isUserAllowed(config, userinfo.sub)) {
			this.log.warn(`handleHandoff :: User ${userinfo.sub} not in allowed users list`, req);
			return new Response('user not allowed', { status: 401 });
		}

		session.user = userinfo;
		const redirect = session.redirect || this.getOrigin(req);
		delete session.redirect;
		this.log.info(`handleHandoff :: Handoff successful for user ${userinfo.sub}, redirecting to ${redirect}`, req);

		return this.setSessionCookie(
			new Response(null, {
				status: config.redirect_code,
				headers: { Location: redirect },
			}),
			session,
		);
	}

	// Handle an OAuth callback on the secondary (centralized) callback server.
	// Verifies the signed state, exchanges the code for a token, fetches user info,
	// and redirects to the originating service with a signed handoff token.
	async handleCentralizedCallback(req: Request, url: URL): Promise<Response> {
		this.log.debug('handleCentralizedCallback :: Processing centralized OAuth callback', req);

		const params = Object.fromEntries(url.searchParams);

		if (!params.code || !params.state) {
			this.log.warn('handleCentralizedCallback :: Missing code or state', req);
			return new Response('invalid request', { status: 400 });
		}

		// Verify and decode the signed state to get uuid and originating service origin
		const centralizedState = this.verifyToken<CentralizedState>('state', params.state);
		if (!centralizedState || !centralizedState.uuid || !centralizedState.origin) {
			this.log.warn('handleCentralizedCallback :: Invalid, expired or tampered state parameter', req);
			return new Response('invalid state', { status: 400 });
		}

		// Validate the origin before using it in a redirect
		let originUrl: URL;
		try {
			originUrl = new URL(centralizedState.origin);
		} catch {
			this.log.warn(`handleCentralizedCallback :: Invalid origin in state: ${centralizedState.origin}`, req);
			return new Response('invalid state origin', { status: 400 });
		}

		// Only allow https origins (and http when cookie_insecure is set for development)
		const allowedProtocols = this.config.cookie_insecure ? ['http:', 'https:'] : ['https:'];
		if (!allowedProtocols.includes(originUrl.protocol)) {
			this.log.warn(`handleCentralizedCallback :: Disallowed protocol in state origin: ${originUrl.protocol}`, req);
			return new Response('invalid state origin', { status: 400 });
		}

		// The handoff token carries the user's identity, so it must only ever be sent to known hosts.
		if (!this.isAllowedCallbackHost(originUrl.hostname)) {
			this.log.warn(`handleCentralizedCallback :: Origin ${originUrl.origin} not in CALLBACK_ALLOWED_DOMAINS`, req);
			return new Response('invalid state origin', { status: 400 });
		}

		const config = await this.getConfigWithDiscovery({});

		const userinfo = await this.exchangeCode(config, params.code, this.config.callback_url || '', req, 'handleCentralizedCallback');
		if (userinfo instanceof Response) return userinfo;

		// Build the signed handoff token and redirect to the originating service.
		// Use originUrl.origin (not raw string) to prevent path injection via the state.
		const handoffPayload: HandoffPayload = {
			uuid: centralizedState.uuid,
			aud: originUrl.origin,
			user: userinfo,
			exp: this.unixtime() + HANDOFF_TTL,
		};
		const handoffToken = this.signToken('handoff', handoffPayload);

		const handoffUrl = new URL('/_auth/callback', originUrl.origin);
		handoffUrl.searchParams.set('handoff', handoffToken);

		this.log.info(`handleCentralizedCallback :: Redirecting handoff for user ${userinfo.sub} to ${handoffUrl.origin}/_auth/callback`, req);

		return new Response(null, {
			status: 302,
			headers: { Location: handoffUrl.href },
		});
	}

	// Exchange an authorization code for an access token and fetch the user info.
	// Returns the user, or a Response describing the failure.
	private async exchangeCode(config: Config, code: string, redirectUri: string, req: Request, ctx: string): Promise<User | Response> {
		try {
			const tokenResponse = await fetch(config.token_url, {
				method: 'POST',
				headers: { accept: 'application/json' },
				body: new URLSearchParams({
					client_id: config.client_id || '',
					client_secret: config.client_secret || '',
					code,
					grant_type: 'authorization_code',
					redirect_uri: redirectUri,
				}),
				signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
			});

			if (!tokenResponse.ok) {
				this.log.error(`${ctx} :: Token request failed: ${tokenResponse.status} ${tokenResponse.statusText}`, req);
				return new Response('invalid access_token', { status: 401 });
			}

			const json = (await tokenResponse.json()) as TokenResponse;

			if (!json || typeof json.access_token !== 'string' || !json.access_token) {
				this.log.error(`${ctx} :: Invalid or missing access token`, req);
				return new Response('invalid access_token', { status: 401 });
			}

			this.log.debug(`${ctx} :: Got access token, fetching user info`, req);
			const userinfoResponse = await fetch(config.userinfo_url, {
				headers: {
					accept: 'application/json',
					authorization: 'Bearer ' + json.access_token,
				},
				signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
			});

			if (!userinfoResponse.ok) {
				this.log.error(`${ctx} :: Failed to fetch user info: ${userinfoResponse.status} ${userinfoResponse.statusText}`, req);
				return new Response('failed to fetch user info', { status: 401 });
			}

			const userinfo = (await userinfoResponse.json()) as User;

			if (!userinfo || (typeof userinfo.sub !== 'string' && typeof userinfo.sub !== 'number') || userinfo.sub === '') {
				this.log.error(`${ctx} :: Invalid user info structure: missing sub field`, req);
				return new Response('invalid user info', { status: 401 });
			}
			userinfo.sub = String(userinfo.sub);

			this.log.debug(`${ctx} :: User info retrieved, user=${userinfo.sub}`, req);
			return userinfo;
		} catch (error) {
			this.log.error(`${ctx} :: Error during token/userinfo exchange`, error instanceof Error ? { message: error.message, stack: error.stack } : error, req);
			return new Response('authentication error', { status: 500 });
		}
	}

	isCentralised(config: Config): boolean {
		return !!this.config.callback_url && config.callback_centralised;
	}

	getRedirectUri(req: Request, config: Config): string {
		if (this.isCentralised(config)) {
			this.log.debug(`getRedirectUri :: Using centralized callback URL: ${this.config.callback_url}`, req);
			return this.config.callback_url!;
		}
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
			try {
				return new URL(`${proto}://${host}${uri}`);
			} catch {
				this.log.warn('getForwardedUri :: Malformed forwarded headers', req);
				return null;
			}
		}

		this.log.debug('getForwardedUri :: Missing forwarded headers', req);
		return null;
	}

	async fetchOIDCDiscoveryDocument(discoveryUrl: string): Promise<OIDCDiscoveryDocument | null> {
		this.log.debug(`fetchOIDCDiscoveryDocument :: Fetching discovery document from ${discoveryUrl}`);
		try {
			// Check cache first (cache for 1 hour)
			const now = this.unixtime();
			const cached = this.discoveryCache.get(discoveryUrl);

			if (cached && now - cached.fetchedAt < DISCOVERY_CACHE_TTL) {
				this.log.debug(`fetchOIDCDiscoveryDocument :: Using cached discovery document for ${discoveryUrl}`);
				return cached.document;
			}

			// Ensure the URL ends with /.well-known/openid-configuration if not provided
			let fullUrl = discoveryUrl;
			if (!discoveryUrl.endsWith('/.well-known/openid-configuration')) {
				fullUrl = discoveryUrl.endsWith('/') ? `${discoveryUrl}.well-known/openid-configuration` : `${discoveryUrl}/.well-known/openid-configuration`;
			}

			this.log.debug(`fetchOIDCDiscoveryDocument :: Fetching from ${fullUrl}`);
			const response = await fetch(fullUrl, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });

			if (!response.ok) {
				this.log.error(`fetchOIDCDiscoveryDocument :: Failed to fetch: ${response.status} ${response.statusText}`);
				return null;
			}

			const document = (await response.json()) as OIDCDiscoveryDocument;
			this.log.debug(`fetchOIDCDiscoveryDocument :: Successfully fetched discovery document from ${discoveryUrl}`);

			// Cache the result, evicting the oldest entry so per-request discovery URLs cannot grow it unbounded
			this.discoveryCache.delete(discoveryUrl);
			if (this.discoveryCache.size >= DISCOVERY_CACHE_MAX_ENTRIES) {
				this.discoveryCache.delete(this.discoveryCache.keys().next().value!);
			}
			this.discoveryCache.set(discoveryUrl, { document, fetchedAt: now });

			return document;
		} catch (error) {
			this.log.error('fetchOIDCDiscoveryDocument :: Error fetching document', error instanceof Error ? { message: error.message, stack: error.stack } : error);
			return null;
		}
	}

	getQueryConfig(query: Record<string, string>): Config {
		this.log.debug(`getQueryConfig :: Processing query parameters for config override: ${JSON.stringify({ ...query, ...(query.client_secret && { client_secret: '***' }) })}`);
		const config = { ...this.config };

		if (query.client_id) config.client_id = query.client_id;
		if (query.client_secret) config.client_secret = query.client_secret;
		if (query.scopes) config.scopes = query.scopes;
		if (query.redirect_code) {
			const redirectCode = Number(query.redirect_code);
			if (isValidRedirectCode(redirectCode)) {
				config.redirect_code = redirectCode;
			} else {
				this.log.warn(`getQueryConfig :: Ignoring invalid redirect_code: ${query.redirect_code}`);
			}
		}
		if (query.authorize_url) config.authorize_url = query.authorize_url;
		if (query.token_url) config.token_url = query.token_url;
		if (query.userinfo_url) config.userinfo_url = query.userinfo_url;
		if (query.discovery_url) config.discovery_url = query.discovery_url;

		if (query.allowed_users) {
			config.allowed_users = query.allowed_users;
		}

		if (query.callback_centralised !== undefined) {
			config.callback_centralised = query.callback_centralised !== 'false';
		}

		return config;
	}

	async getConfigWithDiscovery(query: Record<string, string>): Promise<Config> {
		this.log.debug('getConfigWithDiscovery :: Getting configuration with potential discovery');
		const config = this.getQueryConfig(query);

		// If discovery_url is provided, try to fetch OIDC endpoints
		if (config.discovery_url) {
			this.log.debug(`getConfigWithDiscovery :: Using discovery URL: ${config.discovery_url}`);
			const discoveryDoc = await this.fetchOIDCDiscoveryDocument(config.discovery_url);

			if (discoveryDoc) {
				this.log.debug('getConfigWithDiscovery :: Successfully retrieved discovery document');
				// Only override if values are not explicitly provided in query
				if (!query.authorize_url && typeof discoveryDoc.authorization_endpoint === 'string') {
					config.authorize_url = discoveryDoc.authorization_endpoint;
					this.log.debug(`getConfigWithDiscovery :: Using discovered authorize_url: ${config.authorize_url}`);
				}

				if (!query.token_url && typeof discoveryDoc.token_endpoint === 'string') {
					config.token_url = discoveryDoc.token_endpoint;
					this.log.debug(`getConfigWithDiscovery :: Using discovered token_url: ${config.token_url}`);
				}

				if (!query.userinfo_url && typeof discoveryDoc.userinfo_endpoint === 'string') {
					config.userinfo_url = discoveryDoc.userinfo_endpoint;
					this.log.debug(`getConfigWithDiscovery :: Using discovered userinfo_url: ${config.userinfo_url}`);
				}
			} else {
				this.log.warn(`getConfigWithDiscovery :: Failed to retrieve discovery document from ${config.discovery_url}`);
			}
		}

		return config;
	}

	async getSession(req: Request): Promise<Session | null> {
		this.log.debug('getSession :: Retrieving session from cookies', req);
		const cookieHeader = req.headers.get('cookie');
		if (!cookieHeader) {
			this.log.debug('getSession :: No cookie header found', req);
			return null;
		}

		// Take the first matching cookie: browsers send the most specific / oldest one first,
		// which makes it harder for a sibling subdomain to shadow the session via cookie tossing.
		let cookie: string | undefined;
		for (const part of cookieHeader.split(';')) {
			const eq = part.indexOf('=');
			if (eq !== -1 && part.slice(0, eq).trim() === this.config.cookie_name) {
				cookie = part.slice(eq + 1).trim();
				break;
			}
		}

		if (!cookie) {
			this.log.debug(`getSession :: Cookie ${this.config.cookie_name} not found`, req);
			return null;
		}

		const session = this.verifyToken<Session>('session', cookie);
		if (!session) {
			this.log.warn('getSession :: Invalid, expired or tampered session cookie', req);
			return null;
		}

		// A session is only valid for the origin it was issued for, so a cookie copied from
		// one protected service cannot be replayed against another one.
		const origin = this.getOrigin(req);
		if (session.aud !== origin) {
			this.log.warn(`getSession :: Session audience ${session.aud} does not match origin ${origin}`, req);
			return null;
		}

		this.log.debug(`getSession :: Valid session found${session.user ? ` for user ${session.user.sub}` : ''}`, req);
		return session;
	}

	setSessionCookie(response: Response, session: Session): Response {
		this.log.debug(`setSessionCookie :: Setting session cookie${session.user ? ` for user ${session.user.sub}` : ''}`);

		// Set server-side expiration timestamp
		session.exp = this.unixtime() + this.config.cookie_age;

		const secureFlag = this.config.cookie_insecure ? '' : '; Secure';
		const cookie = `${this.config.cookie_name}=${this.signToken('session', session)}; Max-Age=${this.config.cookie_age}; Path=/; HttpOnly; SameSite=Lax${secureFlag}`;

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

	if (!!config.callback_port !== !!config.callback_url) {
		log.warn('forwardAuth :: CALLBACK_PORT and CALLBACK_URL should both be set when using centralized callback mode');
	}
	if (config.callback_port && !config.callback_allowed_domains) {
		log.warn('forwardAuth :: CALLBACK_ALLOWED_DOMAINS is not set, the callback server will hand off logins to any origin');
	}

	// Never cache auth decisions and never fall back to Bun's development error page (leaks source and stack traces).
	const serveOptions = {
		hostname: config.listen_host,
		development: false,
		error(error: Error) {
			log.error('forwardAuth :: Unhandled error', { message: error.message, stack: error.stack });
			return new Response('internal error', { status: 500, headers: { 'Cache-Control': 'no-store' } });
		},
	};
	const noStore = (response: Response) => {
		response.headers.set('Cache-Control', 'no-store');
		return response;
	};

	const server = Bun.serve({
		...serveOptions,
		port: config.listen_port,
		async fetch(req) {
			const url = new URL(req.url);

			// Check if this is an OAuth callback
			const forwardedUri = forwardAuth.getForwardedUri(req);
			if (forwardedUri && forwardedUri.pathname === '/_auth/callback') {
				// We need code/handoff from the real URL the browser sends
				const query = Object.fromEntries(forwardedUri.searchParams);
				return noStore(await forwardAuth.handleOAuthCallback(query, req));
			}
			// Proceed to auth check
			else if (url.pathname === '/auth') {
				return noStore(await forwardAuth.handleAuthCheck(req, url));
			}

			// Default response for unexpected routes
			return new Response('Not found', { status: 404 });
		},
	});

	log.info(`forwardAuth :: listening on http://${config.listen_host}:${config.listen_port}`);

	let callbackServer: ReturnType<typeof Bun.serve> | undefined;
	if (config.callback_port) {
		callbackServer = Bun.serve({
			...serveOptions,
			port: config.callback_port,
			async fetch(req) {
				const url = new URL(req.url);
				if (url.pathname === '/callback') {
					const response = noStore(await forwardAuth.handleCentralizedCallback(req, url));
					response.headers.set('Referrer-Policy', 'no-referrer');
					return response;
				}
				return new Response('Not found', { status: 404 });
			},
		});
		log.info(`forwardAuth :: centralized callback server listening on http://${config.listen_host}:${config.callback_port}`);
	}

	return { server, callbackServer, forwardAuth, log };
}
