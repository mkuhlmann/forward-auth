import { isValidRedirectCode, runForwardAuth } from './ForwardAuth';
import { LogLevel } from './Log';

// Parse log level from environment variable
function parseLogLevel(level: string | undefined): LogLevel {
	if (!level) return LogLevel.INFO;

	switch (level.toUpperCase()) {
		case 'DEBUG':
			return LogLevel.DEBUG;
		case 'INFO':
			return LogLevel.INFO;
		case 'WARN':
			return LogLevel.WARN;
		case 'ERROR':
			return LogLevel.ERROR;
		case 'NONE':
			return LogLevel.NONE;
		default:
			return LogLevel.INFO;
	}
}

// Parse a positive integer from an environment variable, failing loudly on garbage
// (a NaN cookie age would otherwise produce sessions that never expire).
function parseIntEnv(name: string, fallback: number): number {
	const raw = process.env[name];
	if (raw === undefined || raw === '') return fallback;
	const value = Number(raw);
	if (!Number.isInteger(value) || value <= 0) {
		throw new Error(`${name} must be a positive integer, got "${raw}".`);
	}
	return value;
}

const appKey = process.env.APP_KEY;
if (!appKey || appKey.length < 32) {
	throw new Error('APP_KEY is required and must be at least 32 characters long.');
}

// Default config
const config = {
	listen_host: process.env.LISTEN_HOST || '0.0.0.0',
	listen_port: parseIntEnv('LISTEN_PORT', 8080),

	redirect_code: parseIntEnv('REDIRECT_CODE', 302),

	app_key: appKey,
	authorize_url: process.env.AUTHORIZE_URL || '',
	token_url: process.env.TOKEN_URL || '',
	userinfo_url: process.env.USERINFO_URL || '',
	discovery_url: process.env.DISCOVERY_URL || undefined,

	client_id: process.env.CLIENT_ID || undefined,
	client_secret: process.env.CLIENT_SECRET || undefined,
	allowed_users: process.env.ALLOWED_USERS || undefined,
	scopes: process.env.SCOPES || undefined,

	cookie_name: process.env.COOKIE_NAME || '__auth',
	cookie_age: parseIntEnv('COOKIE_AGE', 604800), // 7 days, renewed on every request
	session_max_age: parseIntEnv('SESSION_MAX_AGE', 604800), // 7 days after login, then re-authenticate
	cookie_insecure: process.env.COOKIE_INSECURE === 'true',

	callback_port: process.env.CALLBACK_PORT ? parseIntEnv('CALLBACK_PORT', 0) : undefined,
	callback_url: process.env.CALLBACK_URL || undefined,
	callback_centralised: process.env.CALLBACK_CENTRALISED !== 'false',
	callback_allowed_domains: process.env.CALLBACK_ALLOWED_DOMAINS || undefined,

	logout_url: process.env.LOGOUT_URL || undefined,

	log_level: parseLogLevel(process.env.LOG_LEVEL),
};

if (!isValidRedirectCode(config.redirect_code)) {
	throw new Error(`REDIRECT_CODE must be a 3xx, 401 or 403 status code, got ${config.redirect_code}.`);
}

runForwardAuth(config);
