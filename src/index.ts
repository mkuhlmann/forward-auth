import { runForwardAuth } from './ForwardAuth';
import { LogLevel } from './Log';
import { randomBytes } from 'crypto';

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

let appKey = process.env.APP_KEY;
if (!appKey || appKey.length < 32) {
	console.warn(`Generated random APP_KEY as APP_KEY is missing or too short. It must be at least 32 characters long.`);
	appKey = randomBytes(32).toString('hex');
}

// Default config
const config = {
	listen_host: process.env.LISTEN_HOST || '0.0.0.0',
	listen_port: parseInt(process.env.LISTEN_PORT || '8080'),

	redirect_code: parseInt(process.env.REDIRECT_CODE || '302'),

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
	cookie_age: parseInt(process.env.COOKIE_AGE || '604800'), // 7 days

	log_level: parseLogLevel(process.env.LOG_LEVEL),
};

runForwardAuth(config);
