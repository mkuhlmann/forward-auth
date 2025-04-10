import { readFileSync, existsSync } from 'fs';
import { runForwardAuth } from './ForwardAuth';

// Default config
const config = {
	listen_host: process.env.LISTEN_HOST || '0.0.0.0',
	listen_port: parseInt(process.env.LISTEN_PORT || '8080'),

	redirect_code: parseInt(process.env.REDIRECT_CODE || '302'),

	app_key: process.env.APP_KEY || '',
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
};

runForwardAuth(config);
