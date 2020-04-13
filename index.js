import fs from 'fs';
import { runForwardAuth } from './ForwardAuth.js';

let config = {
	listen_host: process.env.LISTEN_HOST || '0.0.0.0',
	listen_port: process.env.LISTEN_PORT || 8080,

	redirect_code: 302,

	app_key: [ process.env.APP_KEY ],
	authorize_url: process.env.authorize_url,
	token_url: process.env.TOKEN_URL,
	userinfo_url: process.env.userinfo_url,

	client_id: process.env.CLIENT_ID || null,
	client_secret: process.env.CLIENT_SECRET || null,
	allowed_users: process.env.ALLOWED_USERS || null,
	scopes: process.env.SCOPES || null,
	
	cookie_name: process.env.COOKIE_NAME || '__auth'
};

// local config.json file can overwrite default env
if(fs.existsSync('./config.json')) {
	let localConfig = JSON.parse(fs.readFileSync('./config.json', 'utf8'));
	Object.assign(config, localConfig);
}

runForwardAuth(config);