import fs from 'fs';
import { runForwardAuth } from './ForwardAuth.js';

let config = {
	appKey: [process.env.APP_KEY || 'THIS_SHOULD_BE_CHANGED'],
	loginUrl: process.env.LOGIN_URL,
	tokenUrl: process.env.TOKEN_URL,
	userUrl: process.env.USER_URL,

	clientId: process.env.CLIENT_ID || null,
	clientSecret: process.env.CLIENT_SECRET || null,
	allowedUsers: process.env.ALLOWED_USERS || null,
	scopes: process.env.SCOPES || null,
	
	cookieName: process.env.COOKIE_NAME || '__auth'
};

// local config.json file can overwrite default env
if(fs.existsSync('./config.json')) {
	let localConfig = JSON.parse(fs.readFileSync('./config.json', 'utf8'));
	Object.assign(config, localConfig);
}

runForwardAuth(config);