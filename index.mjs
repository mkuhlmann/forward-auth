import Koa from 'koa';
import koaSession from 'koa-session';
import nanoid from 'nanoid';
import fetch from 'node-fetch';
import fs from 'fs';
import { URLSearchParams } from 'url';
import Log from './Log.mjs';

let config = {
	appKey: [process.env.APP_KEY || 'THIS_SHOULD_BE_CHANGED'],
	loginUrl: process.env.LOGIN_URL,
	tokenUrl: process.env.TOKEN_URL,
	userUrl: process.env.USER_URL,
	
	cookieName: process.env.COOKIE_NAME || '__auth'	
};

// local config.json file can overwrite default env
if(fs.existsSync('./config.json')) {
	let localConfig = JSON.parse(fs.readFileSync('./config.json', 'utf8'));
	Object.assign(config, localConfig);
}


(async _ => {

	const app =  {
		config,
		log: new Log(),
		unixtime: _ => { return Math.floor(new Date() / 1000) }
	};

	app.getAuthConfig = query => {
		let config = {
			clientId: query.client_id,
			clientSecret: query.client_secret			
		};

		if(query.allowed_users) {
			config.allowedUsers = query.allowed_users.split(',');
		}

		return config;
	};
	
	app.getRedirectUri = (ctx) => {
		return ctx.origin + '/_auth/callback';
	};
 	
	app.handleAuth = async (ctx, next) => {
		if(ctx.session.user && ctx.session.user.sub) {
			await app.handleAuthOk(ctx, next);
		} else {
			await app.handleOAuth(ctx, next);
		}
	}
	
	app.handleOAuth = async (ctx, next) => {
		
		if(!ctx.query.client_id || !ctx.query.client_secret) {
			app.log.logNs(Log.LEVEL_ERROR, 'handleAuth', 'invalid clientId and/or clientSecret supplied.');
			return ctx.throw(401, 'invalid request');
		}
		
		let authConfig = app.getAuthConfig(ctx.query);

		let state = nanoid();
		let scope = ctx.query.scope || '';
		
		let redirectUri = app.getRedirectUri(ctx);
		
		ctx.session.state = state;
		
		if (ctx.state.forwardedUri) {
			ctx.session.redirect = ctx.state.forwardedUri.href;
		}

		ctx.redirect(`${app.config.loginUrl}?client_id=${authConfig.clientId}&redirect_uri=${redirectUri}&response_type=code&scope=${scope}&state=${state}`);
	};
	
	app.handleAuthCallback = async (query, ctx, next) => {
		if(!query.code) {
			return ctx.throw(400, 'invalid code');
		}
		
		if(query.state != ctx.session.state) {
			return ctx.throw(400, 'invalid state');
		}
		
		delete ctx.session.state;
		let authConfig = app.getAuthConfig(ctx.query);
		
		let json = await fetch(app.config.tokenUrl, {
			method: 'POST',
			body: new URLSearchParams({
				client_id: authConfig.clientId,
				client_secret: authConfig.clientSecret,
				code: query.code,
				grant_type: 'authorization_code',
				redirect_uri: app.getRedirectUri(ctx)
			})
		}).then(res => res.json());

		if(!json || !json.access_token) {
			return ctx.throw(401, 'invalid access_token');
		}		
		
		let userinfo = await fetch(app.config.userUrl, {
			headers: {
				'authorization': 'Bearer ' + json.access_token
			}
		}).then(res => res.json());
		
		if(authConfig.allowedUsers && authConfig.allowedUsers.indexOf(userinfo.sub) == -1) {
			return ctx.throw(401, 'user not allowed');
		}		
		
		ctx.session.user = {
			sub: userinfo.sub,
			name: userinfo.name
		};
		
		let redirect = ctx.session.redirect || ctx.origin;
		ctx.redirect(redirect);
	};
	
	app.handleAuthOk = async (ctx, next) => {
		let user = ctx.session.user;
		
		ctx.set('X-Auth-User', user.sub);
		ctx.set('X-Auth-Info', JSON.stringify(user));
		
		ctx.code = 200;
		ctx.body = 'auth ok, id=' + user.sub;
	};
 	
 	const koa = app.koa = new Koa();
	
	koa.proxy = true;
	koa.keys = app.config.appKey;

	koa.use(koaSession({
		key: app.config.cookieName,
		maxAge: 7*24*60*60*1000
	}, koa));

	
	koa.use(async (ctx, next) => {
		ctx.code = 401; // ensure we don't send a 2xx code!

		let forwardedUri = null;
		if(ctx.header['x-forwarded-uri']) {
			forwardedUri = new URL(ctx.header['x-forwarded-proto'] + '://' + ctx.header['x-forwarded-host'] + ctx.header['x-forwarded-uri']);
			ctx.state.forwardedUri = forwardedUri;
		}

		if(forwardedUri && forwardedUri.pathname == '/_auth/callback') {
			// we need code from the real url the browser sends
			let query = paramsToObject(forwardedUri.searchParams.entries());
			await app.handleAuthCallback(query, ctx, next);
		} else if(ctx.path == '/auth') {
			await app.handleAuth(ctx, next);
		}
	});
	
	
	koa.listen(8080, '0.0.0.0');

})();

function paramsToObject(entries) {
	let result = {}
	for(let entry of entries) { // each 'entry' is a [key, value] tupple
		const [key, value] = entry;
		result[key] = value;
	}
	return result;
}
