import Koa from 'koa';
import koaSession from 'koa-session';
import nanoid from 'nanoid';
import fetch from 'node-fetch';


import Log from './Log.js';


class ForwardAuth {

	constructor(config, log) {
		/** @type {Object} */
		this.config = config;
		this.log = log;
	}

	async handleAuthCheck(ctx, next) {
		if(ctx.session.user && ctx.session.user.sub) {
			// user is logged in, return 400 and set headers

			let user = ctx.session.user;
		
			ctx.set('X-Auth-User', user.sub);
			ctx.set('X-Auth-Info', JSON.stringify(user));
			
			ctx.code = 200;
			ctx.body = 'auth ok, id=' + user.sub;

		} else {
			// use is not logged in, redirect to oauth endpoint
			await this.handleOAuthRedirect(ctx, next);
		}
	}

	async handleOAuthRedirect(ctx, next) {
		let config = this.getQueryConfig(ctx.query);
		
		if(!config.clientId || !config.clientSecret) {
			this.log.error('handleOAuthRedirect :: invalid clientId and/or clientSecret supplied.');
			return ctx.throw(401, 'invalid request');
		}
		
		let state = nanoid();
		let scope = config.scope || '';
		
		let redirectUri = this.getRedirectUri(ctx);
		
		ctx.session.state = state;
		
		if (ctx.state.forwardedUri) {
			ctx.session.redirect = ctx.state.forwardedUri.href;
		}

		ctx.redirect(`${config.loginUrl}?client_id=${config.clientId}&redirect_uri=${redirectUri}&response_type=code&scope=${scope}&state=${state}`);
	}

	/**
	 * 
	 * @param {object} query The forwarded (from the browser) query arguments
	 * @param {*} ctx 
	 * @param {*} next 
	 */
	async handleOAuthCallback(browserQuery, ctx, next) {
		if(!browserQuery.code) {
			return ctx.throw(400, 'invalid code');
		}
		
		if(browserQuery.state != ctx.session.state) {
			return ctx.throw(400, 'invalid state');
		}
		
		delete ctx.session.state;
		let config = this.getQueryConfig(ctx.query); // use proxyquery, not browser
		
		let json = await fetch(config.tokenUrl, {
			method: 'POST',
			body: new URLSearchParams({
				client_id: config.clientId,
				client_secret: config.clientSecret,
				code: browserQuery.code,
				grant_type: 'authorization_code',
				redirect_uri: this.getRedirectUri(ctx)
			})
		}).then(res => res.json());

		if(!json || !json.access_token) {
			return ctx.throw(401, 'invalid access_token');
		}		
		
		let userinfo = await fetch(config.userUrl, {
			headers: {
				'authorization': 'Bearer ' + json.access_token
			}
		}).then(res => res.json());
		
		if(config.allowedUsers && config.allowedUsers.indexOf(userinfo.sub) == -1) {
			return ctx.throw(401, 'user not allowed');
		}		
		
		ctx.session.user = {
			sub: userinfo.sub,
			name: userinfo.name
		};
		
		let redirect = ctx.session.redirect || ctx.origin;
		ctx.redirect(redirect);
	}

	getRedirectUri(ctx) {
		return ctx.origin + '/_auth/callback';
	}

	getQueryConfig(query) {
		let config = { ...this.config };

		config.clientId = query.client_id || config.clientId;
		config.clientSecret = query.client_secret || config.clientSecret;
		config.scopes = query.scopes || config.scopes;

		if(query.allowed_users) {
			config.allowedUsers = query.allowed_users.split(',');
		}

		return config;
	}

	/**
	 * @returns {number} Current unixtime in seconds
	 */
	unixtime() {
		return Math.floor(new Date() / 1000);
	}
}


export function runForwardAuth(config) {
	const log = new Log();
	const koa = new Koa();

	const forwardAuth = new ForwardAuth(config, log);
		
	koa.proxy = true; // always behind proxy
	koa.keys = config.appKey;
	
	koa.use(koaSession({
		key: config.cookieName,
		maxAge: 7*24*60*60*1000
	}, koa));
	
		
	koa.use(async (ctx, next) => {
		ctx.code = 401; // ensure we don't send a 2xx code!
	
		let forwardedUri = null;
	
		// parse the original uri sent by the browser, since this app sits behind a proxy at all times
		if(ctx.header['x-forwarded-uri']) {
			forwardedUri = new URL(ctx.header['x-forwarded-proto'] + '://' + ctx.header['x-forwarded-host'] + ctx.header['x-forwarded-uri']);
			ctx.state.forwardedUri = forwardedUri;
		}
	
		// is this a oauth callback?
		if(forwardedUri && forwardedUri.pathname == '/_auth/callback') {
			// we need code from the real url the browser sends
			let query = paramsToObject(forwardedUri.searchParams.entries());
			await forwardAuth.handleOAuthCallback(query, ctx, next);
	
		// proceed to auth check
		} else if(ctx.path == '/auth') {
			await forwardAuth.handleAuthCheck(ctx, next);
		}
	});	
	
	const httpServer = koa.listen(8080, '0.0.0.0');
	log.info('forwardAuth :: listening on 0.0.0.0:8080');
	
	return { httpServer, koa, forwardAuth, log };
};


function paramsToObject(entries) {
	let result = {}
	for(let entry of entries) { // each 'entry' is a [key, value] tupple
		const [key, value] = entry;
		result[key] = value;
	}
	return result;
}