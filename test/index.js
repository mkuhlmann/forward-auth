import Koa from 'koa';
import { fetch as cookieFetch, CookieJar } from 'node-fetch-cookies';
import assert from 'assert';

import { runForwardAuth } from '../ForwardAuth.js';

const config = {
	listen_host: '0.0.0.0',
	listen_port: 8080,

	redirect_code: 302,
	
	app_key: 'THIS_SHOULD_BE_CHANGED',

	authorize_url: 'http://127.0.0.1:8081/login',
	token_url: 'http://127.0.0.1:8081/token',
	userinfo_url: 'http://127.0.0.1:8081/userinfo',

	client_id: 'clientId',
	client_secret: 'clientSecret',
	allowed_users: ['testOkUser'],
	scopes: 'test',

	cookie_name: '__auth'
};

const forwardAuth = runForwardAuth(config);

// spin up mock oauth endpoint
const koa = new Koa();

let currentUser = 'testOkUser';

koa.use((ctx, next) => {
	if(ctx.path == '/login') {
		ctx.body = '/login';		
	} else if(ctx.path == '/token') {
		ctx.body = { access_token: currentUser };
	} else if(ctx.path == '/userinfo') {
		let token = ctx.header.authorization.split(' ')[1];
		ctx.body = { name: 'Test User', sub: currentUser };
	}
});

const httpServer = koa.listen(8081, '127.0.0.1');
let cookieJar = new CookieJar();

const fetch = (url, opt = {}) => {
	if(!opt.headers) opt.headers = {};
	if(!opt.redirect) opt.redirect = 'manual';

	return cookieFetch(cookieJar, url, opt);
};

let oauthState;

describe('an unauthenicated user', async () => {
	let response;

	before(async () => {		
		response = await fetch('http://127.0.0.1:8080/auth', {
			headers: {
				'x-forwarded-proto': 'http',
				'x-forwarded-host': 'app',
				'x-forwarded-uri': '/redirect/to/here'
			}
		});
	});

	it('should be redirected to oauth login', async function() {
		assert.strictEqual(response.headers.get('location').indexOf('http://127.0.0.1:8081/login'), 0);
	});

	it('should be a 302 redirection', async function() {
		assert.strictEqual(response.status, 302);
	});

	it('should now be a 403 redirection', async function() {
		response = await fetch('http://127.0.0.1:8080/auth?redirect_code=403', {
			headers: {
				'x-forwarded-proto': 'http',
				'x-forwarded-host': 'app',
				'x-forwarded-uri': '/redirect/to/here'
			}
		});

		assert.strictEqual(response.status, 403);
	});

	
	it('redirected url has to include state', async function() {
		let re = response.headers.get('location').match(/state=([\w_-]+)$/i);
		assert.strictEqual(re.length, 2);
		oauthState = re[1];
	});
});

describe('an valid user calling oauth callback', () => {
	it('should not be accepted with invalid state', async () => {
		let r = await fetch('http://127.0.0.1:8080/auth', {
			headers: {
				'x-forwarded-proto': 'http',
				'x-forwarded-host': '127.0.0.1:8080',
				'x-forwarded-uri': '/_auth/callback?code=test&state=invalid'
			}
		}).then(r => r.text());
		assert.equal(r, 'invalid state');
	});

	it('should be redirected to intended', async() => {
		let r = await fetch('http://127.0.0.1:8080/auth', {
			headers: {
				'x-forwarded-proto': 'http',
				'x-forwarded-host': '127.0.0.1:8080',
				'x-forwarded-uri': '/_auth/callback?code=test&state=' + oauthState
			}
		});
		assert.equal(r.headers.get('location'), 'http://app/redirect/to/here');
	});

	it('should be accepted on subsequent requests', async() => {
		let r = await fetch('http://127.0.0.1:8080/auth', {redirect: 'manual'});
		assert.equal(r.status, 200);
	})
});

describe('an invalid user calling oauth callback', () => {

	before(async() => {
		cookieJar = new CookieJar();
		let response = await fetch('http://127.0.0.1:8080/auth', {
			headers: {
				'x-forwarded-proto': 'http',
				'x-forwarded-host': 'app',
				'x-forwarded-uri': '/redirect/to/here'
			}
		});
		let re = response.headers.get('location').match(/state=([\w_-]+)$/i);
		oauthState = re[1];
		currentUser = 'testFailUser';
	});

	it('should be declined', async() => {
		let r = await fetch('http://127.0.0.1:8080/auth', {
			headers: {
				'x-forwarded-proto': 'http',
				'x-forwarded-host': '127.0.0.1:8080',
				'x-forwarded-uri': '/_auth/callback?code=test&state=' + oauthState
			}
		});
		assert.equal(r.status, 401);
	});
})

after(async () => {
	httpServer.close();
	forwardAuth.httpServer.close();
});

