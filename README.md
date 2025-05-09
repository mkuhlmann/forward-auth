# forward-auth

v2 🎉

Highly flexible forward auth service for use with an oauth endpoint and a reverse proxy (e.g. [traefik](https://docs.traefik.io/middlewares/forwardauth/)).

## Configuration

forward-auth can be configured in two ways, values are applied in following priority (low to high):

`environment variables < query params`

Please use UPPER_CASE in environment variables, lower_case otherwise. Note that listen_host, listen_port, app_key, cookie_name and cookie_age cannot be set via query params.

The following options are available:

| Config Key    | Description                                                                                                                       | Required | Default           |
| ------------- | --------------------------------------------------------------------------------------------------------------------------------- | -------- | ----------------- |
| listen_host   | host to bind                                                                                                                      |          | `0.0.0.0`         |
| listen_port   | port to bind                                                                                                                      |          | `8080`            |
| app_key       | keys for cookie signing                                                                                                           | ✔        |
| cookie_name   | Name of Cookie                                                                                                                    |          | `__auth`          |
| cookie_age    | Max age of cookie in seconds                                                                                                      |          | `604800` (7 days) |
| redirect_code | HTTP status code to return, when redirecting<sup>[because](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html)</sup> |          | 302               |
| discovery_url | OpenID Connect Discovery URL, used to auto-configure authorize_url, token_url and userinfo_url                                    |          |                   |
| authorize_url | OAuth Authorization Request URL ([spec](https://tools.ietf.org/html/rfc6749#section-4.1.1))                                       | ✔\*      |                   |
| token_url     | OAuth Access Token Endpoint                                                                                                       | ✔\*      |                   |
| userinfo_url  | OpenID Connect UserInfo endpoint, must include `sub` field                                                                        | ✔\*      |                   |
| client_id     | OAuth Client Id                                                                                                                   | ✔        |                   |
| client_secret | OAuth Client Secret                                                                                                               | ✔        |                   |
| allowed_users | Comma-seperated list of allowed `sub`s, empty = anyone                                                                            |          | `[]`              |
| scopes        | Comma-seperated OAuth Scopes                                                                                                      |          | `id`              |
| log_level     | Log level (DEBUG, INFO, WARN, ERROR, NONE)                                                                                        |          | `INFO`            |

\* You can either provide individual URLs (authorize_url, token_url, userinfo_url) OR use discovery_url to automatically fetch them from an OpenID Connect provider's discovery document.

When client is authenticated, forward_auth passes X-Auth-User with the sub and X-Auth-Info with the json encoded userinfo_url response, those may be passed to your application via the reverse proxy (see example below).

## OpenID Connect Discovery

If your identity provider supports OpenID Connect, you can use the discovery_url parameter instead of manually configuring the endpoint URLs.
The service will automatically fetch the standard endpoints from the provider's discovery document available at `/.well-known/openid-configuration`.

For example, with Google:

```
discovery_url=https://accounts.google.com
```

This will automatically configure authorize_url, token_url, and userinfo_url based on the discovery document.
If you provide any of these URLs explicitly, they will override the values from the discovery document.

## Usage

Example `docker-compose.yml`

```yaml
version: '3.5'

services:
  traefik:
    image: traefik:v3
    restart: always
    command:
      - '--providers.docker=true'
      - '--providers.docker.exposedbydefault=false'
      - '--entrypoints.web.address=:80'
    ports:
      - 80:80
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock

  forward_auth:
    image: ghcr.io/mkuhlmann/forward-auth
    restart: unless-stopped
    environment:
      - APP_KEY=CHANGE_ME
      # Either use discovery_url
      - DISCOVERY_URL=https://example.com
      # OR specify individual endpoints
      # - AUTHORIZE_URL=https://example.com/oauth/authorize
      # - TOKEN_URL=https://example.com/oauth/token
      # - USERINFO_URL=https://example.com/oauth/userinfo
      - CLIENT_ID=clientid
      - CLIENT_SECRET=verysecret

  nginx:
    image: nginx:mainline-alpine
    networks:
      - proxy
    labels:
      - 'traefik.enable=true'
      - 'traefik.http.services.nginx.loadbalancer.server.port=80'
      - 'traefik.http.routers.nginx.entrypoints=web'
      - 'traefik.http.routers.nginx.rule=Host(`private.example.com`)'
      - 'traefik.http.middlewares.forward_auth.forwardauth.address=http://forward_auth:8080/auth?allowed_users=ALLOWED_USER_SUB'
      - 'traefik.http.middlewares.forward_auth.forwardauth.authResponseHeaders=X-Auth-User,X-Auth-Info'
```

Example nginx config, be sure to set redirect_code to 403!

```nginxconf
server {
	listen 443 ssl http2;
	listen [::]:443 ssl http2;
	server_name secret.example.com;

	location = /auth {
		internal;
		proxy_pass http://forward_auth:8080;
		proxy_intercept_errors on;
		proxy_set_header Host $host;
		proxy_set_header X-Real-IP $remote_addr;
		proxy_set_header X-Forwarded-Host $host;
		proxy_set_header X-Forwarded-Proto $scheme;
		proxy_set_header X-Forwarded-Uri $request_uri;

		proxy_pass_request_headers on;
		proxy_set_header Content-Length "";
	}

	location @auth_redirect {
		add_header Set-Cookie $auth_cookie;
		return 302 $auth_location;
	}

	location / {
		auth_request /auth;
		auth_request_set $auth_location $upstream_http_location;

		auth_request_set $auth_cookie $upstream_http_set_cookie;
		add_header Set-Cookie $auth_cookie;

		error_page 403 = @auth_redirect;
		error_page 401 = /no_auth;

		auth_request_set $auth_user  $upstream_http_x_auth_user;
		auth_request_set $auth_info  $upstream_http_x_auth_info;
		proxy_set_header X-Auth-User $auth_user;
		proxy_set_header X-Auth-Info $auth_info;

		proxy_buffering off;
		proxy_pass http://upstream;
		proxy_set_header Host $host;
		proxy_redirect http:// https://;
		proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
		proxy_set_header Upgrade $http_upgrade;
		proxy_set_header Connection $connection_upgrade;
	}

	location = /noauth {
		internal;
		add_header Content-Type text/plain;
		return 200 'unauthenticated';
	}
}

```

## Contributing

Pull request are _very_ welcome!
