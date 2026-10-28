# forward-auth

v2 🎉

Highly flexible forward auth service for use with an oauth endpoint and a reverse proxy (e.g. [traefik](https://docs.traefik.io/middlewares/forwardauth/)).

## Configuration

forward-auth can be configured in two ways, values are applied in following priority (low to high):

`environment variables < query params`

Note that `LISTEN_HOST`, `LISTEN_PORT`, `APP_KEY`, `COOKIE_NAME`, `COOKIE_AGE`, `SESSION_MAX_AGE`, `CALLBACK_PORT`, and `CALLBACK_URL` can only be set via environment variables, not query params.

The following options are available:

| Environment Variable       | Description                                                                                                                                                                   | Required | Default           |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | ----------------- |
| `LISTEN_HOST`              | Host to bind                                                                                                                                                                  |          | `0.0.0.0`         |
| `LISTEN_PORT`              | Port to bind                                                                                                                                                                  |          | `8080`            |
| `APP_KEY`                  | Key for cookie signing (min. 32 characters)                                                                                                                                   | ✔        |                   |
| `COOKIE_NAME`              | Name of the session cookie                                                                                                                                                    |          | `__auth`          |
| `COOKIE_AGE`               | Inactivity timeout in seconds, renewed on every request                                                                                                                       |          | `604800` (7 days) |
| `SESSION_MAX_AGE`          | Absolute session lifetime in seconds; users must log in again this long after their login, regardless of activity                                                             |          | `604800` (7 days) |
| `COOKIE_INSECURE`          | Allow cookies over insecure (HTTP) connections. Set to `true` for development, should be `false` in production                                                                |          | `false`           |
| `REDIRECT_CODE`            | HTTP status code to return when redirecting<sup>[because](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html)</sup>                                              |          | `302`             |
| `DISCOVERY_URL`            | OpenID Connect Discovery URL, used to auto-configure `AUTHORIZE_URL`, `TOKEN_URL`, and `USERINFO_URL`                                                                         |          |                   |
| `AUTHORIZE_URL`            | OAuth Authorization Request URL ([spec](https://tools.ietf.org/html/rfc6749#section-4.1.1))                                                                                   | ✔\*      |                   |
| `TOKEN_URL`                | OAuth Access Token Endpoint                                                                                                                                                   | ✔\*      |                   |
| `USERINFO_URL`             | OpenID Connect UserInfo endpoint, must include `sub` field                                                                                                                    | ✔\*      |                   |
| `CLIENT_ID`                | OAuth Client ID                                                                                                                                                               | ✔        |                   |
| `CLIENT_SECRET`            | OAuth Client Secret                                                                                                                                                           | ✔        |                   |
| `ALLOWED_USERS`            | Comma-separated list of allowed `sub` values; empty = anyone                                                                                                                  |          | `[]`              |
| `SCOPES`                   | Space-separated OAuth scopes, passed verbatim as the `scope` parameter                                                                                                        |          |                   |
| `CALLBACK_PORT`            | Port for the centralized callback server (see [Centralized Callback](#centralized-callback)); disabled when unset                                                             |          |                   |
| `CALLBACK_URL`             | Public URL of the centralized callback endpoint, e.g. `https://auth-cb.example.com/callback` (required when `CALLBACK_PORT` set)                                              |          |                   |
| `CALLBACK_ALLOWED_DOMAINS` | Comma-separated domains the centralized callback may hand logins off to; `example.com` also matches `*.example.com`. **Strongly recommended** whenever `CALLBACK_PORT` is set |          |                   |
| `CALLBACK_CENTRALISED`     | Enable/disable centralized callback mode (`true`/`false`). Can be overridden per-request via query param (`?callback_centralised=false`)                                      |          | `true`            |
| `LOGOUT_URL`               | Where to redirect after logout, e.g. your IdP's logout page. Defaults to the root of the protected service                                                                    |          |                   |
| `LOG_LEVEL`                | Log level (`DEBUG`, `INFO`, `WARN`, `ERROR`, `NONE`)                                                                                                                          |          | `INFO`            |

\* You can either provide individual URLs (`AUTHORIZE_URL`, `TOKEN_URL`, `USERINFO_URL`) OR use `DISCOVERY_URL` to automatically fetch them from an OpenID Connect provider's discovery document.

When a client is authenticated, forward-auth passes `X-Auth-User` (and `X-Forwarded-User`) with the `sub` and `X-Auth-Info` with the JSON-encoded `USERINFO_URL` response. These can be forwarded to your application via the reverse proxy (see examples below).

The session, including the user info, is stored in a signed cookie. To stay below the browser limit of 4096 bytes, the largest user info claims (e.g. long `groups` lists) are dropped from the session and from `X-Auth-Info` when needed; `sub` is always kept.

## Logout

Send users to `/_auth/logout` on any protected service to clear their session. They are then redirected to `LOGOUT_URL`, or to the root of the service if it is unset. Since your IdP usually still has an active session, the user will often be logged straight back in. Set `LOGOUT_URL` to your IdP's logout page to end both sessions.

> [!WARNING]
> **Never expose the forward-auth port (`LISTEN_PORT`) to clients.** It must only be reachable by your reverse proxy.
> forward-auth trusts the query params of the `/auth` request (which can override `token_url`, `userinfo_url`, `allowed_users`, …) and the `X-Forwarded-Host`, `X-Forwarded-Proto` and `X-Forwarded-Uri` headers. Anyone who can call it directly can forge logins as any user.
> Your reverse proxy must also **overwrite** the `X-Forwarded-*` headers instead of trusting values sent by clients. The Traefik and Nginx examples below do this.
>
> Sessions are bound to the host they were issued for and `allowed_users` is checked on every request, so a cookie from one protected service cannot be reused on another.

## OpenID Connect Discovery

If your identity provider supports OpenID Connect, you can use `DISCOVERY_URL` instead of manually configuring the individual endpoint URLs.
The service will automatically fetch the standard endpoints from the provider's discovery document available at `/.well-known/openid-configuration`.

For example, with Google:

```
DISCOVERY_URL=https://accounts.google.com
```

This will automatically configure `AUTHORIZE_URL`, `TOKEN_URL`, and `USERINFO_URL` based on the discovery document.
If you provide any of these URLs explicitly, they will override the values from the discovery document.

## Centralized Callback

By default, the OAuth `redirect_uri` is derived from the service being accessed (e.g. `https://app-a.example.com/_auth/callback`), which means every protected service needs its own callback URL registered with the OAuth provider.

Setting `CALLBACK_PORT` and `CALLBACK_URL` enables a **centralized callback server** on a separate port, so you only need to register a single callback URL with your OAuth provider — regardless of how many services are protected.

```
CALLBACK_PORT=8081
CALLBACK_URL=https://auth-callback.example.com/callback
CALLBACK_ALLOWED_DOMAINS=example.com
```

> [!IMPORTANT]
> Set `CALLBACK_ALLOWED_DOMAINS`. The callback server sends a signed token carrying the user's identity to the origin recorded in the OAuth state. Without the allowlist, a misconfigured proxy that lets a client choose `X-Forwarded-Host` lets an attacker receive that token for a victim and take over their session.

The secondary server listens on `CALLBACK_PORT` and exposes a single `GET /callback` endpoint. It must be reachable at `CALLBACK_URL` by the browser (i.e. exposed via your reverse proxy or directly).

### How it works

1. An unauthenticated user visits a protected service
2. forward-auth redirects to the OAuth provider with `redirect_uri` set to `CALLBACK_URL`
3. After login, the OAuth provider redirects the browser to `CALLBACK_URL?code=...&state=...`
4. The centralized callback server exchanges the code, fetches user info, and redirects the browser back to the originating service's `/_auth/callback?handoff=<signed-token>`
5. The reverse proxy forwards that to the primary forward-auth, which verifies the signed token, sets the session cookie on the correct domain, and redirects to the original destination

The session cookie is always set on the originating service's domain. CSRF protection is preserved: a signed nonce ties the handoff token to the session cookie that was set before the OAuth redirect.

> [!NOTE]
> Per-request config overrides passed as query parameters (e.g. `?allowed_users=alice`) are supported — they are evaluated at the primary server, not the callback server. The callback server uses only environment-level configuration.

### Traefik example

Expose **only** the callback server (port 8081) publicly. The primary auth server (port 8080) is called by the forward-auth middleware and must not get a router of its own:

```yaml
services:
  forward_auth:
    image: ghcr.io/mkuhlmann/forward-auth
    environment:
      - APP_KEY=CHANGE_ME
      - DISCOVERY_URL=https://idp.example.com
      - CLIENT_ID=clientid
      - CLIENT_SECRET=verysecret
      - CALLBACK_PORT=8081
      - CALLBACK_URL=https://auth-callback.example.com/callback
      - CALLBACK_ALLOWED_DOMAINS=example.com
    labels:
      - 'traefik.enable=true'
      # Centralized callback (public, called by the OAuth provider redirect)
      - 'traefik.http.routers.callback.rule=Host(`auth-callback.example.com`)'
      - 'traefik.http.routers.callback.service=callback'
      - 'traefik.http.services.callback.loadbalancer.server.port=8081'
```

Register `https://auth-callback.example.com/callback` as the single allowed redirect URI in your OAuth provider. All protected services will share it.

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
      # Either use DISCOVERY_URL
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

Example nginx config, be sure to set `REDIRECT_CODE=403`!

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
