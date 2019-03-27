
# forward-auth
[![Docker Cloud Build Status](https://img.shields.io/docker/cloud/build/mkuhlmann/forward-auth.svg)](https://hub.docker.com/r/mkuhlmann/forward-auth)

This is a flexible forward auth service for use with the traefik reverse proxy.


## Usage

Example `docker-compose.yml`

```yaml
version: '3.5'

volumes:
  traefik:
  
networks:
  proxy:
  
services:
  traefik:
    image: traefik:alpine
    restart: always
    ports:
      - 80:80
      - 443:443
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - traefik:/etc/traefik
    networks:
      - proxy
      
    forward_auth:
      image: mkuhlmann/forward-auth
      restart: unless-stopped
      environment:
        - APP_KEY=CHANGE_ME
        - LOGIN_URL=https://example.com/oauth/authorize
        - TOKEN_URL=https://example.com/api/oauth/token
        - USER_URL=https://example.com/api/oauth/userinfo
      networks:
        - proxy
    
    nginx:
      image: nginx:1-alpine
      networks:
        - proxy
      labels:
        - traefik.enable=true
        - traefik.port=80
        - traefik.docker.network=proxy
        - traefik.frontend.rule=Host:private.example.com
        - traefik.frontend.auth.forward.address=http://forward_auth:8080/auth?client_id=CLIENT_ID_HERE&client_secret=CLIENT_SECRET_HERE&allowed_users=OPTIONAL_LIMIT_USERS
     
      
```

## Contributing

Pull request are *very* welcome!