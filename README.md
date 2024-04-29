# samsa — [team Team] Single Sign On

**Seamless automatic multi-site authorization** for all internal [team Team] resources.

Nginx example setup: `nginx/nginx.conf`. Outline:

- `/.sso/authorize` everywhere should be proxied to the app with `internal; proxy_pass_request_body off;`
- We need a domain where user profile will be stored (`main_domain`). It should be proxied to the app.
- On all domains, `auth_request /.sso/authorize` should be added, `error_page 401` should be set to redirect to `/.sso/login?next=$request_uri` and `/.sso` should be proxied to the app

Settings example (`.env` file):

```
DATABASE_URL=postgresql+asyncpg://nora:nora@localhost:16432/nora
DEBUG=True
MAIN_DOMAIN=localhost:8001
ALLOWED_DOMAINS=["demo.localhost:8001", "localhost:8001"]
```
