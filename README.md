# kandev-authentik

A [Kandev](https://github.com/kdlbs/kandev) plugin that adds a **Continue with
Authentik** button to the login screen, using an Authentik OAuth2/OpenID
Connect provider (authorization code flow with PKCE).

The plugin only verifies the Authentik login and tells Kandev who the user is;
Kandev creates the session itself (plugin `auth` capability, ADR 0050). The
plugin id is `kandev-plugin-authentik`; identities are stored under provider
`authentik`.

## Requirements

- Kandev **0.94.0** or newer with [authentication enabled](https://github.com/kdlbs/kandev/blob/main/docs/public/authentication.md)
  and the first admin already set up.
- An Authentik instance reachable from both the browser and the Kandev server.

## Authentik setup

1. Create an **OAuth2/OpenID Provider** and an application for it:
   - Client type: **Confidential**
   - Redirect URI (strict):
     `https://<kandev>/api/plugins/kandev-plugin-authentik/webhooks/callback`
   - Scopes: `openid`, `email`, `profile`
   - Leave **Include claims in id_token** on (the default).
2. Note the **Client ID**, **Client Secret** and **OpenID Configuration Issuer**.

### Verified emails

Kandev matches a first-time SSO login to an existing account by email, so the
plugin only passes on an email that Authentik marks `email_verified: true`.
Recent Authentik versions send `false` by default. Pick one:

- Add a custom **Scope Mapping** for the `email` scope that returns
  `{"email": request.user.email, "email_verified": True}` and select it on the
  provider instead of the default one, or
- enable **Trust unverified emails** in the plugin settings.

Do either only if users cannot change their own email in Authentik; otherwise
any Authentik user can take over a Kandev member account by claiming its email.

## Install and configure

1. `make package-host` (or `make package` for all platforms).
2. **Settings > Plugins > Install plugin**, upload the tarball, enable
   **Authentik SSO**.
3. **Settings > Plugins > Authentik SSO**: set **OpenID issuer** (copied
   exactly, including the trailing slash), **Client ID**, **Client secret** and
   **Kandev URL** (the public root URL, e.g. `https://kandev.example.com`).

The login page now shows **Continue with Authentik**.

## Behaviour

- A known Authentik user (matched by the `sub` claim) is logged in.
- Otherwise a verified email matching an existing **member** links the two;
  Kandev refuses to auto-link to an **admin** account.
- Otherwise a new **member** is created. Promote users in **Settings > Users**.
- `{"error":"auth login rejected"}` after the redirect means Kandev refused the
  identity: no verified email for a new user, the email belongs to an admin,
  the account is disabled, or authentication is not enabled. The Kandev log has
  the reason.

## Develop

`go.mod` resolves the Kandev SDK from a sibling checkout:

```text
parent/
├── kandev/             # https://github.com/kdlbs/kandev at v0.94.0
└── kandev-authentik/   # this repository
```

```sh
make vet
make test
make package-host   # tarball for this platform
make package        # all five platforms
```

Bump `version` in `manifest.yaml` and `VERSION` in the `Makefile` together.

## CI and releases

`.github/workflows` and `.gitea/workflows` hold the same two jobs for GitHub
Actions and Gitea Actions: `ci` (format, vet, test, package) on pushes and pull
requests to `main`, and `release`, which publishes the tarball and
`checksums.txt` when a `v*` tag matching the manifest version is pushed.
