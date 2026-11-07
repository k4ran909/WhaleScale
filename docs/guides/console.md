# Web console

The dashboard served by your server: signing in, admin accounts, two-factor sign-in and API keys.

Served at the server's URL. Sign in with your admin account (created on the first visit, see [Quick start](../getting-started.md)), with your identity provider if OIDC is configured (only emails in `oidc-admins` get in), or with an API key (`whalescale apikeys create`, under "Use an API key instead"). Forgot the password? `whalescale admins reset-password NAME` on the server prints a new one; `whalescale admins create NAME` adds another admin.

**Two-factor sign-in:** in the sidebar's **Two-factor sign-in**, confirm your password, scan the QR code with an authenticator app (Google or Microsoft Authenticator, 1Password, Authy…) and type the code it shows. From then on, signing in takes the password and a current code; each code works once, and turning it on signs your account out of other browsers. Turning it off needs the password and a code. Lost the phone? `whalescale admins reset-2fa NAME` on the server turns it off for that account; `whalescale admins list` shows who has it on. (With OIDC, your identity provider handles two-factor.)

Pages:

- **Machines:** online state, addresses, OS and routes.
- **Topology:** a from/to matrix showing direct or relayed paths, with latency, as the nodes report it.
- **Users**, **Keys** (pre-auth and API keys) and **Routes** (approve subnets and exit nodes).
- **Access policy:** an editor with live validation and lint warnings.
