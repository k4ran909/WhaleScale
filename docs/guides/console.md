# Web console

The dashboard served by your server: signing in, admin accounts, passkeys, two-factor sign-in and API keys.

Served at the server's URL. Sign in with your admin account (created on the first visit, see [Quick start](../getting-started.md)), with your identity provider if OIDC is configured (only emails in `oidc-admins` get in), or with an API key (`whalescale apikeys create`, under "Use an API key instead"). Forgot the password? `whalescale admins reset-password NAME` on the server prints a new one; `whalescale admins create NAME` adds another admin.

**Two-factor sign-in:** in the sidebar's **Two-factor sign-in**, confirm your password, scan the QR code with an authenticator app (Google or Microsoft Authenticator, 1Password, Authy…) and type the code it shows. From then on, signing in takes the password and a current code; each code works once, and turning it on signs your account out of other browsers. Turning it off needs the password and a code. Lost the phone? `whalescale admins reset-2fa NAME` on the server turns it off for that account; `whalescale admins list` shows who has it on. (With OIDC, your identity provider handles two-factor.)

## Passkeys

A passkey signs you in with the device's own unlock (a fingerprint, your face, a PIN, or a security key) instead of the password. Windows Hello, macOS and iOS Touch ID or Face ID, Android, password managers such as 1Password, and YubiKeys all work.

- **Adding one:** in the sidebar's **Passkeys**, name it (the console suggests one, like "Windows PC"), confirm your password, and follow the browser's prompt. Add one for each device you sign in from, up to 20.
- **Signing in:** choose **Sign in with a passkey** on the sign-in page. There's no name or password to type: the browser offers the passkeys it has for this server.
- **What it replaces:** a passkey takes the place of both the password and the two-factor code. It's two factors on its own: the device that holds the key, unlocked by your fingerprint, face or PIN.
- **Phishing:** a passkey only works on the server's own address (its `public-url`). A look-alike site can't use it, even if you're fooled into opening one.
- **Requirements:** passkeys need the server's `public-url` to be an `https://` address, because browsers don't offer them on plain `http://` (apart from `localhost`). The sign-in page shows the passkey button only when they can work.
- **Removing one:** use **Remove** next to it in **Passkeys**. Lost a device? `whalescale admins reset-passkeys NAME` on the server removes all of that account's passkeys and signs it out everywhere; `whalescale admins list` shows how many each account has.

Every addition, removal and passkey sign-in is in the audit log.

Pages:

- **Machines:** online state, addresses, OS and routes.
- **Topology:** a from/to matrix showing direct or relayed paths, with latency, as the nodes report it.
- **Users**, **Keys** (pre-auth and API keys) and **Routes** (approve subnets and exit nodes).
- **Access policy:** an editor with live validation and lint warnings.
