# Web console

The dashboard served by your server: signing in, your team's accounts, passkeys, two-factor sign-in, settings you can change while the server runs, and search.

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

## Team

**Users → Team** lists the people who can sign in to the console. **Add team member** takes a name and shows a generated password once: give it to them privately, and they change it (and can add a passkey or two-factor sign-in) after signing in. Each member also gets a user of the same name for their own machines. **Remove** signs a member out everywhere and deletes their account; you can't remove yourself or the last account. Both are in the audit log. (`whalescale admins create NAME` and `whalescale admins delete NAME` on the server do the same.)

## Settings

**Server → Settings** changes these while the server runs, for every machine within seconds, with no config file edit or restart:

| Setting | What it does | Config file key |
|---|---|---|
| Flow logs | Machines report who talked to whom, on which port, and refused attempts ([Flow logs](monitoring.md#flow-logs)). | `flow-logs` |
| Post-quantum protection | ML-KEM-768 keys on top of WireGuard ([Post-quantum protection](security.md#post-quantum-protection)). | `post-quantum` |
| Gateway | The domain machines' web apps are published under; empty turns the gateway off ([Gateway](gateway.md)). It still needs a wildcard DNS record `*.DOMAIN` pointing at the server. | `gateway-domain` |

The config file gives each its starting value. A value saved in the console is kept in the database and overrides the config file (servers sharing a database pick it up within 30 seconds); **Use the config file's value** next to it goes back. The admin API has the same as `GetSettings` and `UpdateSetting`.

The page also shows **MagicDNS** (every machine is reachable at `NAME.` plus the `dns-suffix`, `whale.internal` by default) and **SSH**: how many machines run the mesh SSH server (`ws up --ssh`), how many SSH rules the [access policy](access-policy.md) has, and how many of them record sessions ([SSH](ssh.md)).

## Search and help

Press **Ctrl K** (**⌘K** on a Mac), or **/**, anywhere in the console, or click **Search** at the top: type a few letters to jump to a page, a setting, an action such as "add a device", or a guide. Arrow keys choose and Enter opens. **Server → Help** lists every console page and every guide, linked, with its own search.

## Pages

- **Machines:** online state, addresses, OS and routes.
- **Topology:** a from/to matrix showing direct or relayed paths, with latency, as the nodes report it.
- **Users** (and the **Team** who can sign in), **Keys** (pre-auth and API keys) and **Routes** (approve subnets and exit nodes).
- **Access policy:** an editor with live validation and lint warnings.
- **Settings** and **Help**, above.
