# CI on Woodpecker (self-hosted)

The pipelines in `.woodpecker/` do what the GitHub Actions workflows do, on a
[Woodpecker CI](https://woodpecker-ci.org) server you run yourself, for
example on Dokploy. The code stays on GitHub: Woodpecker gets push and pull
request webhooks and reports a ✓/✗ check on each commit and pull request
through GitHub's API, so it works while GitHub Actions is unavailable.

| Pipeline | Runs on | What |
|---|---|---|
| `ci.yaml` | pushes to `main`, pull requests | generated code is current, `go vet`, race tests on SQLite and PostgreSQL, cross-compiling |
| `console.yaml` | same | `web/dist` matches its sources |
| `terraform.yaml` | same | provider acceptance tests |
| `helm.yaml` | same | chart lint and render |
| `vuln.yaml` | same, plus nightly | `govulncheck` on both modules |
| `installer.yaml` | same | the Windows installer builds |
| `packages.yaml` | same | the `.deb` and `.rpm` packages build, and install, upgrade and uninstall on Debian and Fedora |
| `android.yaml` | same, when the app or Go code changes | the Go core with gomobile and a debug APK ([Android app](../guides/android.md)) |
| `release.yaml` | `v*` tags | archives, installers, `.deb`/`.rpm` packages and signed checksums on GitHub Releases; images on `ghcr.io` |

What GitHub Actions did that this doesn't: build artifacts aren't kept per
run (the release pipeline publishes the real ones). Like Actions here, tests
run on Linux only.

## 1. GitHub OAuth app

GitHub → Settings → Developer settings → OAuth Apps → New OAuth App:

- **Homepage URL:** `https://ci.example.com` (the domain you'll give Woodpecker)
- **Authorization callback URL:** `https://ci.example.com/authorize`

Note the client ID and generate a client secret.

## 2. Deploy on Dokploy

1. **Create a Compose app** from [`deploy/woodpecker/docker-compose.yml`](../../deploy/woodpecker/docker-compose.yml): point it at this repository and that path, or paste the file.
2. **Environment:** set these in the app's environment.

   ```
   WOODPECKER_HOST=https://ci.example.com
   WOODPECKER_GITHUB_CLIENT=<client ID>
   WOODPECKER_GITHUB_SECRET=<client secret>
   WOODPECKER_AGENT_SECRET=<output of: openssl rand -hex 32>
   WOODPECKER_ADMIN=<your GitHub username>
   ```
3. **Domain:** add `ci.example.com` on service `woodpecker-server`, port `8000`, with HTTPS. Port 9000 (agents) stays inside the compose network.
4. **Deploy**, open `https://ci.example.com` and sign in with GitHub.

Without Dokploy, the same file works with `docker compose up -d` behind any reverse proxy.

## 3. Turn on the repository

In Woodpecker: **Add repository** → `k4ran909/WhaleScale` → enable. Then in its settings:

- **Project → Require approval for:** pull requests from forks. The repository is public, and pipelines run on your server: approve fork pull requests after reading them.
- **Project → Timeout:** 60 minutes (race tests on a small server are slow).
- **Project → Trusted → Volumes:** on (admins only). The pipelines keep Go's module and build caches and npm's cache in named Docker volumes (`woodpecker-go-mod`, `woodpecker-go-build`, `woodpecker-npm`, and for the Android app `woodpecker-android` and `woodpecker-gradle`), so runs don't download everything again. Without this setting Woodpecker refuses to start them. Leave **Network** and **Security** off.
- **Secrets → Add** `github_token`: a classic personal access token (GitHub → Settings → Developer settings → Tokens (classic)) with the `repo` and `write:packages` scopes. Events: **Push** and **Tag** only, never Pull Request. The release pipeline uses it for GitHub Releases and for pushing images to `ghcr.io`.
- **Secrets → Add** `release_signing_key`: the release key's private half, the one line in the file `go run ./internal/release/tool keygen -out FILE` wrote. Events: **Tag** only. The release pipeline signs `checksums.txt` with it (`checksums.txt.minisig`), and the tray's updater refuses releases without that signature, so a release without the secret fails rather than shipping unsigned. Its public half is `packaging/release-key.pub` and `internal/release.PublicKey`. Keep a copy of the private key somewhere safe, such as a password manager: if it's lost, a new key means a release whose tray can't update itself, so people install that one by hand.
- **Cron → Add** a job named `nightly`, branch `main`, schedule `0 3 * * *`. It runs `vuln.yaml` so a new advisory shows up even on quiet days.

## Notes

- **One agent, this host's Docker.** Steps run as containers through the mounted Docker socket. That's normal for Woodpecker, but it means a pipeline that gets a privileged container controls the host. Only the image-build plugin is allowed one (`WOODPECKER_PLUGINS_PRIVILEGED`), and the approval setting above keeps strangers' code from running unreviewed. Don't run other untrusted workloads on the same Docker host.
- **Capacity.** `WOODPECKER_MAX_WORKFLOWS=3` runs three pipelines at once. The race tests want about 2 CPU cores and 3 GB of RAM; lower it on a small server.
- **Releases if GitHub limits more than Actions.** If the account restrictions also block the API, `publish release` and the image push fail with 403. Try a test tag first.
- **Trusting volumes has a cost.** With it on, a pipeline file may mount any volume, including the host's Docker socket, which means control of the host. That's why fork pull requests need your approval: before approving one, check whether it changes `.woodpecker/` or `scripts/ci/`. Your own pushes are unaffected.
- **Caches:** downloads are retried (`scripts/ci/retry.sh`), and the caches are safe to share between runs. To start fresh: `docker volume rm woodpecker-go-mod woodpecker-go-build woodpecker-npm woodpecker-android woodpecker-gradle` on the agent's host.
- **Shell variables in pipelines.** Woodpecker replaces `$VAR` in commands before running them, so scripts with variables live in `scripts/ci/` rather than inline.
- **When GitHub Actions comes back**, both systems will run on every push. Disable the repository in Woodpecker, or delete `.github/workflows/`, to keep one.
