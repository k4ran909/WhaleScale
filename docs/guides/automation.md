# Automation

Manage Whalescale from AI agents (MCP) and from Terraform or OpenTofu.

- [AI agents (MCP)](#ai-agents-mcp)
- [Terraform / OpenTofu](#terraform--opentofu)

## AI agents (MCP)

`ws mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server, so AI assistants can look after the network. Agents can:
- list machines, users and routes;
- read and check the access policy, and explain why one machine can or can't reach another;
- read connection and audit logs;
- with an admin key, apply policies, approve routes and access requests, and remove machines.

Give it a **read-only** key unless the agent should make changes:

```bash
whalescale apikeys create --scope read     # or "Create read-only key" in the console
```

Claude Desktop (or any client that reads an `mcpServers` config):

```json
{
  "mcpServers": {
    "whalescale": {
      "command": "ws",
      "args": ["mcp", "--server", "https://ws.example.com"],
      "env": { "WS_API_KEY": "wsapi-..." }
    }
  }
}
```

Claude Code:

```bash
claude mcp add whalescale --env WS_API_KEY=wsapi-... -- ws mcp --server https://ws.example.com
```

The key's scope is enforced by the server, not just by the tool list. A read-only key doesn't see the change tools, and calls to them are refused anyway. Everything an agent changes is recorded in the audit log under its key.

## Terraform / OpenTofu

The provider in `terraform/` manages the network as code:
- **Resources:** `whalescale_policy`, `whalescale_user`, `whalescale_preauth_key` (its secret is a sensitive attribute) and `whalescale_route_approval`.
- **Data source:** `whalescale_machines`.
- **Example:** see [terraform/examples/main.tf](../../terraform/examples/main.tf).

```hcl
resource "whalescale_policy" "main" {
  policy = jsonencode({
    groups = { "group:ops" = ["ops"] }
    acls   = [{ action = "accept", src = ["group:ops"], dst = ["*:*"] }]
  })
}
```

- **Credentials:** an admin API key (`WS_API_KEY`) and the server URL (`WHALESCALE_SERVER`), or `server_url` / `api_key` in the provider block.
- **Validation:** the server refuses a policy that's invalid or fails its own `tests`, so a bad change fails at `apply`.
- **No formatting noise:** formatting differences never show up as changes.
- **Destroy keeps the policy:** destroying `whalescale_policy` leaves the policy in force, because falling back to allow-all would open the network.
- **Install:** until the provider is published to a registry, build it with `make terraform` (or `cd terraform && go build`) and point Terraform at it with a `dev_overrides` block in `~/.terraformrc`.
- **Tested both ways:** the acceptance tests run real Terraform in CI and OpenTofu locally, against an in-process server.
