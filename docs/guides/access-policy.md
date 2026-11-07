# Access policy

Who can reach what: rules, groups, temporary access, device posture, device limits, policy from Git, tests and explanations.

Without one, every node can reach every other node. Edit it in the console, or point `policy:` at a JSON file (the server reloads it within 5 s; an invalid file keeps the previous policy). Receiving nodes drop anything not allowed. Replies to a node's own connections are always let back in.

```json
{
  "groups": { "group:admins": ["karan"] },
  "acls": [
    { "action": "accept", "src": ["group:admins"], "dst": ["*:*"] },
    { "action": "accept", "src": ["guest"], "dst": ["node:nas:445,8000-8100"] },
    { "action": "accept", "src": ["karan"], "dst": ["192.168.1.0/24:*"] }
  ]
}
```

Selectors are `*`, a user, `group:NAME`, `node:NAME` or a CIDR. A CIDR destination grants access through subnet routers that serve it. A user or node selector grants that device only, not the networks behind it.


## Temporary access

Instead of standing access to sensitive machines, let people ask for it when they need it:

```json
"access_requests": [
  { "src": ["group:eng"], "dst": ["node:prod-db:5432"], "max_duration": "4h" },
  { "src": ["group:oncall"], "dst": ["node:prod-db:22"], "max_duration": "1h", "auto_approve": true }
]
```

```bash
ws access list                                             # what you may request, your requests
ws access request node:prod-db:5432 --for 2h --reason "migrating orders table" --wait
```

An admin approves or denies it on the console's **Access requests** page, or with `whalescale access list | approve ID | deny ID`. Access starts at approval and ends by itself when the time is up (`revoke` ends it early). `auto_approve` rules are for break-glass access: granted at once, still audited. The grant covers only the machine that asked and only the requested ports (a subset of the rule's ports is fine). Requests left undecided expire after 24 hours. Every step is in the audit log, and `explain` names the grant when one is what allows a connection.

## Device posture

Require machines to meet conditions before a rule lets them in:

```json
"postures": {
  "posture:current": ["client_version >= 0.4.0", "os in [linux, macos, windows]"],
  "posture:win11":   ["os == windows", "os_version >= 10.0.22000"]
},
"acls": [
  { "action": "accept", "src": ["group:eng"], "dst": ["node:prod-db:5432"], "src_posture": ["posture:current"] }
]
```

- **Attributes:** machines report `os`, `os_version` (Windows build, macOS version, or the Linux distribution's `VERSION_ID`) and `client_version`. The console's Machines page shows them.
- **Operators:** `==`, `!=`, `in [..]`, `not in [..]`, and `>=` `>` `<=` `<`. The last four compare versions numerically, part by part.
- **Effect:** a machine that fails a posture is left out of that rule, including peer visibility. A machine that doesn't report an attribute fails every condition on it.
- **Applies to** ACLs and SSH rules. Network (CIDR) sources aren't machines and aren't checked.
- **Explain** names the failing condition, e.g. "old-laptop fails posture:current: its client_version is 0.3.9, not >= 0.4.0".

## Device limits

Cap how many machines each person can add:

```json
"device_limits": { "*": 5, "group:eng": 10, "ann": 20 }
```

A user's own entry wins (even if it's lower than a group's); otherwise the most generous of their groups applies, then `"*"`. Without a matching entry there is no limit. Registrations over the limit are refused with a message saying why, and recorded in the audit log. Machines already registered are never removed. The console's Users page shows each person's count against their limit.

## Policy from a Git repository

Keep the policy in Git and review changes like code. Point the server at the file's raw URL on a branch:

```yaml
policy-url: https://raw.githubusercontent.com/you/infra/main/whalescale/policy.json
policy-url-token-file: /etc/whalescale/repo-token       # private repositories
policy-webhook-secret-file: /etc/whalescale/hook-secret # optional push webhook
```

- **How updates arrive:** the server polls with ETags every `policy-sync-interval` (default 1 minute). A push webhook to `POST /policy/sync` applies changes at once; it verifies GitHub and Gitea HMAC signatures and the GitLab token.
- **Bad versions are refused:** a version that doesn't parse, or fails its own `tests`, is refused, and the previous policy stays in force.
- **Outages:** the last good copy is cached, so a restart while the repository is unreachable still enforces it. With no copy at all, the server refuses to start rather than run without your policy.
- **Read-only elsewhere:** the console shows the policy as read-only, with the revision, last sync time and any sync error.

## Policy tests

Pin down intent with `tests`. A policy that fails its own tests is refused when saved in the console, when a policy file is reloaded, and by `whalescale policy check`. At server startup failures are only logged, so an outdated test can't lock anyone out.

```json
"tests": [
  { "src": "guest", "accept": ["node:nas:445"], "deny": ["karan:22"] },
  { "src": "karan", "accept": ["192.168.1.10:443"] }
]
```

`src` is a user, `node:NAME` or an IP. `accept` and `deny` entries are `<user|node:NAME|IP>:<port>`.

## Why can't A reach B?

```bash
$ whalescale policy explain guest karan:22
guest → karan port 22: DENIED  (using the policy saved in the console)
  - acls[1]: guest → karan:80,443 covers guest → karan but only ports 80,443
  - acls[0]: group:admins → *:* would allow it for sources group:admins
  - replies to connections karan opens to guest are still allowed
```

The console's Access policy page has the same "Explain access" panel, and it evaluates your unsaved edits. For subnet addresses, explain also warns when the policy allows something that no approved router serves.
