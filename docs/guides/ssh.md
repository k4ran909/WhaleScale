# SSH over the mesh

Log in to your machines without managing SSH keys: your mesh identity is the credential, and the access policy decides who may log in where, and as which local user.

```json
"ssh": [
  { "action": "accept", "src": ["group:admins"], "dst": ["node:nas"], "users": ["root", "$user"], "record": true }
]
```

```bash
sudo ws up --ssh              # on the server machine (Linux or macOS)
ws ssh karan@nas              # from any machine; or plain: ssh karan@nas.whale.internal
```

- **Identity:** the source mesh address identifies the person. WireGuard ties every peer's addresses to its key, so they can't be spoofed (the same model Tailscale SSH uses).
- **Local users:** `"$user"` means "your own username on the mesh". An SSH rule also opens TCP 22 from its sources, and nothing else.
- **No host-key prompts:** each machine's SSH host key is distributed in the network map. `ws ssh` hands it to your `ssh` client.
- **Recording:** with `"record": true`, session output (never keystrokes) is recorded in asciinema format and uploaded to the server. If the upload fails, a copy is kept on the machine. Admins can view, download or delete recordings in the console (SSH recordings) or with `whalescale recordings list | delete ID`; downloads play with `asciinema play`. Deleting one is recorded in the audit log. Each machine may store `recording-quota-mb` of recordings (1024 by default). Past that its new recordings are refused, never its old ones deleted, so a machine someone took over can't flush the recordings of how they got in. `recording-retention` (say `2160h` for 90 days) deletes old recordings; by default they're kept.
- **What's supported:** shells, commands, PTYs and window resizing. Not SFTP, port forwarding, or a Windows SSH server yet.
