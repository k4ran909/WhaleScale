terraform {
  required_providers {
    whalescale = {
      source = "k4ran909/whalescale"
    }
  }
}

# Or set $WHALESCALE_SERVER and $WS_API_KEY.
provider "whalescale" {
  server_url = "https://ws.example.com"
}

resource "whalescale_user" "ops" {
  name = "ops"
}

resource "whalescale_policy" "main" {
  policy = jsonencode({
    groups = { "group:ops" = ["ops"] }
    acls = [
      { action = "accept", src = ["group:ops"], dst = ["*:*"] },
      { action = "accept", src = ["*"], dst = ["node:nas:445"] },
    ]
    tests = [
      { src = "ops", accept = ["node:nas:22"] },
    ]
  })
}

# A key for provisioning servers; pass it to 'ws login --authkey'.
resource "whalescale_preauth_key" "servers" {
  user       = whalescale_user.ops.name
  reusable   = true
  expiration = "720h"
}

output "server_auth_key" {
  value     = whalescale_preauth_key.servers.key
  sensitive = true
}

resource "whalescale_route_approval" "office" {
  machine = "office-router"
  prefix  = "192.168.1.0/24"
}

data "whalescale_machines" "ops" {
  user = whalescale_user.ops.name
}

output "ops_addresses" {
  value = { for m in data.whalescale_machines.ops.machines : m.name => m.ipv4 }
}
