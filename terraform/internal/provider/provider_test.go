package provider

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/k4ran909/whalescale/internal/server"
	"github.com/k4ran909/whalescale/internal/store"
	"github.com/k4ran909/whalescale/internal/store/storetest"
)

var factories = map[string]func() (tfprotov6.ProviderServer, error){
	"whalescale": providerserver.NewProtocol6WithError(New("test")()),
}

// TestProvider runs Terraform (or OpenTofu: TF_ACC_TERRAFORM_PATH) against
// a real server. It needs TF_ACC=1.
func TestProvider(t *testing.T) {
	// OpenTofu needs a namespace for the test provider; Terraform's default
	// is the same.
	if os.Getenv("TF_ACC_PROVIDER_NAMESPACE") == "" {
		t.Setenv("TF_ACC_PROVIDER_NAMESPACE", "hashicorp")
	}
	ctx := context.Background()
	st, err := store.Open(ctx, storetest.DSN(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	hs := httptest.NewUnstartedServer(nil)
	hs.Start()
	t.Cleanup(hs.Close)
	srv, err := server.New(st, server.Config{PublicURL: hs.URL, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	hs.Config.Handler = srv.Handler()
	_, key, _ := st.CreateAPIKey(ctx, time.Hour)
	t.Setenv("WHALESCALE_SERVER", hs.URL)
	t.Setenv("WS_API_KEY", key)

	// A machine advertising a subnet, for the route approval.
	st.CreateUser(ctx, "ann")
	ids, _ := st.SeedNodes(ctx, []string{"ann"}, 1, "")
	st.SetAdvertisedRoutes(ctx, ids[0], []netip.Prefix{netip.MustParsePrefix("10.1.0.0/24")})

	config := func(policy string) string {
		return fmt.Sprintf(`
resource "whalescale_user" "ops" {
  name = "ops"
}

resource "whalescale_policy" "main" {
  policy = %s
}

resource "whalescale_preauth_key" "servers" {
  user       = whalescale_user.ops.name
  reusable   = true
  expiration = "48h"
}

resource "whalescale_route_approval" "office" {
  machine = "ann-0"
  prefix  = "10.1.0.0/24"
}

data "whalescale_machines" "all" {
  depends_on = [whalescale_user.ops]
}
`, policy)
	}
	policyV1 := `jsonencode({
    groups = { "group:ops" = ["ops"] }
    acls   = [{ action = "accept", src = ["group:ops"], dst = ["*:22"] }]
  })`
	// The same kind of policy as a heredoc with its own formatting: the
	// plan after applying must be empty (no spurious diffs).
	policyV2 := "<<-EOT\n    {\n      \"groups\": {\"group:ops\": [\"ops\"]},\n      \"acls\": [ {\"action\": \"accept\", \"src\": [\"group:ops\"], \"dst\": [\"*:22,443\"]} ]\n    }\n  EOT"

	activePolicy := func(want string) resource.TestCheckFunc {
		return func(*terraform.State) error {
			p, _, _ := st.Setting(ctx, "policy")
			if !strings.Contains(p, want) {
				return fmt.Errorf("policy in the database = %s, want it to contain %s", p, want)
			}
			return nil
		}
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: config(policyV1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("whalescale_user.ops", "id", "ops"),
					resource.TestCheckResourceAttrSet("whalescale_preauth_key.servers", "key"),
					resource.TestCheckResourceAttr("whalescale_preauth_key.servers", "reusable", "true"),
					resource.TestCheckResourceAttr("data.whalescale_machines.all", "machines.#", "1"),
					resource.TestCheckResourceAttr("data.whalescale_machines.all", "machines.0.name", "ann-0"),
					activePolicy(`"*:22"`),
					func(*terraform.State) error {
						keys, _ := st.ListPreAuthKeys(ctx)
						if len(keys) != 1 || keys[0].User != "ops" || !keys[0].Reusable {
							return fmt.Errorf("pre-auth keys = %+v", keys)
						}
						routes, _ := st.ListRoutes(ctx)
						if len(routes) != 1 || !routes[0].Approved {
							return fmt.Errorf("routes = %+v", routes)
						}
						return nil
					},
				),
			},
			{
				Config: config(policyV2),
				Check:  activePolicy(`"*:22,443"`),
			},
			{
				ResourceName:      "whalescale_user.ops",
				ImportState:       true,
				ImportStateId:     "ops",
				ImportStateVerify: true,
			},
		},
		CheckDestroy: func(*terraform.State) error {
			if users, _ := st.ListUsers(ctx); len(users) != 1 || users[0].Name != "ann" {
				return fmt.Errorf("users after destroy = %+v", users)
			}
			// The key was expired, then removed along with its user.
			for _, k := range mustKeys(st) {
				if k.ExpiresAt.After(time.Now()) {
					return fmt.Errorf("pre-auth key still valid: %+v", k)
				}
			}
			if routes, _ := st.ListRoutes(ctx); len(routes) != 1 || routes[0].Approved {
				return fmt.Errorf("route still approved: %+v", routes)
			}
			// The policy stays: Whalescale always has one.
			return activePolicy(`"*:22,443"`)(nil)
		},
	})
}

func mustKeys(st *store.Store) []store.PreAuthKey {
	keys, _ := st.ListPreAuthKeys(context.Background())
	return keys
}
