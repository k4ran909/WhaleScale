package main

import (
	"context"
	"flag"
	"os"
	"os/signal"

	"github.com/k4ran909/whalescale/internal/mcp"
	"github.com/k4ran909/whalescale/internal/version"
)

// cmdMCP serves the Model Context Protocol on stdin/stdout, for AI agents.
// Its tools call the admin API with the given key, so a read-only key
// (whalescale apikeys create --scope read) gives a read-only agent.
func cmdMCP(args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	server := fs.String("server", "", "server URL (default: the one this machine uses)")
	apiKeyFile := fs.String("api-key-file", "", "file holding an API key (default: $WS_API_KEY)")
	fs.Parse(args)
	admin, apiKey, err := adminClient(*server, *apiKeyFile)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return mcp.New(admin, apiKey, version.Version).Serve(ctx, os.Stdin, os.Stdout)
}
