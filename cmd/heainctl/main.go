// Command heainctl is the command line for heain-core's Config API
// (/v1/admin/*), used with an admin certificate. See heainctl help.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/heainframework/heainctl/internal/ctl"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := ctl.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
