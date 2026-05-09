package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/moolen/FCKTLS/pkg/fcktls"
)

func main() {
	var (
		target   = flag.String("target", "", "target executable basename to match, e.g. curl")
		capture  = flag.Bool("capture", false, "capture plaintext application data via SSL_read/SSL_write")
		cacheDir = flag.String("cache-dir", "", "artifact directory, defaults to ~/.cache/fcktls")
	)
	flag.Parse()

	cfg, err := fcktls.NewConfig(*target, *capture, *cacheDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	daemon, err := fcktls.NewDaemon(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := daemon.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
