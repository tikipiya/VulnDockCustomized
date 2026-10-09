package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"VulnDock/internal/auth"
	"VulnDock/internal/httpapi"
	"VulnDock/internal/migrate"
	"VulnDock/internal/service"
	"VulnDock/internal/static"
	"VulnDock/internal/store/sqlite"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		runMigrate(os.Args[2:])
		return
	}
	runServer()
}

func runMigrate(args []string) {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	from := fs.String("from-json", "", "path to legacy reports.json")
	force := fs.Bool("force", false, "import even if database has reports")
	dataDir := fs.String("data-dir", defaultDataDir(), "data directory")
	_ = fs.Parse(args)

	jsonPath := *from
	if jsonPath == "" {
		path, err := migrate.DefaultLegacyJSONPath()
		if err != nil {
			log.Fatal(err)
		}
		jsonPath = path
	}

	store, err := sqlite.Open(*dataDir)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	if err := migrate.ImportJSON(context.Background(), store, jsonPath, *force); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("imported reports from %s into %s\n", jsonPath, store.DBPath())
}

func runServer() {
	bind := envOr("VULNDOCK_BIND", "127.0.0.1:8080")
	dataDir := envOr("VULNDOCK_DATA_DIR", defaultDataDir())
	staticDir := strings.TrimSpace(os.Getenv("VULNDOCK_STATIC_DIR"))
	staticHandler, staticSource := resolveStaticHandler(staticDir)

	store, err := sqlite.Open(dataDir)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	reports := &service.Reports{Store: store}
	prompts := &service.Prompts{Store: store}
	backupSvc := &service.Backup{Store: store}
	authSvc := &auth.Service{Store: store}
	setupToken := strings.TrimSpace(os.Getenv("VULNDOCK_SETUP_TOKEN"))
	if setupToken == "" {
		generated, err := auth.RandomHex(16)
		if err != nil {
			log.Fatal(err)
		}
		setupToken = generated
		tokenPath := filepath.Join(dataDir, ".setup-token")
		if err := os.WriteFile(tokenPath, []byte(setupToken+"\n"), 0o600); err != nil {
			log.Printf("VULNDOCK_SETUP_TOKEN is unset and could not write %s: %v", tokenPath, err)
		} else {
			log.Printf("VULNDOCK_SETUP_TOKEN is unset; set the env var or read the token from %s (mode 0600) for remote setup", tokenPath)
		}
	}

	srv := httpapi.New(
		authSvc, reports, prompts, backupSvc, staticHandler, dataDir, setupToken,
		envBool("VULNDOCK_TRUST_LOOPBACK_SETUP", false),
		envBool("VULNDOCK_SECURE_COOKIES", false),
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.RunBackgroundMaintenance(ctx)
	_ = reports.PurgeExpired(ctx)

	httpServer := &http.Server{
		Addr:              bind,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("VulnDockCustomized listening on http://%s (data: %s, static: %s)", bind, dataDir, staticSource)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = httpServer.Shutdown(shutdownCtx)
}

func defaultDataDir() string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".local", "share", "vulndock-customized")
	}
	return "./data"
}

func resolveStaticHandler(staticDir string) (http.Handler, string) {
	if staticDir != "" {
		return httpapi.SPAFileServer(staticDir), staticDir
	}
	if embedded, err := static.SPAHandler(); err == nil {
		return embedded, "embedded"
	}
	fallback := defaultStaticDir()
	if _, err := os.Stat(fallback); err == nil {
		return httpapi.SPAFileServer(fallback), fallback
	}
	log.Fatal("static UI unavailable: set VULNDOCK_STATIC_DIR or run make build")
	return nil, ""
}

func defaultStaticDir() string {
	if _, err := os.Stat("frontend/dist"); err == nil {
		return "frontend/dist"
	}
	exe, err := os.Executable()
	if err != nil {
		return "frontend/dist"
	}
	return filepath.Join(filepath.Dir(exe), "frontend", "dist")
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if v == "" {
		return fallback
	}
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}
