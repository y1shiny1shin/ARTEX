package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/y1shiny1shin/ryagent/bff/internal/artex"
	"github.com/y1shiny1shin/ryagent/bff/internal/conductor"
	"github.com/y1shiny1shin/ryagent/bff/internal/httpapi"
	"github.com/y1shiny1shin/ryagent/bff/internal/store"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	addr := env("RYAGENT_ADDR", ":8788")
	dataDir := env("RYAGENT_DATA", "./data")
	ownerPassword := os.Getenv("RYAGENT_OWNER_PASSWORD")
	if ownerPassword == "" {
		log.Fatal("RYAGENT_OWNER_PASSWORD is required (device pairing password)")
	}
	statePath := filepath.Join(dataDir, "state.json")
	st, err := store.Open(statePath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	ac := artex.New(
		env("ARTEX_BASE_URL", "http://127.0.0.1:8787"),
		os.Getenv("ARTEX_TOKEN"),
		env("ARTEX_USERNAME", "ARTEX"),
		os.Getenv("ARTEX_PASSWORD"),
	)
	ds := conductor.New(
		env("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
		os.Getenv("DEEPSEEK_API_KEY"),
		env("DEEPSEEK_MODEL", "deepseek-chat"),
	)
	srv := httpapi.New(st, ac, ds, ownerPassword)
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("RyAgent BFF listening on %s (data=%s, artex=%s, deepseek=%v)", addr, statePath, ac.BaseURL(), ds.Configured())
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("serve: %v", err)
	}
}
