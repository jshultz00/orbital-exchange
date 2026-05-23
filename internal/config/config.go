// Package config holds runtime configuration loaded from env vars with sane defaults.
package config

import (
	"os"
)

type Config struct {
	Addr   string // listen address, e.g. ":3000"
	DBPath string // path to the SQLite file
}

func Load() Config {
	return Config{
		Addr:   envOr("ORBITAL_ADDR", ":3000"),
		DBPath: envOr("ORBITAL_DB", "data/orbital.sqlite"),
	}
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}
