package main

import (
	"context"
	"encoding/gob"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/artemstreltsov/url-shortener/internal/database"
	"github.com/artemstreltsov/url-shortener/internal/handlers"
	"github.com/artemstreltsov/url-shortener/internal/safebrowsing"
	"github.com/joho/godotenv"
)

func init() {
	gob.Register(&database.User{})
}

func main() {
	godotenv.Load() // Load .env file if it exists, ignore error if it doesn't

	port := getEnvWithDefault("PORT", "8080")

	dbPath := getEnvWithDefault("DB_PATH", "database/database.sqlite3")

	dbPath = os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "database/database.sqlite3"
	}

	// Touch the database file if it doesn't exist
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		dir := filepath.Dir(dbPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("Error creating directory for database: %v", err)
		}
		file, err := os.Create(dbPath)
		if err != nil {
			log.Fatalf("Error creating database file: %v", err)
		}
		file.Close()
	}

	db, err := database.NewDB(dbPath)
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}
	defer db.Close()

	if err := safebrowsing.InitSafeBrowsing(); err != nil {
		log.Printf("Error initializing Safe Browsing: %v", err)
	}
	defer safebrowsing.Close()

	handler := handlers.NewHandler(db)

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: handler.Routes(),
	}

	go func() {
		log.Printf("Starting server at :%s", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Error starting server: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exiting")
}

func getEnvWithDefault(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}
