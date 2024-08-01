package main

import (
	"context"
	"encoding/gob"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/artemstreltsov/url-shortener/internal/database"
	"github.com/artemstreltsov/url-shortener/internal/handlers"
	"github.com/artemstreltsov/url-shortener/internal/safebrowsing"
)

func init() {
	// Register the database.User type with gob
	gob.Register(&database.User{})
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "database/database.sqlite3"
	}

	db, err := database.NewDB(dbPath)
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}
	defer db.Close()

	if err := safebrowsing.InitSafeBrowsing(); err != nil {
		log.Fatalf("Error initializing Safe Browsing: %v", err)
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