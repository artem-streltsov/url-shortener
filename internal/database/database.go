package database

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

type DB struct {
	*sql.DB
}

func NewDB(dbPath string) (*DB, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("error opening database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("error connecting to database: %w", err)
	}

	return &DB{db}, nil
}

func (db *DB) InsertURL(url, key string) error {
	stmt, err := db.Prepare("INSERT INTO urls (url, key) VALUES (?, ?)")
	if err != nil {
		return fmt.Errorf("error preparing statement: %w", err)
	}
	defer stmt.Close()

	_, err = stmt.Exec(url, key)
	if err != nil {
		return fmt.Errorf("error inserting URL: %w", err)
	}

	return nil
}

func (db *DB) GetURL(key string) (string, error) {
	var url string
	err := db.QueryRow("SELECT url FROM urls WHERE key = ?", key).Scan(&url)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("no URL found for key: %s", key)
		}
		return "", fmt.Errorf("error querying URL: %w", err)
	}
	return url, nil
}

func (db *DB) GetAllURLs() ([]struct{ URL, Key string }, error) {
	rows, err := db.Query("SELECT url, key FROM urls")
	if err != nil {
		return nil, fmt.Errorf("error querying URLs: %w", err)
	}
	defer rows.Close()

	var urls []struct{ URL, Key string }
	for rows.Next() {
		var url, key string
		if err := rows.Scan(&url, &key); err != nil {
			return nil, fmt.Errorf("error scanning row: %w", err)
		}
		urls = append(urls, struct{ URL, Key string }{url, key})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	return urls, nil
}