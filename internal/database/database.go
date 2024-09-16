package database

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type DB struct {
	*sql.DB
}

type User struct {
	ID       int64
	Username string
	Email    string
	Password string
}

type URL struct {
	ID        int64
	UserID    int64
	URL       string
	Key       string
	CreatedAt time.Time
	Clicks    int
	Password  string
	QRCode    string
}

func NewDB(dbPath string) (*DB, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("error opening database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("error connecting to database: %w", err)
	}

	if err := initSchema(db); err != nil {
		return nil, fmt.Errorf("error initializing schema: %w", err)
	}

	return &DB{db}, nil
}

func initSchema(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		email TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL
	);

    CREATE TABLE IF NOT EXISTS urls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        url TEXT NOT NULL,
        key TEXT UNIQUE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        clicks INTEGER DEFAULT 0,
        password TEXT,
        qr_code TEXT,  -- Add this line to store the QR code in base64 format
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
	`

	_, err := db.Exec(schema)
	return err
}

func (db *DB) CreateUser(username, email, password string) (*User, error) {
	stmt, err := db.Prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)")
	if err != nil {
		return nil, fmt.Errorf("error preparing statement: %w", err)
	}
	defer stmt.Close()

	result, err := stmt.Exec(username, email, password)
	if err != nil {
		return nil, fmt.Errorf("error inserting user: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("error getting last insert ID: %w", err)
	}

	return &User{ID: id, Username: username, Email: email, Password: password}, nil
}

func (db *DB) GetUserByUsername(username string) (*User, error) {
	var user User
	err := db.QueryRow("SELECT id, username, email, password FROM users WHERE username = ?", username).Scan(&user.ID, &user.Username, &user.Email, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("error querying user: %w", err)
	}
	return &user, nil
}

func (db *DB) InsertURL(url, key string, userID int64, password string, qrCode string) error {
	stmt, err := db.Prepare("INSERT INTO urls (url, key, user_id, password, qr_code) VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		return fmt.Errorf("error preparing statement: %w", err)
	}
	defer stmt.Close()

	_, err = stmt.Exec(url, key, userID, password, qrCode) // Add qrCode as an argument
	if err != nil {
		return fmt.Errorf("error inserting URL: %w", err)
	}

	return nil
}

func (db *DB) GetURL(key string) (*URL, error) {
	var url URL
	err := db.QueryRow("SELECT id, user_id, url, key, created_at, clicks, password FROM urls WHERE key = ?", key).Scan(&url.ID, &url.UserID, &url.URL, &url.Key, &url.CreatedAt, &url.Clicks, &url.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no URL found for key: %s", key)
		}
		return nil, fmt.Errorf("error querying URL: %w", err)
	}
	return &url, nil
}

func (db *DB) GetURLsByUserID(userID int64) ([]URL, error) {
	rows, err := db.Query("SELECT id, user_id, url, key, created_at, clicks, password FROM urls WHERE user_id = ?", userID)
	if err != nil {
		return nil, fmt.Errorf("error querying URLs: %w", err)
	}
	defer rows.Close()

	var urls []URL
	for rows.Next() {
		var url URL
		if err := rows.Scan(&url.ID, &url.UserID, &url.URL, &url.Key, &url.CreatedAt, &url.Clicks, &url.Password); err != nil {
			return nil, fmt.Errorf("error scanning row: %w", err)
		}
		urls = append(urls, url)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	return urls, nil
}

func (db *DB) IncrementClicks(urlID int64) error {
	_, err := db.Exec("UPDATE urls SET clicks = clicks + 1 WHERE id = ?", urlID)
	if err != nil {
		return fmt.Errorf("error incrementing clicks: %w", err)
	}
	return nil
}

func (db *DB) UpdateURL(id int64, url string, password string) error {
	_, err := db.Exec("UPDATE urls SET url = ?, password = ? WHERE id = ?", url, password, id)
	if err != nil {
		return fmt.Errorf("error updating URL: %w", err)
	}
	return nil
}

func (db *DB) DeleteURL(id int64) error {
	_, err := db.Exec("DELETE FROM urls WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("error deleting URL: %w", err)
	}
	return nil
}

func (db *DB) GetURLByID(id int64) (*URL, error) {
	var url URL
	err := db.QueryRow("SELECT id, user_id, url, key, created_at, clicks, password, qr_code FROM urls WHERE id = ?", id).Scan(
		&url.ID, &url.UserID, &url.URL, &url.Key, &url.CreatedAt, &url.Clicks, &url.Password, &url.QRCode)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no URL found for id: %d", id)
		}
		return nil, fmt.Errorf("error querying URL: %w", err)
	}
	return &url, nil
}
