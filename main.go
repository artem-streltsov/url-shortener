package main

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"log"
	"net/http"
    "encoding/json"
    "strings"

	_ "modernc.org/sqlite"
)

var DB *sql.DB
const base62Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

type URL struct {
    URL string `json:"url"`
    Key string `json:"key"`
}

func defaultHandler(w http.ResponseWriter, r *http.Request) {
    sql := "SELECT url, key FROM urls"
    rows, err := DB.Query(sql)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    var response string
    for rows.Next() {
        var url string
        var key string
        err = rows.Scan(&url, &key)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        response += fmt.Sprintf("url: %s, key: %s\n", url, key)
    }

    if err = rows.Err(); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    fmt.Fprintf(w, response)
}

func encodeBytesToBase62(input []byte) string {
    result := make([]byte, 0, 10)
    for _, b := range input {
        result = append(result, base62Chars[b%62])
    }
    return string(result)
}

func generateKey(url string) string {
    hash := sha256.Sum256([]byte(url))
    key := encodeBytesToBase62(hash[:])
    return key
}

// returns number of affected rows and error
func insertRow(url string, key string) (int, error) {
    sql := "INSERT INTO urls (url, key) VALUES (?, ?)"
    result, err := DB.Exec(sql, url, key)
    if err != nil {
        return 0, err
    }

    rowsAffected, err := result.RowsAffected()
    if err != nil {
        return 0, err
    }

    return int(rowsAffected), nil
}

func newURL(w http.ResponseWriter, r *http.Request) {
    var newURL URL
    decoder := json.NewDecoder(r.Body)
    if err := decoder.Decode(&newURL); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    newURL.Key = generateKey(newURL.URL)
    rowsAffected, err := insertRow(newURL.URL, newURL.Key)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    fmt.Println("Inserted", newURL, rowsAffected, "rows affected")

    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(newURL)
}

func redirect(w http.ResponseWriter, r *http.Request) {
    key := strings.TrimPrefix(r.URL.Path, "/r/")
    if key == "" {
		http.Error(w, "Key is required", http.StatusBadRequest)
		return
	}

    sql := "SELECT url FROM urls WHERE key = ?"
	var url string
	err := DB.QueryRow(sql, key).Scan(&url)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

    http.Redirect(w, r, url, http.StatusFound)
}

func main() {
    var err error
    DB, err = sql.Open("sqlite", "database/database.sqlite3")
    if err != nil {
        log.Fatal(err)
    }
    defer DB.Close()

    http.HandleFunc("/", defaultHandler)
    http.HandleFunc("/new", newURL)
    http.HandleFunc("/r/", redirect)

    fmt.Println("Starting server at :8080")
    if err := http.ListenAndServe(":8080", nil); err != nil {
        log.Fatal("Error starting server:", err)
    }
}
