package main

import (
    "database/sql"
    "fmt"
    "net/http"
    "log"

    _ "modernc.org/sqlite"
)

var DB *sql.DB

func defaultHandler(w http.ResponseWriter, r *http.Request) {
    rows, err := DB.Query("SELECT url, key FROM urls")
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

func main() {
    var err error
    DB, err = sql.Open("sqlite", "database/database.sqlite3")
    if err != nil {
        log.Fatal(err)
    }
    defer DB.Close()

    http.HandleFunc("/", defaultHandler)

    fmt.Println("Starting server at :8080")
    if err := http.ListenAndServe(":8080", nil); err != nil {
        log.Fatal("Error starting server:", err)
    }
}
