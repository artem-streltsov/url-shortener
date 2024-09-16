package handlers

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/artem-streltsov/url-shortener/internal/database"
	"github.com/artem-streltsov/url-shortener/internal/middleware"
	"github.com/artem-streltsov/url-shortener/internal/safebrowsing"
	"github.com/artem-streltsov/url-shortener/internal/utils"
	"github.com/gorilla/sessions"
	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	db        *database.DB
	store     *sessions.CookieStore
}

func NewHandler(db *database.DB) *Handler {
	// TODO: use environment variable
	secretKey := os.Getenv("SESSION_SECRET_KEY")
	if secretKey == "" {
		log.Fatalf("SESSION_SECRET_KEY environment variable is not set")
	}

	store := sessions.NewCookieStore([]byte(secretKey))
	return &Handler{db: db, store: store}
}

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", h.indexHandler)
	mux.HandleFunc("/new", h.newURLHandler)
	mux.HandleFunc("/r/", h.redirectHandler)
	mux.HandleFunc("/register", h.registerHandler)
	mux.HandleFunc("/login", h.loginHandler)
	mux.HandleFunc("/logout", h.logoutHandler)
	mux.HandleFunc("/dashboard", h.dashboardHandler)
	mux.HandleFunc("/edit/", h.editURLHandler)
	mux.HandleFunc("/delete/", h.deleteURLHandler)
	mux.HandleFunc("/details/", h.urlDetailsHandler)

	rl := middleware.NewRateLimiter(100, time.Minute)
	return middleware.LoggingMiddleware(middleware.RateLimitingMiddleware(rl)(mux))
}

func (h *Handler) indexHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: create a 404 page, etc
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	session, _ := h.store.Get(r, "session")
	user, _ := session.Values["user"].(*database.User)

	flashes := session.Flashes("error")
	var errorMsg string
	if len(flashes) > 0 {
		errorMsg, _ = flashes[0].(string)
	}

	data := struct {
		User  *database.User
		Error string
	}{
		User:  user,
		Error: errorMsg,
	}
	session.Save(r, w)

    tmpl, err := template.ParseFiles("internal/templates/base.html", "internal/templates/index.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    err = tmpl.ExecuteTemplate(w, "base.html", data)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
}

func (h *Handler) newURLHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := h.store.Get(r, "session")
	user, ok := session.Values["user"].(*database.User)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	switch r.Method {
	case http.MethodGet:
		flashes := session.Flashes("error")
		var errorMsg string
		if len(flashes) > 0 {
			errorMsg, _ = flashes[0].(string)
		}
		session.Save(r, w)

		data := struct {
			Error string
		}{
			Error: errorMsg,
		}

    tmpl, err := template.ParseFiles("internal/templates/base.html", "internal/templates/new.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    err = tmpl.ExecuteTemplate(w, "base.html", data)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
	case http.MethodPost:
		err := r.ParseForm()
		if err != nil {
			session.AddFlash("Error parsing form", "error")
			session.Save(r, w)
			http.Redirect(w, r, "/new", http.StatusSeeOther)
			return
		}

		url := r.Form.Get("url")
		password := r.Form.Get("password")

		if url == "" {
			session.AddFlash("URL is required", "error")
			session.Save(r, w)
			http.Redirect(w, r, "/new", http.StatusSeeOther)
			return
		}

		url, isValid := utils.IsValidURL(url)
		if !isValid {
			session.AddFlash("Invalid URL", "error")
			session.Save(r, w)
			http.Redirect(w, r, "/new", http.StatusSeeOther)
			return
		}

		isSafe, err := safebrowsing.IsSafeURL(url)
		if err != nil {
			session.AddFlash("The provided URL is not safe", "error")
			session.Save(r, w)
			http.Redirect(w, r, "/new", http.StatusSeeOther)
			return
		}

		if !isSafe {
			session.AddFlash("The provided URL is not safe", "error")
			session.Save(r, w)
			http.Redirect(w, r, "/new", http.StatusSeeOther)
			return
		}

		key := utils.GenerateKey(url)

		var hashedPassword string
		if password != "" {
			hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if err != nil {
				session.AddFlash("Error hashing password", "error")
				session.Save(r, w)
				http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
				return
			}
			hashedPassword = string(hash)
		}

		shortURL := fmt.Sprintf("http://%s/r/%s", r.Host, key)
		qrCode, err := qrcode.Encode(shortURL, qrcode.Medium, 256)
		if err != nil {
			session.AddFlash("Error generating QR code", "error")
			session.Save(r, w)
			http.Redirect(w, r, "/new", http.StatusSeeOther)
			return
		}

		qrCodeBase64 := base64.StdEncoding.EncodeToString(qrCode)

		if err := h.db.InsertURL(url, key, user.ID, hashedPassword, qrCodeBase64); err != nil {
			session.AddFlash("Error inserting URL into database", "error")
			session.Save(r, w)
			http.Redirect(w, r, "/new", http.StatusSeeOther)
			return
		}

		session.AddFlash("URL successfully added", "success")
		session.Save(r, w)
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) redirectHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: add flashes
	key := strings.TrimPrefix(r.URL.Path, "/r/")
	if key == "" {
		http.Error(w, "Key is required", http.StatusBadRequest)
		return
	}

	url, err := h.db.GetURL(key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	if url.Password != "" {
		switch r.Method {
		case http.MethodGet:
            data := struct{ Key string }{Key: key}
    tmpl, err := template.ParseFiles("internal/templates/password.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    err = tmpl.ExecuteTemplate(w, "password.html", data)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
			return
		case http.MethodPost:
			password := r.FormValue("password")
			if err := bcrypt.CompareHashAndPassword([]byte(url.Password), []byte(password)); err != nil {
				http.Error(w, "Invalid password", http.StatusUnauthorized)
				return
			}
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	isSafe, err := safebrowsing.IsSafeURL(url.URL)
	if err != nil {
		http.Error(w, "Error checking URL safety", http.StatusInternalServerError)
		return
	}

	if !isSafe {
		http.Error(w, "The requested URL is not safe", http.StatusForbidden)
		return
	}

	if err := h.db.IncrementClicks(url.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, url.URL, http.StatusFound)
}

func (h *Handler) registerHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
    tmpl, err := template.ParseFiles("internal/templates/register.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    err = tmpl.ExecuteTemplate(w, "register.html", nil)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
	case http.MethodPost:
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")

		if username == "" || email == "" || password == "" {
			http.Error(w, "All fields are required", http.StatusBadRequest)
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Error hashing password", http.StatusInternalServerError)
			return
		}

		user, err := h.db.CreateUser(username, email, string(hashedPassword))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		session, _ := h.store.Get(r, "session")
		session.Values["user"] = user
		err = session.Save(r, w)
		if err != nil {
			log.Printf("Error saving session: %v", err)
			http.Error(w, "Error saving session", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) loginHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := h.store.Get(r, "session")

	switch r.Method {
	case http.MethodGet:
		flashes := session.Flashes("error")
		var errorMsg string
		if len(flashes) > 0 {
			errorMsg, _ = flashes[0].(string)
		}
		session.Save(r, w)

		data := struct {
			Error string
		}{
			Error: errorMsg,
		}

    tmpl, err := template.ParseFiles("internal/templates/base.html", "internal/templates/login.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    err = tmpl.ExecuteTemplate(w, "base.html", data)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
	case http.MethodPost:
		username := r.FormValue("username")
		password := r.FormValue("password")

		user, err := h.db.GetUserByUsername(username)
		if err != nil || user == nil {
			session.AddFlash("Invalid username or password", "error")
			session.Save(r, w)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		if err != nil {
			session.AddFlash("Invalid username or password", "error")
			session.Save(r, w)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		session.Values["user"] = user
		err = session.Save(r, w)
		if err != nil {
			log.Printf("Error saving session: %v", err)
			http.Error(w, "Error saving session", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := h.store.Get(r, "session")
	session.Values["user"] = nil
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *Handler) dashboardHandler(w http.ResponseWriter, r *http.Request) {
	session, err := h.store.Get(r, "session")
	if err != nil {
		log.Printf("Error getting session: %v", err)
		http.Error(w, "Error getting session", http.StatusInternalServerError)
		return
	}

	userValue, ok := session.Values["user"]
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	user, ok := userValue.(*database.User)
	if !ok {
		log.Printf("Error: user value is not of type *database.User")
		http.Error(w, "Invalid session data", http.StatusInternalServerError)
		return
	}

	errorFlashes := session.Flashes("error")
	var errorMsg string
	if len(errorFlashes) > 0 {
		errorMsg, _ = errorFlashes[0].(string)
	}

	var successMsg string
	if errorMsg == "" {
		successFlashes := session.Flashes("success")
		if len(successFlashes) > 0 {
			successMsg, _ = successFlashes[0].(string)
		}
	}

	session.Save(r, w)

	urls, err := h.db.GetURLsByUserID(user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := struct {
		User    *database.User
		URLs    []database.URL
		Host    string
		Success string
		Error   string
	}{
		User:    user,
		URLs:    urls,
		Host:    r.Host,
		Success: successMsg,
		Error:   errorMsg,
	}

    tmpl, err := template.ParseFiles("internal/templates/base.html", "internal/templates/dashboard.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    err = tmpl.ExecuteTemplate(w, "base.html", data)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
}

func (h *Handler) editURLHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := h.store.Get(r, "session")
	user, ok := session.Values["user"].(*database.User)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	urlID, err := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/edit/"), 10, 64)
	if err != nil {
		session.AddFlash("Invalid URL ID", "error")
		session.Save(r, w)
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	url, err := h.db.GetURLByID(urlID)
	if err != nil {
		session.AddFlash("URL not found", "error")
		session.Save(r, w)
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	if url.UserID != user.ID {
		session.AddFlash("Unauthorized access", "error")
		session.Save(r, w)
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	switch r.Method {
	case http.MethodGet:
		flashes := session.Flashes("error")
		var errorMsg string
		if len(flashes) > 0 {
			errorMsg, _ = flashes[0].(string)
		}
		session.Save(r, w)

		data := struct {
			URL   *database.URL
			Host  string
			Error string
		}{
			URL:   url,
			Host:  r.Host,
			Error: errorMsg,
		}

    tmpl, err := template.ParseFiles("internal/templates/base.html", "internal/templates/edit.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    err = tmpl.ExecuteTemplate(w, "base.html", data)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
	case http.MethodPost:
		newURL := r.FormValue("url")
		newPassword := r.FormValue("password")

		if newURL == "" {
			session.AddFlash("URL is required", "error")
			session.Save(r, w)
			http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
			return
		}

		newURL, isValid := utils.IsValidURL(newURL)
		if !isValid {
			session.AddFlash("Invalid URL provided", "error")
			session.Save(r, w)
			http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
			return
		}

		isSafe, err := safebrowsing.IsSafeURL(newURL)
		if err != nil {
			session.AddFlash("Error checking URL safety", "error")
			session.Save(r, w)
			http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
			return
		}

		if !isSafe {
			session.AddFlash("The provided URL is not safe", "error")
			session.Save(r, w)
			http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
			return
		}

		var hashedPassword string
		if newPassword != "" {
			hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
			if err != nil {
				session.AddFlash("Error hashing password", "error")
				session.Save(r, w)
				http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
				return
			}
			hashedPassword = string(hash)
		}

		err = h.db.UpdateURL(urlID, newURL, hashedPassword)
		if err != nil {
			session.AddFlash("Error updating the URL", "error")
			session.Save(r, w)
			http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
			return
		}

		session.AddFlash("URL updated successfully", "success")
		session.Save(r, w)
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) deleteURLHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := h.store.Get(r, "session")
	user, ok := session.Values["user"].(*database.User)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	urlID, err := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/delete/"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid URL ID", http.StatusBadRequest)
		return
	}

	url, err := h.db.GetURLByID(urlID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	if url.UserID != user.ID {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	err = h.db.DeleteURL(urlID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (h *Handler) urlDetailsHandler(w http.ResponseWriter, r *http.Request) {
	urlID, err := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/details/"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid URL ID", http.StatusBadRequest)
		return
	}

	url, err := h.db.GetURLByID(urlID)
	if err != nil {
		http.Error(w, "URL not found", http.StatusNotFound)
		return
	}

	shortURL := fmt.Sprintf("http://%s/r/%s", r.Host, url.Key)
	qrCode, err := qrcode.Encode(shortURL, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "Error generating QR code", http.StatusInternalServerError)
		return
	}

	data := struct {
		URL      *database.URL
		QRCode   string
		Host     string
		ShortURL string
	}{
		URL:      url,
		QRCode:   base64.StdEncoding.EncodeToString(qrCode),
		Host:     r.Host,
		ShortURL: shortURL,
	}

    tmpl, err := template.ParseFiles("internal/templates/base.html", "internal/templates/details.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    err = tmpl.ExecuteTemplate(w, "base.html", data)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
}
