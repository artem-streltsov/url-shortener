package handlers

import (
	"encoding/base64"
	"encoding/gob"
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
	db    *database.DB
	store *sessions.CookieStore
}

type FlashMessage struct {
	Type    string
	Message string
}

func NewHandler(db *database.DB) *Handler {
	gob.Register(FlashMessage{})

	secretKey := os.Getenv("SESSION_SECRET_KEY")
	if secretKey == "" {
		log.Fatalf("SESSION_SECRET_KEY environment variable is not set")
	}

	store := sessions.NewCookieStore([]byte(secretKey))
	return &Handler{db: db, store: store}
}

func (h *Handler) addFlashMessage(w http.ResponseWriter, r *http.Request, messageType, message string) {
	session, _ := h.store.Get(r, "session")
	session.AddFlash(FlashMessage{Type: messageType, Message: message}, "flashMessages")
	if err := session.Save(r, w); err != nil {
		log.Println("Error saving session:", err)
	}
}

func (h *Handler) getFlashMessages(w http.ResponseWriter, r *http.Request) []FlashMessage {
	session, _ := h.store.Get(r, "session")
	flashes := session.Flashes("flashMessages")

	var messages []FlashMessage
	for _, f := range flashes {
		if msg, ok := f.(FlashMessage); ok {
			messages = append(messages, msg)
		}
	}

	if len(flashes) > 0 {
		if err := session.Save(r, w); err != nil {
			log.Println("Error saving session:", err)
		}
	}

	return messages
}

func (h *Handler) prepareTemplateData(w http.ResponseWriter, r *http.Request, data map[string]interface{}) map[string]interface{} {
	if data == nil {
		data = make(map[string]interface{})
	}
	flashMessages := h.getFlashMessages(w, r)
	data["FlashMessages"] = flashMessages
	return data
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

	mux.HandleFunc("/404", h.notFoundHandler)
	mux.HandleFunc("/403", h.forbiddenHandler)

	rl := middleware.NewRateLimiter(100, time.Minute)
	return middleware.LoggingMiddleware(middleware.RateLimitingMiddleware(rl)(mux))
}

func (h *Handler) notFoundHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	data := h.prepareTemplateData(w, r, nil)
	tmpl, err := template.ParseFiles("internal/templates/base.html", "internal/templates/404.html")
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

func (h *Handler) forbiddenHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusForbidden)
	data := h.prepareTemplateData(w, r, nil)
	tmpl, err := template.ParseFiles("internal/templates/base.html", "internal/templates/403.html")
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

func (h *Handler) indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		h.notFoundHandler(w, r)
		return
	}

	session, _ := h.store.Get(r, "session")
	user, _ := session.Values["user"].(*database.User)

	data := h.prepareTemplateData(w, r, map[string]interface{}{
		"User": user,
	})

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
		data := h.prepareTemplateData(w, r, nil)
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
			h.addFlashMessage(w, r, "error", "Error parsing form")
			http.Redirect(w, r, "/new", http.StatusSeeOther)
			return
		}

		url := r.Form.Get("url")
		password := r.Form.Get("password")

		if url == "" {
			h.addFlashMessage(w, r, "error", "URL is required")
			http.Redirect(w, r, "/new", http.StatusSeeOther)
			return
		}

		url, isValid := utils.IsValidURL(url)
		if !isValid {
			h.addFlashMessage(w, r, "error", "Invalid URL")
			http.Redirect(w, r, "/new", http.StatusSeeOther)
			return
		}

		isSafe, err := safebrowsing.IsSafeURL(url)
		if err != nil {
			h.addFlashMessage(w, r, "error", "Error checking URL safety")
			http.Redirect(w, r, "/new", http.StatusSeeOther)
			return
		}

		if !isSafe {
			h.addFlashMessage(w, r, "error", "The provided URL is not safe")
			http.Redirect(w, r, "/new", http.StatusSeeOther)
			return
		}

		key := utils.GenerateKey(url)

		var hashedPassword string
		if password != "" {
			hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if err != nil {
				h.addFlashMessage(w, r, "error", "Error hashing password")
				http.Redirect(w, r, "/new", http.StatusSeeOther)
				return
			}
			hashedPassword = string(hash)
		}

		shortURL := fmt.Sprintf("http://%s/r/%s", r.Host, key)
		qrCode, err := qrcode.Encode(shortURL, qrcode.Medium, 256)
		if err != nil {
			h.addFlashMessage(w, r, "error", "Error generating QR code")
			http.Redirect(w, r, "/new", http.StatusSeeOther)
			return
		}

		qrCodeBase64 := base64.StdEncoding.EncodeToString(qrCode)

		if err := h.db.InsertURL(url, key, user.ID, hashedPassword, qrCodeBase64); err != nil {
			h.addFlashMessage(w, r, "error", "Error inserting URL into database")
			http.Redirect(w, r, "/new", http.StatusSeeOther)
			return
		}

		h.addFlashMessage(w, r, "success", "URL successfully added")
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) redirectHandler(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/r/")
	if key == "" {
		h.notFoundHandler(w, r)
		return
	}

	url, err := h.db.GetURL(key)
	if err != nil {
		h.notFoundHandler(w, r)
		return
	}

	if url.Password != "" {
		switch r.Method {
		case http.MethodGet:
			data := h.prepareTemplateData(w, r, map[string]interface{}{
				"Key": key,
			})
			tmpl, err := template.ParseFiles("internal/templates/base.html", "internal/templates/password.html")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			err = tmpl.ExecuteTemplate(w, "base.html", data)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			return
		case http.MethodPost:
			password := r.FormValue("password")
			if err := bcrypt.CompareHashAndPassword([]byte(url.Password), []byte(password)); err != nil {
				h.addFlashMessage(w, r, "error", "Invalid password")
				http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
				return
			}
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	isSafe, err := safebrowsing.IsSafeURL(url.URL)
	if err != nil {
		h.addFlashMessage(w, r, "error", "Error checking URL safety")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if !isSafe {
		h.forbiddenHandler(w, r)
		return
	}

	if err := h.db.IncrementClicks(url.ID); err != nil {
		log.Printf("Error incrementing clicks: %v", err)
	}

	http.Redirect(w, r, url.URL, http.StatusFound)
}

func (h *Handler) registerHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		data := h.prepareTemplateData(w, r, nil)
		tmpl, err := template.ParseFiles("internal/templates/base.html", "internal/templates/register.html")
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
		email := r.FormValue("email")
		password := r.FormValue("password")

		if username == "" || email == "" || password == "" {
			h.addFlashMessage(w, r, "error", "All fields are required")
			http.Redirect(w, r, "/register", http.StatusSeeOther)
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			h.addFlashMessage(w, r, "error", "Error hashing password")
			http.Redirect(w, r, "/register", http.StatusSeeOther)
			return
		}

		user, err := h.db.CreateUser(username, email, string(hashedPassword))
		if err != nil {
			h.addFlashMessage(w, r, "error", "Error creating user")
			http.Redirect(w, r, "/register", http.StatusSeeOther)
			return
		}

		session, _ := h.store.Get(r, "session")
		session.Values["user"] = user
		err = session.Save(r, w)
		if err != nil {
			log.Printf("Error saving session: %v", err)
			h.addFlashMessage(w, r, "error", "Error saving session")
			http.Redirect(w, r, "/register", http.StatusSeeOther)
			return
		}

		h.addFlashMessage(w, r, "success", "Registration successful")
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) loginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		data := h.prepareTemplateData(w, r, nil)
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
			h.addFlashMessage(w, r, "error", "Invalid username or password")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		if err != nil {
			h.addFlashMessage(w, r, "error", "Invalid username or password")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		session, _ := h.store.Get(r, "session")
		session.Values["user"] = user
		err = session.Save(r, w)
		if err != nil {
			log.Printf("Error saving session: %v", err)
			h.addFlashMessage(w, r, "error", "Error saving session")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		h.addFlashMessage(w, r, "success", "Login successful")
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := h.store.Get(r, "session")
	session.Values["user"] = nil
	session.Save(r, w)
	h.addFlashMessage(w, r, "info", "You have been logged out")
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

	urls, err := h.db.GetURLsByUserID(user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := h.prepareTemplateData(w, r, map[string]interface{}{
		"User": user,
		"URLs": urls,
		"Host": r.Host,
	})

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
		h.addFlashMessage(w, r, "error", "Invalid URL ID")
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	url, err := h.db.GetURLByID(urlID)
	if err != nil {
		h.addFlashMessage(w, r, "error", "URL not found")
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	if url.UserID != user.ID {
		h.forbiddenHandler(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		data := h.prepareTemplateData(w, r, map[string]interface{}{
			"URL":  url,
			"Host": r.Host,
		})

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
			h.addFlashMessage(w, r, "error", "URL is required")
			http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
			return
		}

		newURL, isValid := utils.IsValidURL(newURL)
		if !isValid {
			h.addFlashMessage(w, r, "error", "Invalid URL provided")
			http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
			return
		}

		isSafe, err := safebrowsing.IsSafeURL(newURL)
		if err != nil {
			h.addFlashMessage(w, r, "error", "Error checking URL safety")
			http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
			return
		}

		if !isSafe {
			h.addFlashMessage(w, r, "error", "The provided URL is not safe")
			http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
			return
		}

		var hashedPassword string
		if newPassword != "" {
			hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
			if err != nil {
				h.addFlashMessage(w, r, "error", "Error hashing password")
				http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
				return
			}
			hashedPassword = string(hash)
		}

		err = h.db.UpdateURL(urlID, newURL, hashedPassword)
		if err != nil {
			h.addFlashMessage(w, r, "error", "Error updating the URL")
			http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
			return
		}

		h.addFlashMessage(w, r, "success", "URL updated successfully")
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
		h.addFlashMessage(w, r, "error", "Invalid URL ID")
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	url, err := h.db.GetURLByID(urlID)
	if err != nil {
		h.notFoundHandler(w, r)
		return
	}

	if url.UserID != user.ID {
		h.forbiddenHandler(w, r)
		return
	}

	err = h.db.DeleteURL(urlID)
	if err != nil {
		h.addFlashMessage(w, r, "error", "Error deleting URL")
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	h.addFlashMessage(w, r, "success", "URL deleted successfully")
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (h *Handler) urlDetailsHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := h.store.Get(r, "session")
	user, ok := session.Values["user"].(*database.User)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	urlID, err := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/details/"), 10, 64)
	if err != nil {
		h.addFlashMessage(w, r, "error", "Invalid URL ID")
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	url, err := h.db.GetURLByID(urlID)
	if err != nil {
		h.notFoundHandler(w, r)
		return
	}

	if url.UserID != user.ID {
		h.forbiddenHandler(w, r)
		return
	}

	shortURL := fmt.Sprintf("http://%s/r/%s", r.Host, url.Key)
	qrCode, err := qrcode.Encode(shortURL, qrcode.Medium, 256)
	if err != nil {
		h.addFlashMessage(w, r, "error", "Error generating QR code")
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	data := h.prepareTemplateData(w, r, map[string]interface{}{
		"URL":      url,
		"QRCode":   base64.StdEncoding.EncodeToString(qrCode),
		"Host":     r.Host,
		"ShortURL": shortURL,
	})

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
