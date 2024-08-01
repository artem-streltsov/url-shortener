package handlers

import (
	"html/template"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/artemstreltsov/url-shortener/internal/database"
	"github.com/artemstreltsov/url-shortener/internal/safebrowsing"
	"github.com/artemstreltsov/url-shortener/internal/utils"
)

type Handler struct {
	db        *database.DB
	templates *template.Template
}

func NewHandler(db *database.DB) *Handler {
	templatesDir := "./internal/templates"
	templates := template.Must(template.ParseGlob(filepath.Join(templatesDir, "*.html")))
	return &Handler{db: db, templates: templates}
}

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", h.indexHandler)
	mux.HandleFunc("/new", h.newURLHandler)
	mux.HandleFunc("/r/", h.redirectHandler)
	return mux
}

func (h *Handler) indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	urls, err := h.db.GetAllURLs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = h.templates.ExecuteTemplate(w, "index.html", urls)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *Handler) newURLHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		err := h.templates.ExecuteTemplate(w, "new.html", nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case http.MethodPost:
		err := r.ParseForm()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		url := r.Form.Get("url")
		if url == "" {
			http.Error(w, "URL is required", http.StatusBadRequest)
			return
		}

		if !utils.IsValidURL(url) {
			http.Error(w, "Invalid URL", http.StatusBadRequest)
			return
		}

		isSafe, err := safebrowsing.IsSafeURL(url)
		if err != nil {
			http.Error(w, "Error checking URL safety", http.StatusInternalServerError)
			return
		}

		if !isSafe {
			http.Error(w, "The provided URL is not safe", http.StatusBadRequest)
			return
		}

		key := utils.GenerateKey(url)

		if err := h.db.InsertURL(url, key); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) redirectHandler(w http.ResponseWriter, r *http.Request) {
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

	isSafe, err := safebrowsing.IsSafeURL(url)
	if err != nil {
		http.Error(w, "Error checking URL safety", http.StatusInternalServerError)
		return
	}

	if !isSafe {
		http.Error(w, "The requested URL is not safe", http.StatusForbidden)
		return
	}

	http.Redirect(w, r, url, http.StatusFound)
}