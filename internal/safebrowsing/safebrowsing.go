package safebrowsing

import (
	"fmt"
	"os"

	safebrowsing "github.com/google/safebrowsing"
)

var sb *safebrowsing.SafeBrowser

func InitSafeBrowsing() error {
	apiKey := os.Getenv("SAFE_BROWSING_API_KEY")
	if apiKey == "" {
		return fmt.Errorf("SAFE_BROWSING_API_KEY environment variable is not set")
	}

	config := &safebrowsing.Config{
		APIKey: apiKey,
		ID:     "url-shortener",
		DBPath: "database/safebrowsing_db",
	}

	var err error
	sb, err = safebrowsing.NewSafeBrowser(*config)
	if err != nil {
		return fmt.Errorf("failed to create SafeBrowser: %v", err)
	}

	return nil
}

func IsSafeURL(url string) (bool, error) {
	if sb == nil {
		return false, fmt.Errorf("SafeBrowser is not initialized")
	}

	threats, err := sb.LookupURLs([]string{url})
	if err != nil {
		return false, fmt.Errorf("failed to lookup URL: %v", err)
	}

	isSafe := len(threats[0]) == 0
	return isSafe, nil
}

func Close() {
	if sb != nil {
		sb.Close()
	}
}
