package utils

import (
	"crypto/sha256"
	"strconv"
	"strings"
	"time"

	urlverifier "github.com/davidmytton/url-verifier"
)

const base62Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func encodeBytesToBase62(input []byte) string {
	result := make([]byte, 0, 10)
	for _, b := range input {
		result = append(result, base62Chars[b%62])
	}
	return string(result)
}

func GenerateKey(url string) string {
	currentTime := strconv.FormatInt(time.Now().Unix(), 10)
	hashInput := url + currentTime
	hash := sha256.Sum256([]byte(hashInput))
	return encodeBytesToBase62(hash[:])[:10]
}

func IsValidURL(urlStr string) (string, bool) {
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		urlStr = "http://" + urlStr
	}

	verifier := urlverifier.NewVerifier()
	verifier.EnableHTTPCheck()
	result, err := verifier.Verify(urlStr)
	if err != nil || !result.IsRFC3986URI || !result.IsRFC3986URL {
		return "", false
	}

	return urlStr, true
}
