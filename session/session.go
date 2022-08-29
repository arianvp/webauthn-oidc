package session

import (
	"net/http"
)

type SessionStore[T any] interface {
	GetOrCreateSession(r *http.Request, w http.ResponseWriter, cookieSettings *CookieSettings) (*T, error)
	UpdateSession(r *http.Request, cookieName string, session *T) error
}
