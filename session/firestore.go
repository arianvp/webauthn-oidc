package session

import (
	"net/http"

	"cloud.google.com/go/firestore"
)

type FireStore[T any] struct {
	sesisonCollection *firestore.CollectionRef
}

func NewFireStore[T any](client *firestore.Client) *FireStore[T] {
	sessionCollection := client.Collection("sessions")
	return &FireStore[T]{sessionCollection}
}

type CookieSettings struct {
	Name     string
	MaxAge   int
	SameSite http.SameSite
}

func (store *FireStore[T]) UpdateSession(r *http.Request, cookieName string, session *T) error {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return err
	}
	sessionId := cookie.Value
	_, err = store.sesisonCollection.Doc(sessionId).Set(r.Context(), session)
	return err
}

func (store *FireStore[T]) GetOrCreateSession(r *http.Request, w http.ResponseWriter, cookieSettings *CookieSettings) (*T, error) {
	session := new(T)
	sessionCookie, err := r.Cookie(cookieSettings.Name)
	if err == http.ErrNoCookie {
		doc, _, err := store.sesisonCollection.Add(r.Context(), session)
		if err != nil {
			return nil, err
		}
		sessionCookie = &http.Cookie{
			Name:     cookieSettings.Name,
			Value:    doc.ID,
			MaxAge:   cookieSettings.MaxAge,
			Secure:   true,
			HttpOnly: true,
			SameSite: cookieSettings.SameSite,
		}
		http.SetCookie(w, sessionCookie)
	} else if err != nil {
		return nil, err
	}
	documentRef := store.sesisonCollection.Doc(sessionCookie.Value)
	document, err := documentRef.Get(r.Context())
	if err != nil {
		return nil, err
	}
	if err := document.DataTo(session); err != nil {
		return nil, err
	}
	return session, err
}
