package oauthclient

import (
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/hashicorp/cap/oidc"
)

type params struct {
	URL string
}

func (client *Client) ServeIndex(rw http.ResponseWriter, req *http.Request) {

	template := template.New("index.html")
	template, err := template.ParseFS(content, "index.html")
	if err != nil {
		log.Fatal(err)
	}

	codeVerifier, err := oidc.NewCodeVerifier()
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	request, err := oidc.NewRequest(time.Minute, client.redirectURI, oidc.WithPKCE(codeVerifier))
	client.cache.Add(request)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	url, err := client.oidcProvider.AuthURL(req.Context(), request)
	rw.Header().Set("Content-Type", "text/html")
	if err := template.Execute(rw, params{URL: url}); err != nil {
		panic(err)
	}
}
