package oauthclient

import (
	"embed"
	"net/http"
)

//go:embed *.html
var content embed.FS

type Client struct {
	http.ServeMux
	callback OauthCallback
	index    Index
}

func New() Client {
	client := Client{}
	client.Handle("/", &client.index)
	client.Handle("/callback", &client.callback)
	return client
}
