package oauthclient

import (
	"embed"
	_ "embed"
	"html/template"
	"log"
	"net/http"
)

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

//go:embed *.html
var content embed.FS

type OauthCallback struct{}

func (callback *OauthCallback) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	template := template.New("callback.html")
	template, err = template.ParseFS(content, "callback.html")
	if err != nil {
		log.Fatal(err)
	}
	rw.Header().Set("Content-Type", "text/html")
	template.Execute(rw, nil)
}

type Index struct {
}

func (index *Index) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	template := template.New("index.html")
	template, err := template.ParseFS(content, "index.html")
	if err != nil {
		log.Fatal(err)
	}
	rw.Header().Set("Content-Type", "text/html")
	template.Execute(rw, nil)
}
