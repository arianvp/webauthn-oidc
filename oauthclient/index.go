package oauthclient

import (
	"html/template"
	"log"
	"net/http"
)

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
