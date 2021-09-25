package oauthclient

import (
	"html/template"
	"net/http"
)

type OauthCallback struct {
}

func (callback *OauthCallback) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	template := template.New("callback.html")
	template, err = template.ParseFS(content, "callback.html")
	if err != nil {
		panic(err)
	}
	rw.Header().Set("Content-Type", "text/html")
	if err := template.Execute(rw, nil); err != nil {
		panic(err)
	}
}
