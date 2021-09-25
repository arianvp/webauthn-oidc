package server

import "net/http"

type OauthServer struct {
	serveMux http.ServeMux
}

func New() OauthServer {

}
