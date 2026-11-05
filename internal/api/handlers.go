package handlers

import "net/http"

func GetThreatByHash(w http.ResponseWriter, r *http.Request) {
	// TODO
}

func ModifyThreat(w http.ResponseWriter, r *http.Request) {
	// TODO
}

func CreateThreat(w http.ResponseWriter, r *http.Request) {
	// TODO
}

func Health(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Everything is ok!"))
}
