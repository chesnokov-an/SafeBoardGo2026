package api

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/chesnokov-an/SafeBoardGo2026/internal/storage"
	"github.com/chesnokov-an/SafeBoardGo2026/internal/threat"
)

type Handler struct {
	store     storage.Store
	bodyLimit int64
	log       *slog.Logger
}

func New(store storage.Store, bodyLimit int64, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	return &Handler{store: store, bodyLimit: bodyLimit, log: log}
}

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /info/{md5}", h.GetThreat)
	mux.HandleFunc("PUT /info/{md5}", h.ReplaceThreat)
	mux.HandleFunc("POST /info", h.CreateThreat)
	mux.HandleFunc("GET /health", h.Health)
	return mux
}

func (h *Handler) GetThreat(w http.ResponseWriter, r *http.Request) {
	md5, err := threat.ParseMD5(r.PathValue("md5"))
	if err != nil {
		h.writeError(w, getHTTPError(err))
		return
	}
	t, err := h.store.Get(r.Context(), md5)
	if errors.Is(err, storage.ErrNotFound) {
		h.writeError(w, &httpError{404, "threat not found", err.Error()})
		return
	}
	if err != nil {
		h.log.Error("get threat", "error", err)
		h.writeError(w, &httpError{500, "internal server error", ""})
		return
	}
	h.writeJSON(w, http.StatusOK, newThreatResponse(t))
}

func (h *Handler) ReplaceThreat(w http.ResponseWriter, r *http.Request) {
	md5, err := threat.ParseMD5(r.PathValue("md5"))
	if err != nil {
		h.writeError(w, getHTTPError(err))
		return
	}
	var req updateThreatRequest
	if httpErr := h.decodeJSON(w, r, &req); httpErr != nil {
		h.writeError(w, httpErr)
		return
	}
	t, err := req.toThreat(md5)
	if err != nil {
		h.writeError(w, getHTTPError(err))
		return
	}
	if err := h.store.Replace(r.Context(), t); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			h.writeError(w, &httpError{404, "threat not found", err.Error()})
			return
		}
		h.log.Error("get threat", "error", err)
		h.writeError(w, &httpError{500, "internal server error", ""})
		return
	}
	h.writeJSON(w, http.StatusOK, newThreatResponse(t))
}

func (h *Handler) CreateThreat(w http.ResponseWriter, r *http.Request) {
	var req createThreatRequest
	if httpErr := h.decodeJSON(w, r, &req); httpErr != nil {
		h.writeError(w, httpErr)
		return
	}
	t, err := req.toThreat()
	if err != nil {
		h.writeError(w, getHTTPError(err))
		return
	}
	if err := h.store.Create(r.Context(), t); err != nil {
		if errors.Is(err, storage.ErrAlreadyExists) {
			h.writeError(w, &httpError{409, "threat already exists", err.Error()})
			return
		}
		h.log.Error("create threat", "error", err)
		h.writeError(w, &httpError{500, "internal server error", ""})
		return
	}
	h.writeJSON(w, 201, newThreatResponse(t))
}

func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	//nolint:errcheck
	_, _ = w.Write([]byte("ok\n"))
}
