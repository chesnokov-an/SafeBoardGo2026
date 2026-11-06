package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chesnokov-an/SafeBoardGo2026/internal/storage"
	"github.com/chesnokov-an/SafeBoardGo2026/internal/threat"
)

const (
	testMD5   = "d41d8cd98f00b204e9800998ecf8427e"
	otherMD5  = "0cc175b9c0f1b6a831c399e269772661"
	mediaJSON = "application/json"
	bodyLimit = 1 << 20
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestServer(t *testing.T, store storage.Store, limit int64) http.Handler {
	t.Helper()

	return New(store, limit, testLogger()).Routes()
}

func validCreateBody() string {
	return `{"md5":"` + testMD5 + `","name":"Trojan.Win32.Generic","description":"test description",` +
		`"category":"trojan","severity":"high","tags":["demo","test"],` +
		`"firstSeen":"2026-01-01T00:00:00Z","lastSeen":"2026-02-01T00:00:00Z"}`
}

func validUpdateBody() string {
	return `{"name":"Updated.Threat","description":null,"category":"ransomware","severity":"critical",` +
		`"tags":["new"],"firstSeen":"2025-12-01T00:00:00Z","lastSeen":"2026-03-01T00:00:00Z"}`
}

func doRequest(t *testing.T, srv http.Handler, method, path, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func decodeResponse[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()

	var v T
	if err := json.NewDecoder(rec.Body).Decode(&v); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return v
}

func mustCreateThreat(t *testing.T, srv http.Handler, body string) threatResponse {
	t.Helper()

	rec := doRequest(t, srv, http.MethodPost, "/info", mediaJSON, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d (body %s)", rec.Code, http.StatusCreated, rec.Body.String())
	}
	return decodeResponse[threatResponse](t, rec)
}

func assertErrorResponse(t *testing.T, rec *httptest.ResponseRecorder, wantStatus int, wantDetails string) {
	t.Helper()

	if rec.Code != wantStatus {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, wantStatus, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, want application/json; charset=utf-8", ct)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode error response: %v (body %q)", err, rec.Body.String())
	}
	for _, key := range []string{"message", "details"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("error response has no %q key: %s", key, rec.Body.String())
		}
	}
	if wantDetails == "" {
		return
	}

	var details string
	if err := json.Unmarshal(raw["details"], &details); err != nil {
		t.Fatalf("decode details: %v", err)
	}
	if !strings.Contains(details, wantDetails) {
		t.Errorf("details = %q, want to contain %q", details, wantDetails)
	}
}

func TestHealth(t *testing.T) {
	srv := newTestServer(t, storage.NewMemory(), bodyLimit)

	rec := doRequest(t, srv, http.MethodGet, "/health", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/plain; charset=utf-8", ct)
	}
	if got, want := rec.Body.String(), "ok\n"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestCreateThreatSuccess(t *testing.T) {
	srv := newTestServer(t, storage.NewMemory(), bodyLimit)

	rec := doRequest(t, srv, http.MethodPost, "/info", mediaJSON, validCreateBody())
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusCreated, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, want application/json; charset=utf-8", ct)
	}

	got := decodeResponse[threatResponse](t, rec)
	if got.MD5 != testMD5 {
		t.Errorf("MD5 = %q, want %q", got.MD5, testMD5)
	}
	if got.Name != "Trojan.Win32.Generic" {
		t.Errorf("Name = %q, want %q", got.Name, "Trojan.Win32.Generic")
	}
	if got.Description != "test description" {
		t.Errorf("Description = %q, want %q", got.Description, "test description")
	}
	if got.Category != threat.CategoryTrojan {
		t.Errorf("Category = %q, want %q", got.Category, threat.CategoryTrojan)
	}
	if got.Severity != threat.SeverityHigh {
		t.Errorf("Severity = %q, want %q", got.Severity, threat.SeverityHigh)
	}
	if want := []string{"demo", "test"}; !slices.Equal(got.Tags, want) {
		t.Errorf("Tags = %v, want %v", got.Tags, want)
	}

	wantFirstSeen := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	wantLastSeen := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	if got.FirstSeen == nil || !got.FirstSeen.Equal(wantFirstSeen) {
		t.Errorf("FirstSeen = %v, want %v", got.FirstSeen, wantFirstSeen)
	}
	if got.LastSeen == nil || !got.LastSeen.Equal(wantLastSeen) {
		t.Errorf("LastSeen = %v, want %v", got.LastSeen, wantLastSeen)
	}
}

func TestCreateThreatNormalizesInput(t *testing.T) {
	srv := newTestServer(t, storage.NewMemory(), bodyLimit)
	body := `{"md5":"` + strings.ToUpper(testMD5) + `","name":"  Trojan  ",` +
		`"tags":[" TEST ","demo","demo"]}`

	rec := doRequest(t, srv, http.MethodPost, "/info", mediaJSON, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusCreated, rec.Body.String())
	}

	got := decodeResponse[threatResponse](t, rec)
	if got.MD5 != testMD5 {
		t.Errorf("MD5 = %q, want lower-case %q", got.MD5, testMD5)
	}
	if got.Name != "Trojan" {
		t.Errorf("Name = %q, want trimmed %q", got.Name, "Trojan")
	}
	if want := []string{"demo", "test"}; !slices.Equal(got.Tags, want) {
		t.Errorf("Tags = %v, want %v", got.Tags, want)
	}
}

func TestCreateThreatDefaults(t *testing.T) {
	srv := newTestServer(t, storage.NewMemory(), bodyLimit)
	body := `{"md5":"` + testMD5 + `","name":"Threat","description":null,"tags":null}`

	rec := doRequest(t, srv, http.MethodPost, "/info", mediaJSON, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusCreated, rec.Body.String())
	}

	got := decodeResponse[threatResponse](t, rec)
	if got.Description != "" {
		t.Errorf("Description = %q, want empty string", got.Description)
	}
	if got.Category != threat.CategoryUnknown {
		t.Errorf("Category = %q, want %q", got.Category, threat.CategoryUnknown)
	}
	if got.Severity != threat.SeverityUnknown {
		t.Errorf("Severity = %q, want %q", got.Severity, threat.SeverityUnknown)
	}
	if got.Tags == nil {
		t.Error("Tags = nil, want empty slice")
	}
	if len(got.Tags) != 0 {
		t.Errorf("Tags = %v, want empty slice", got.Tags)
	}
	if got.FirstSeen != nil || got.LastSeen != nil {
		t.Errorf("dates = (%v, %v), want (nil, nil)", got.FirstSeen, got.LastSeen)
	}
}

func TestCreateThreatIgnoresUnknownFields(t *testing.T) {
	srv := newTestServer(t, storage.NewMemory(), bodyLimit)
	body := `{"md5":"` + testMD5 + `","name":"Threat","unknown":123}`

	rec := doRequest(t, srv, http.MethodPost, "/info", mediaJSON, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusCreated, rec.Body.String())
	}
}

func TestCreateThreatResponseKeys(t *testing.T) {
	srv := newTestServer(t, storage.NewMemory(), bodyLimit)
	body := `{"md5":"` + testMD5 + `","name":"Threat"}`

	rec := doRequest(t, srv, http.MethodPost, "/info", mediaJSON, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	wantKeys := []string{"md5", "name", "description", "category", "severity", "tags", "firstSeen", "lastSeen"}
	if len(raw) != len(wantKeys) {
		t.Errorf("response has %d keys, want %d: %s", len(raw), len(wantKeys), rec.Body.String())
	}
	for _, key := range wantKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("response has no %q key: %s", key, rec.Body.String())
		}
	}
	if got := string(raw["tags"]); got != "[]" {
		t.Errorf("tags in JSON = %s, want []", got)
	}
}

func TestCreateThreatValidation(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantDetails string
	}{
		{
			name:        "missing md5",
			body:        `{"name":"Threat"}`,
			wantDetails: "md5",
		},
		{
			name:        "missing name",
			body:        `{"md5":"` + testMD5 + `"}`,
			wantDetails: "name",
		},
		{
			name:        "invalid md5",
			body:        `{"md5":"nope","name":"Threat"}`,
			wantDetails: "md5",
		},
		{
			name:        "empty category",
			body:        `{"md5":"` + testMD5 + `","name":"Threat","category":""}`,
			wantDetails: "category",
		},
		{
			name:        "empty severity",
			body:        `{"md5":"` + testMD5 + `","name":"Threat","severity":""}`,
			wantDetails: "severity",
		},
		{
			name:        "invalid category",
			body:        `{"md5":"` + testMD5 + `","name":"Threat","category":"Trojan"}`,
			wantDetails: "category",
		},
		{
			name:        "invalid severity",
			body:        `{"md5":"` + testMD5 + `","name":"Threat","severity":"critical!"}`,
			wantDetails: "severity",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newTestServer(t, storage.NewMemory(), bodyLimit)

			rec := doRequest(t, srv, http.MethodPost, "/info", mediaJSON, tt.body)
			assertErrorResponse(t, rec, http.StatusBadRequest, tt.wantDetails)
		})
	}
}

func TestCreateThreatDecodeErrors(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		wantStatus  int
	}{
		{
			name:        "missing content type",
			contentType: "",
			body:        validCreateBody(),
			wantStatus:  http.StatusUnsupportedMediaType,
		},
		{
			name:        "wrong content type",
			contentType: "text/plain",
			body:        validCreateBody(),
			wantStatus:  http.StatusUnsupportedMediaType,
		},
		{
			name:        "empty body",
			contentType: mediaJSON,
			body:        "",
			wantStatus:  http.StatusBadRequest,
		},
		{
			name:        "malformed json",
			contentType: mediaJSON,
			body:        `{"md5":`,
			wantStatus:  http.StatusBadRequest,
		},
		{
			name:        "trailing data",
			contentType: mediaJSON,
			body:        validCreateBody() + `{}`,
			wantStatus:  http.StatusBadRequest,
		},
		{
			name:        "charset is allowed",
			contentType: "application/json; charset=utf-8",
			body:        validCreateBody(),
			wantStatus:  http.StatusCreated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newTestServer(t, storage.NewMemory(), bodyLimit)

			rec := doRequest(t, srv, http.MethodPost, "/info", tt.contentType, tt.body)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body.String())
			}
		})
	}
}

func TestCreateThreatBodyTooLarge(t *testing.T) {
	srv := newTestServer(t, storage.NewMemory(), 10)

	rec := doRequest(t, srv, http.MethodPost, "/info", mediaJSON, validCreateBody())
	assertErrorResponse(t, rec, http.StatusRequestEntityTooLarge, "")
}

func TestCreateThreatDuplicate(t *testing.T) {
	srv := newTestServer(t, storage.NewMemory(), bodyLimit)

	mustCreateThreat(t, srv, validCreateBody())

	rec := doRequest(t, srv, http.MethodPost, "/info", mediaJSON, validCreateBody())
	assertErrorResponse(t, rec, http.StatusConflict, "already exists")
}

func TestGetThreat(t *testing.T) {
	srv := newTestServer(t, storage.NewMemory(), bodyLimit)
	created := mustCreateThreat(t, srv, validCreateBody())

	t.Run("existing", func(t *testing.T) {
		rec := doRequest(t, srv, http.MethodGet, "/info/"+testMD5, "", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusOK, rec.Body.String())
		}

		got := decodeResponse[threatResponse](t, rec)
		if !reflect.DeepEqual(got, created) {
			t.Errorf("response = %+v, want %+v", got, created)
		}
	})

	t.Run("uppercase path md5", func(t *testing.T) {
		rec := doRequest(t, srv, http.MethodGet, "/info/"+strings.ToUpper(testMD5), "", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusOK, rec.Body.String())
		}
	})

	t.Run("not found", func(t *testing.T) {
		rec := doRequest(t, srv, http.MethodGet, "/info/"+otherMD5, "", "")
		assertErrorResponse(t, rec, http.StatusNotFound, otherMD5)
	})

	t.Run("invalid path md5", func(t *testing.T) {
		rec := doRequest(t, srv, http.MethodGet, "/info/nope", "", "")
		assertErrorResponse(t, rec, http.StatusBadRequest, "md5")
	})
}

func TestReplaceThreatSuccess(t *testing.T) {
	srv := newTestServer(t, storage.NewMemory(), bodyLimit)
	mustCreateThreat(t, srv, validCreateBody())

	rec := doRequest(t, srv, http.MethodPut, "/info/"+testMD5, mediaJSON, validUpdateBody())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	got := decodeResponse[threatResponse](t, rec)
	if got.Name != "Updated.Threat" {
		t.Errorf("Name = %q, want %q", got.Name, "Updated.Threat")
	}
	if got.Description != "" {
		t.Errorf("Description = %q, want empty string", got.Description)
	}
	if got.Category != threat.CategoryRansomware {
		t.Errorf("Category = %q, want %q", got.Category, threat.CategoryRansomware)
	}
	if got.Severity != threat.SeverityCritical {
		t.Errorf("Severity = %q, want %q", got.Severity, threat.SeverityCritical)
	}
	if want := []string{"new"}; !slices.Equal(got.Tags, want) {
		t.Errorf("Tags = %v, want %v", got.Tags, want)
	}

	getRec := doRequest(t, srv, http.MethodGet, "/info/"+testMD5, "", "")
	if getRec.Code != http.StatusOK {
		t.Fatalf("get status = %d, want %d", getRec.Code, http.StatusOK)
	}
	stored := decodeResponse[threatResponse](t, getRec)
	if !reflect.DeepEqual(stored, got) {
		t.Errorf("stored threat = %+v, want %+v", stored, got)
	}
}

func TestReplaceThreatUppercasePath(t *testing.T) {
	srv := newTestServer(t, storage.NewMemory(), bodyLimit)
	mustCreateThreat(t, srv, validCreateBody())

	rec := doRequest(t, srv, http.MethodPut, "/info/"+strings.ToUpper(testMD5), mediaJSON, validUpdateBody())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestReplaceThreatPathWinsOverBody(t *testing.T) {
	srv := newTestServer(t, storage.NewMemory(), bodyLimit)
	mustCreateThreat(t, srv, validCreateBody())

	body := `{"md5":"` + otherMD5 + `","name":"Updated"}`
	rec := doRequest(t, srv, http.MethodPut, "/info/"+testMD5, mediaJSON, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	got := decodeResponse[threatResponse](t, rec)
	if got.MD5 != testMD5 {
		t.Errorf("MD5 = %q, want %q from path", got.MD5, testMD5)
	}

	otherRec := doRequest(t, srv, http.MethodGet, "/info/"+otherMD5, "", "")
	assertErrorResponse(t, otherRec, http.StatusNotFound, otherMD5)
}

func TestReplaceThreatErrors(t *testing.T) {
	t.Run("not found", func(t *testing.T) {
		srv := newTestServer(t, storage.NewMemory(), bodyLimit)

		rec := doRequest(t, srv, http.MethodPut, "/info/"+otherMD5, mediaJSON, validUpdateBody())
		assertErrorResponse(t, rec, http.StatusNotFound, otherMD5)
	})

	t.Run("invalid path md5", func(t *testing.T) {
		srv := newTestServer(t, storage.NewMemory(), bodyLimit)

		rec := doRequest(t, srv, http.MethodPut, "/info/nope", mediaJSON, validUpdateBody())
		assertErrorResponse(t, rec, http.StatusBadRequest, "md5")
	})

	t.Run("malformed body", func(t *testing.T) {
		srv := newTestServer(t, storage.NewMemory(), bodyLimit)
		mustCreateThreat(t, srv, validCreateBody())

		rec := doRequest(t, srv, http.MethodPut, "/info/"+testMD5, mediaJSON, `{"name":`)
		assertErrorResponse(t, rec, http.StatusBadRequest, "")
	})

	t.Run("empty category", func(t *testing.T) {
		srv := newTestServer(t, storage.NewMemory(), bodyLimit)
		mustCreateThreat(t, srv, validCreateBody())

		body := `{"name":"Threat","category":""}`
		rec := doRequest(t, srv, http.MethodPut, "/info/"+testMD5, mediaJSON, body)
		assertErrorResponse(t, rec, http.StatusBadRequest, "category")
	})
}

type errorStore struct {
	err error
}

func (s errorStore) Create(context.Context, threat.Threat) error {
	return s.err
}

func (s errorStore) Get(context.Context, string) (threat.Threat, error) {
	return threat.Threat{}, s.err
}

func (s errorStore) Replace(context.Context, threat.Threat) error {
	return s.err
}

var _ storage.Store = errorStore{}

func TestHandlerInternalErrors(t *testing.T) {
	sensitive := errors.New("boom: secret internals")

	tests := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{
			name:   "get",
			method: http.MethodGet,
			path:   "/info/" + testMD5,
		},
		{
			name:   "create",
			method: http.MethodPost,
			path:   "/info",
			body:   validCreateBody(),
		},
		{
			name:   "replace",
			method: http.MethodPut,
			path:   "/info/" + testMD5,
			body:   validUpdateBody(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newTestServer(t, errorStore{err: sensitive}, bodyLimit)

			rec := doRequest(t, srv, tt.method, tt.path, mediaJSON, tt.body)
			assertErrorResponse(t, rec, http.StatusInternalServerError, "")

			if strings.Contains(rec.Body.String(), "secret") {
				t.Errorf("response leaks internal error: %s", rec.Body.String())
			}
			if got := decodeResponse[struct {
				Message string `json:"message"`
				Details string `json:"details"`
			}](t, rec); got.Message != "internal server error" {
				t.Errorf("message = %q, want %q", got.Message, "internal server error")
			}
		})
	}
}

func TestHandlerStorageErrorMapping(t *testing.T) {
	t.Run("already exists", func(t *testing.T) {
		srv := newTestServer(t, errorStore{err: storage.ErrAlreadyExists}, bodyLimit)

		rec := doRequest(t, srv, http.MethodPost, "/info", mediaJSON, validCreateBody())
		assertErrorResponse(t, rec, http.StatusConflict, "")
	})

	t.Run("not found on get", func(t *testing.T) {
		srv := newTestServer(t, errorStore{err: storage.ErrNotFound}, bodyLimit)

		rec := doRequest(t, srv, http.MethodGet, "/info/"+testMD5, "", "")
		assertErrorResponse(t, rec, http.StatusNotFound, "")
	})

	t.Run("not found on replace", func(t *testing.T) {
		srv := newTestServer(t, errorStore{err: storage.ErrNotFound}, bodyLimit)

		rec := doRequest(t, srv, http.MethodPut, "/info/"+testMD5, mediaJSON, validUpdateBody())
		assertErrorResponse(t, rec, http.StatusNotFound, "")
	})
}
