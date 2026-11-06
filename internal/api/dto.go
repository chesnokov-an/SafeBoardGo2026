package api

import (
	"errors"
	"time"

	"github.com/chesnokov-an/SafeBoardGo2026/internal/threat"
)

// createThreatRequest is the JSON body of POST /info.
type createThreatRequest struct {
	MD5         string     `json:"md5"`
	Name        string     `json:"name"`
	Description *string    `json:"description"`
	Category    *string    `json:"category"`
	Severity    *string    `json:"severity"`
	Tags        []string   `json:"tags"`
	FirstSeen   *time.Time `json:"firstSeen"`
	LastSeen    *time.Time `json:"lastSeen"`
}

// updateThreatRequest is the JSON body of PUT /info/{md5}. MD5 is taken from
// the path, so a body md5 field is ignored.
type updateThreatRequest struct {
	Name        string     `json:"name"`
	Description *string    `json:"description"`
	Category    *string    `json:"category"`
	Severity    *string    `json:"severity"`
	Tags        []string   `json:"tags"`
	FirstSeen   *time.Time `json:"firstSeen"`
	LastSeen    *time.Time `json:"lastSeen"`
}

// threatResponse is the JSON representation of a threat.
type threatResponse struct {
	MD5         string          `json:"md5"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Category    threat.Category `json:"category"`
	Severity    threat.Severity `json:"severity"`
	Tags        []string        `json:"tags"`
	FirstSeen   *time.Time      `json:"firstSeen"`
	LastSeen    *time.Time      `json:"lastSeen"`
}

// toThreat converts and validates a create request.
func (r createThreatRequest) toThreat() (threat.Threat, error) {
	return buildThreat(threat.Threat{
		MD5:         r.MD5,
		Name:        r.Name,
		Description: derefString(r.Description),
		Category:    threat.Category(derefString(r.Category)),
		Severity:    threat.Severity(derefString(r.Severity)),
		Tags:        r.Tags,
		FirstSeen:   r.FirstSeen,
		LastSeen:    r.LastSeen,
	}, r.Category, r.Severity)
}

// toThreat converts and validates an update request using md5 from the path.
func (r updateThreatRequest) toThreat(md5 string) (threat.Threat, error) {
	return buildThreat(threat.Threat{
		MD5:         md5,
		Name:        r.Name,
		Description: derefString(r.Description),
		Category:    threat.Category(derefString(r.Category)),
		Severity:    threat.Severity(derefString(r.Severity)),
		Tags:        r.Tags,
		FirstSeen:   r.FirstSeen,
		LastSeen:    r.LastSeen,
	}, r.Category, r.Severity)
}

// derefString returns the pointed-to value or "" when p is nil.
func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// buildThreat merges transport-level checks with domain validation.
func buildThreat(in threat.Threat, category, severity *string) (threat.Threat, error) {
	ve := threat.ValidationError{}

	if category != nil && *category == "" {
		ve.Add(threat.FieldError{Field: "category", Reason: "must not be empty"})
	}
	if severity != nil && *severity == "" {
		ve.Add(threat.FieldError{Field: "severity", Reason: "must not be empty"})
	}
	out, err := threat.New(in)
	if err != nil {
		var domainErr *threat.ValidationError
		if errors.As(err, &domainErr) {
			ve.Fields = append(ve.Fields, domainErr.Fields...)
		} else {
			return threat.Threat{}, err
		}
	}
	if len(ve.Fields) > 0 {
		return threat.Threat{}, &ve
	}
	return out, nil
}

// newThreatResponse maps a domain threat to its API representation.
func newThreatResponse(t threat.Threat) threatResponse {
	return threatResponse{
		MD5:         t.MD5,
		Name:        t.Name,
		Description: t.Description,
		Category:    t.Category,
		Severity:    t.Severity,
		Tags:        t.Tags,
		FirstSeen:   t.FirstSeen,
		LastSeen:    t.LastSeen,
	}
}
