package api

import (
	"errors"
	"time"

	"github.com/chesnokov-an/SafeBoardGo2026/internal/threat"
)

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

type updateThreatRequest struct {
	Name        string     `json:"name"`
	Description *string    `json:"description"`
	Category    *string    `json:"category"`
	Severity    *string    `json:"severity"`
	Tags        []string   `json:"tags"`
	FirstSeen   *time.Time `json:"firstSeen"`
	LastSeen    *time.Time `json:"lastSeen"`
}

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

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

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
