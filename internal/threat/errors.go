package threat

import (
	"strings"
)

// FieldError describes one invalid field and the reason it was rejected.
type FieldError struct {
	Field  string
	Reason string
}

// ValidationError aggregates all field errors found during one validation pass.
type ValidationError struct {
	Fields []FieldError
}

const (
	reasonMD5          = "must be 32 hexadecimal characters"
	reasonName         = "must be between 1 and 255 characters"
	reasonDescription  = "must be at most 2000 characters"
	reasonCategory     = "must be one of the allowed categories"
	reasonSeverity     = "must be one of the allowed severities"
	reasonTagsCount    = "must contain at most 30 items"
	reasonTag          = "each tag must be between 1 and 50 characters"
	reasonTagDuplicate = "must not contain duplicate tags"
	reasonTagNil       = "must not be nil"
	reasonUTC          = "must be in UTC"
	reasonDateOrder    = "must not be before firstSeen"
)

func (e *ValidationError) Error() string {
	if e == nil || len(e.Fields) == 0 {
		return "validation failed"
	}

	var b strings.Builder
	b.WriteString("validation failed")
	for _, f := range e.Fields {
		b.WriteString("; ")
		b.WriteString(f.Field)
		b.WriteString(": ")
		b.WriteString(f.Reason)
	}
	return b.String()
}

func (e *ValidationError) Add(field FieldError) {
	e.Fields = append(e.Fields, field)
}
