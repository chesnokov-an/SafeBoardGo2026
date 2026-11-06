package threat

import (
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxNameRunes        = 255
	maxDescriptionRunes = 2000
	maxTags             = 30
	maxTagRunes         = 50
)

var regexpMD5 = regexp.MustCompile("^[a-fA-F0-9]{32}$")

func New(input Threat) (Threat, error) {
	out := normalize(&input)
	err := validate(&out)
	if err != nil {
		return Threat{}, err
	}
	return out, nil
}

func normalizeMD5(md5 string) string {
	md5 = strings.ToLower(md5)
	return md5
}

func validateMD5(md5 string) *FieldError {
	if !regexpMD5.MatchString(md5) {
		return &FieldError{"md5", reasonMD5}
	}
	return nil
}

func ParseMD5(rawMD5 string) (string, error) {
	md5 := normalizeMD5(rawMD5)
	field := validateMD5(md5)
	if field == nil {
		return md5, nil
	}
	return "", &ValidationError{[]FieldError{*field}}
}

func normalizeName(name string) string {
	name = strings.TrimSpace(name)
	return name
}

func validateName(name string) *FieldError {
	nameLen := utf8.RuneCountInString(name)
	if nameLen > maxNameRunes || nameLen == 0 {
		return &FieldError{"name", reasonName}
	}
	return nil
}

func normalizeDescription(desc string) string {
	desc = strings.TrimSpace(desc)
	return desc
}

func validateDescription(desc string) *FieldError {
	descLen := utf8.RuneCountInString(desc)
	if descLen > maxDescriptionRunes {
		return &FieldError{"description", reasonDescription}
	}
	return nil
}

func normalizeCategory(c Category) Category {
	if c == "" {
		return CategoryUnknown
	}
	return c
}

func validateCategory(c Category) *FieldError {
	switch c {
	case CategoryMalware, CategoryRansomware, CategoryTrojan, CategoryWorm, CategorySpyware, CategoryPhishing, CategoryBotnet, CategoryExploit, CategoryOther, CategoryUnknown:
		return nil
	}
	return &FieldError{"category", reasonCategory}
}

func normalizeSeverity(s Severity) Severity {
	if s == "" {
		return SeverityUnknown
	}
	return s
}

func validateSeverity(s Severity) *FieldError {
	switch s {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical, SeverityUnknown:
		return nil
	}
	return &FieldError{"severity", reasonSeverity}
}

func normalizeTags(tags []string) []string {
	if tags == nil {
		return []string{}
	}
	for i := range tags {
		tags[i] = strings.TrimSpace(strings.ToLower(tags[i]))
	}
	slices.Sort(tags)
	tags = slices.Compact(tags)
	return tags
}

func validateTags(tags []string) *FieldError {
	if tags == nil {
		return &FieldError{"tags", reasonTagNil}
	}
	if len(tags) > maxTags {
		return &FieldError{"tags", reasonTagsCount}
	}
	for i := range tags {
		tagLen := utf8.RuneCountInString(tags[i])
		if tagLen > maxTagRunes || tagLen == 0 {
			return &FieldError{"tags", reasonTag}
		}
	}
	return nil
}

func normalizeTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

func validateTime(t1, t2 *time.Time) *FieldError {
	if t1 != nil && t1.Location() != time.UTC {
		return &FieldError{"firstSeen", reasonUTC}
	}
	if t2 != nil && t2.Location() != time.UTC {
		return &FieldError{"lastSeen", reasonUTC}
	}
	if t1 != nil && t2 != nil && t2.Before(*t1) {
		return &FieldError{"lastSeen", reasonDateOrder}
	}
	return nil
}

func normalize(t *Threat) Threat {
	return Threat{
		MD5:         normalizeMD5(t.MD5),
		Name:        normalizeName(t.Name),
		Description: normalizeDescription(t.Description),
		Category:    normalizeCategory(t.Category),
		Severity:    normalizeSeverity(t.Severity),
		Tags:        normalizeTags(t.Tags),
		FirstSeen:   normalizeTime(t.FirstSeen),
		LastSeen:    normalizeTime(t.LastSeen),
	}
}

func validate(t *Threat) error {
	fields := []*FieldError{
		validateMD5(t.MD5),
		validateName(t.Name),
		validateDescription(t.Description),
		validateCategory(t.Category),
		validateSeverity(t.Severity),
		validateTags(t.Tags),
		validateTime(t.FirstSeen, t.LastSeen),
	}
	err := &ValidationError{}
	for _, field := range fields {
		if field != nil {
			err.Add(*field)
		}
	}
	if len(err.Fields) == 0 {
		return nil
	}
	return err
}
