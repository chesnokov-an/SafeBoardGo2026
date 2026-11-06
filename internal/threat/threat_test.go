package threat

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func ptr[T any](v T) *T {
	return &v
}

func validInput() Threat {
	return Threat{
		MD5:         "d41d8cd98f00b204e9800998ecf8427e",
		Name:        "Trojan.Win32.Generic",
		Description: "test description",
		Category:    CategoryTrojan,
		Severity:    SeverityHigh,
		Tags:        []string{"demo"},
		FirstSeen:   ptr(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
		LastSeen:    ptr(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)),
	}
}

func wantFields(t *testing.T, err error, fields ...string) *ValidationError {
	t.Helper()

	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("error = %v, want *ValidationError", err)
	}

	got := make([]string, 0, len(ve.Fields))
	for _, f := range ve.Fields {
		got = append(got, f.Field)
	}
	if !slices.Equal(got, fields) {
		t.Fatalf("fields = %v, want %v (%v)", got, fields, ve)
	}
	return ve
}

func TestNormalizeMD5(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "lower case stays lower",
			in:   "d41d8cd98f00b204e9800998ecf8427e",
			want: "d41d8cd98f00b204e9800998ecf8427e",
		},
		{
			name: "upper case is lowered",
			in:   "D41D8CD98F00B204E9800998ECF8427E",
			want: "d41d8cd98f00b204e9800998ecf8427e",
		},
		{
			name: "spaces are not trimmed",
			in:   " d41d8cd98f00b204e9800998ecf8427e ",
			want: " d41d8cd98f00b204e9800998ecf8427e ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeMD5(tt.in); got != tt.want {
				t.Errorf("normalizeMD5(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestNormalizeName(t *testing.T) {
	if got, want := normalizeName("  Trojan  "), "Trojan"; got != want {
		t.Errorf("normalizeName() = %q, want %q", got, want)
	}
}

func TestNormalizeDescription(t *testing.T) {
	if got, want := normalizeDescription("  description  "), "description"; got != want {
		t.Errorf("normalizeDescription() = %q, want %q", got, want)
	}
}

func TestNormalizeCategoryAndSeverity(t *testing.T) {
	t.Run("empty category defaults to unknown", func(t *testing.T) {
		if got := normalizeCategory(""); got != CategoryUnknown {
			t.Errorf("normalizeCategory(\"\") = %q, want %q", got, CategoryUnknown)
		}
	})
	t.Run("known category is kept", func(t *testing.T) {
		if got := normalizeCategory(CategoryTrojan); got != CategoryTrojan {
			t.Errorf("normalizeCategory() = %q, want %q", got, CategoryTrojan)
		}
	})
	t.Run("unknown category value is kept for validation", func(t *testing.T) {
		if got := normalizeCategory("Trojan"); got != Category("Trojan") {
			t.Errorf("normalizeCategory() = %q, want %q", got, "Trojan")
		}
	})
	t.Run("empty severity defaults to unknown", func(t *testing.T) {
		if got := normalizeSeverity(""); got != SeverityUnknown {
			t.Errorf("normalizeSeverity(\"\") = %q, want %q", got, SeverityUnknown)
		}
	})
	t.Run("known severity is kept", func(t *testing.T) {
		if got := normalizeSeverity(SeverityHigh); got != SeverityHigh {
			t.Errorf("normalizeSeverity() = %q, want %q", got, SeverityHigh)
		}
	})
}

func TestNormalizeTags(t *testing.T) {
	t.Run("nil becomes empty non-nil slice", func(t *testing.T) {
		got := normalizeTags(nil)
		if got == nil {
			t.Fatal("normalizeTags(nil) = nil, want non-nil slice")
		}
		if len(got) != 0 {
			t.Fatalf("normalizeTags(nil) = %v, want empty slice", got)
		}
	})

	t.Run("empty slice stays empty", func(t *testing.T) {
		got := normalizeTags([]string{})
		if got == nil {
			t.Fatal("normalizeTags([]) = nil, want non-nil slice")
		}
		if len(got) != 0 {
			t.Fatalf("normalizeTags([]) = %v, want empty slice", got)
		}
	})

	t.Run("trims, lower-cases, sorts and deduplicates", func(t *testing.T) {
		got := normalizeTags([]string{" Demo ", "demo", "TEST"})
		want := []string{"demo", "test"}
		if !slices.Equal(got, want) {
			t.Errorf("normalizeTags() = %v, want %v", got, want)
		}
	})
}

func TestNormalizeTime(t *testing.T) {
	t.Run("nil stays nil", func(t *testing.T) {
		if got := normalizeTime(nil); got != nil {
			t.Errorf("normalizeTime(nil) = %v, want nil", got)
		}
	})

	t.Run("returns UTC copy without mutating input", func(t *testing.T) {
		loc := time.FixedZone("MSK", 3*60*60)
		src := time.Date(2026, 1, 10, 9, 30, 0, 0, loc)

		got := normalizeTime(&src)
		if got == nil {
			t.Fatal("normalizeTime() = nil, want non-nil")
		}
		if got.Location() != time.UTC {
			t.Errorf("location = %v, want UTC", got.Location())
		}
		if !got.Equal(src) {
			t.Errorf("normalizeTime() = %v, want same instant as %v", got, src)
		}
		if src.Location() != loc {
			t.Error("input time was mutated")
		}
	})
}

func TestValidate(t *testing.T) {
	t.Run("valid threat", func(t *testing.T) {
		in := validInput()
		if err := validate(&in); err != nil {
			t.Fatalf("validate() error = %v, want nil", err)
		}
	})

	t.Run("name rune limit is inclusive", func(t *testing.T) {
		in := validInput()
		in.Name = strings.Repeat("я", maxNameRunes)
		if err := validate(&in); err != nil {
			t.Fatalf("validate() with %d runes error = %v, want nil", maxNameRunes, err)
		}

		in.Name += "я"
		if err := validate(&in); err == nil {
			t.Fatal("validate() with too long name = nil, want error")
		}
	})

	tests := []struct {
		name   string
		mutate func(*Threat)
		field  string
		reason string
	}{
		{
			name:   "invalid md5",
			mutate: func(th *Threat) { th.MD5 = "nope" },
			field:  "md5",
			reason: reasonMD5,
		},
		{
			name:   "empty name",
			mutate: func(th *Threat) { th.Name = "" },
			field:  "name",
			reason: reasonName,
		},
		{
			name:   "too long name",
			mutate: func(th *Threat) { th.Name = strings.Repeat("я", maxNameRunes+1) },
			field:  "name",
			reason: reasonName,
		},
		{
			name:   "too long description",
			mutate: func(th *Threat) { th.Description = strings.Repeat("я", maxDescriptionRunes+1) },
			field:  "description",
			reason: reasonDescription,
		},
		{
			name:   "invalid category",
			mutate: func(th *Threat) { th.Category = "Trojan" },
			field:  "category",
			reason: reasonCategory,
		},
		{
			name:   "invalid severity",
			mutate: func(th *Threat) { th.Severity = "critical!" },
			field:  "severity",
			reason: reasonSeverity,
		},
		{
			name:   "nil tags",
			mutate: func(th *Threat) { th.Tags = nil },
			field:  "tags",
			reason: reasonTagNil,
		},
		{
			name: "more than 30 unique tags",
			mutate: func(th *Threat) {
				th.Tags = make([]string, maxTags+1)
				for i := range th.Tags {
					th.Tags[i] = strings.Repeat("a", i+1)
				}
			},
			field:  "tags",
			reason: reasonTagsCount,
		},
		{
			name:   "empty tag",
			mutate: func(th *Threat) { th.Tags = []string{""} },
			field:  "tags",
			reason: reasonTag,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := validInput()
			tt.mutate(&in)

			ve := wantFields(t, validate(&in), tt.field)
			if len(ve.Fields) != 1 {
				t.Fatalf("len(Fields) = %d, want 1: %v", len(ve.Fields), ve)
			}
			if ve.Fields[0].Reason != tt.reason {
				t.Errorf("reason = %q, want %q", ve.Fields[0].Reason, tt.reason)
			}
		})
	}
}

func TestValidateAggregatesAllFields(t *testing.T) {
	in := validInput()
	in.MD5 = "nope"
	in.Name = ""
	in.Category = "Trojan"
	in.Severity = "critical!"
	in.Tags = nil

	ve := wantFields(t, validate(&in), "md5", "name", "category", "severity", "tags")
	if len(ve.Fields) != 5 {
		t.Fatalf("len(Fields) = %d, want 5: %v", len(ve.Fields), ve)
	}
}

func TestValidateDates(t *testing.T) {
	t.Run("rejects non-UTC time", func(t *testing.T) {
		in := validInput()
		loc := time.FixedZone("MSK", 3*60*60)
		in.FirstSeen = ptr(time.Date(2026, 1, 1, 0, 0, 0, 0, loc))

		ve := wantFields(t, validate(&in), "firstSeen")
		if ve.Fields[0].Reason != reasonUTC {
			t.Errorf("reason = %q, want %q", ve.Fields[0].Reason, reasonUTC)
		}
	})

	t.Run("rejects lastSeen before firstSeen", func(t *testing.T) {
		in := validInput()
		in.FirstSeen = ptr(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))
		in.LastSeen = ptr(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

		ve := wantFields(t, validate(&in), "lastSeen")
		if ve.Fields[0].Reason != reasonDateOrder {
			t.Errorf("reason = %q, want %q", ve.Fields[0].Reason, reasonDateOrder)
		}
	})

	t.Run("allows equal dates", func(t *testing.T) {
		in := validInput()
		same := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		in.FirstSeen = &same
		in.LastSeen = &same

		if err := validate(&in); err != nil {
			t.Fatalf("validate() error = %v, want nil", err)
		}
	})
}

func TestNew(t *testing.T) {
	t.Run("normalizes input", func(t *testing.T) {
		in := validInput()
		in.MD5 = strings.ToUpper(in.MD5)
		in.Name = "  Trojan  "
		in.Description = "  description  "
		in.Category = ""
		in.Severity = ""
		in.Tags = []string{" Demo ", "demo", "TEST"}

		loc := time.FixedZone("MSK", 3*60*60)
		in.FirstSeen = ptr(time.Date(2026, 1, 1, 0, 0, 0, 0, loc))
		in.LastSeen = ptr(time.Date(2026, 2, 1, 0, 0, 0, 0, loc))

		out, err := New(in)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		if out.MD5 != "d41d8cd98f00b204e9800998ecf8427e" {
			t.Errorf("MD5 = %q, want lower-case", out.MD5)
		}
		if out.Name != "Trojan" {
			t.Errorf("Name = %q, want %q", out.Name, "Trojan")
		}
		if out.Description != "description" {
			t.Errorf("Description = %q, want %q", out.Description, "description")
		}
		if out.Category != CategoryUnknown {
			t.Errorf("Category = %q, want %q", out.Category, CategoryUnknown)
		}
		if out.Severity != SeverityUnknown {
			t.Errorf("Severity = %q, want %q", out.Severity, SeverityUnknown)
		}
		if !slices.Equal(out.Tags, []string{"demo", "test"}) {
			t.Errorf("Tags = %v, want [demo test]", out.Tags)
		}
		if out.FirstSeen == nil || out.FirstSeen.Location() != time.UTC {
			t.Errorf("FirstSeen = %v, want UTC", out.FirstSeen)
		}
		if out.LastSeen == nil || out.LastSeen.Location() != time.UTC {
			t.Errorf("LastSeen = %v, want UTC", out.LastSeen)
		}
	})

	t.Run("aggregates errors", func(t *testing.T) {
		in := validInput()
		in.MD5 = "nope"
		in.Name = "   "
		in.Category = "Trojan"
		in.Severity = "critical!"
		in.Tags = []string{" "}

		_, err := New(in)
		ve := wantFields(t, err, "md5", "name", "category", "severity", "tags")
		if len(ve.Fields) != 5 {
			t.Fatalf("len(Fields) = %d, want 5: %v", len(ve.Fields), ve)
		}
	})

	t.Run("returns zero threat on error", func(t *testing.T) {
		in := validInput()
		in.MD5 = "nope"

		out, err := New(in)
		if err == nil {
			t.Fatal("New() error = nil, want error")
		}
		if !reflect.DeepEqual(out, Threat{}) {
			t.Errorf("New() = %+v, want zero Threat", out)
		}
	})

	t.Run("allows empty description", func(t *testing.T) {
		in := validInput()
		in.Description = ""

		if _, err := New(in); err != nil {
			t.Fatalf("New() with empty description error = %v, want nil", err)
		}
	})

	t.Run("accepts more than 30 raw tags when unique count fits", func(t *testing.T) {
		in := validInput()
		in.Tags = make([]string, 0, maxTags*2+1)
		for i := 0; i <= maxTags*2; i++ {
			// 30 unique values, repeated; raw count is 61.
			in.Tags = append(in.Tags, "tag-"+strings.Repeat("a", i%maxTags+1))
		}

		out, err := New(in)
		if err != nil {
			t.Fatalf("New() error = %v, want nil", err)
		}
		if len(out.Tags) != maxTags {
			t.Errorf("len(Tags) = %d, want %d unique tags", len(out.Tags), maxTags)
		}
	})

	t.Run("rejects more than 30 unique tags", func(t *testing.T) {
		in := validInput()
		in.Tags = make([]string, maxTags+1)
		for i := range in.Tags {
			// All values are distinct and fit into 50 runes.
			in.Tags[i] = strings.Repeat("a", i+1)
		}

		ve := wantFields(t, mustNewError(t, in), "tags")
		if ve.Fields[0].Reason != reasonTagsCount {
			t.Errorf("reason = %q, want %q", ve.Fields[0].Reason, reasonTagsCount)
		}
	})
}

func mustNewError(t *testing.T, in Threat) error {
	t.Helper()
	_, err := New(in)
	if err == nil {
		t.Fatal("New() error = nil, want error")
	}
	return err
}

func TestValidationError(t *testing.T) {
	t.Run("nil receiver", func(t *testing.T) {
		var ve *ValidationError
		if got, want := ve.Error(), "validation failed"; got != want {
			t.Errorf("Error() = %q, want %q", got, want)
		}
	})

	t.Run("empty fields", func(t *testing.T) {
		ve := &ValidationError{}
		if got, want := ve.Error(), "validation failed"; got != want {
			t.Errorf("Error() = %q, want %q", got, want)
		}
	})

	t.Run("joins field errors", func(t *testing.T) {
		ve := &ValidationError{
			Fields: []FieldError{
				{Field: "md5", Reason: reasonMD5},
				{Field: "name", Reason: reasonName},
			},
		}
		want := "validation failed; md5: " + reasonMD5 + "; name: " + reasonName
		if got := ve.Error(); got != want {
			t.Errorf("Error() = %q, want %q", got, want)
		}
	})

	t.Run("add appends", func(t *testing.T) {
		ve := &ValidationError{}
		ve.Add(FieldError{Field: "tags", Reason: reasonTag})

		if len(ve.Fields) != 1 {
			t.Fatalf("len(Fields) = %d, want 1", len(ve.Fields))
		}
		if ve.Fields[0].Field != "tags" || ve.Fields[0].Reason != reasonTag {
			t.Errorf("Fields[0] = %+v, want tags/%s", ve.Fields[0], reasonTag)
		}
	})
}
