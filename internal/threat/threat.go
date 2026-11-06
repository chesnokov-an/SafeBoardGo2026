// Package threat contains the threat domain model, its normalization rules,
// and validation.
package threat

import "time"

// Category is a threat classification.
type Category string

// Supported threat categories.
const (
	CategoryMalware    Category = "malware"
	CategoryRansomware Category = "ransomware"
	CategoryTrojan     Category = "trojan"
	CategoryWorm       Category = "worm"
	CategorySpyware    Category = "spyware"
	CategoryPhishing   Category = "phishing"
	CategoryBotnet     Category = "botnet"
	CategoryExploit    Category = "exploit"
	CategoryOther      Category = "other"
	CategoryUnknown    Category = "unknown"
)

// Severity is a threat danger level.
type Severity string

// Supported threat severities.
const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
	SeverityUnknown  Severity = "unknown"
)

// Threat is a validated threat record. FirstSeen and LastSeen are optional.
type Threat struct {
	MD5         string
	Name        string
	Description string
	Category    Category
	Severity    Severity
	Tags        []string
	FirstSeen   *time.Time
	LastSeen    *time.Time
}
