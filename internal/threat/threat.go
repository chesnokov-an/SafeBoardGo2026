package threat

import "time"

type Category string

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

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
	SeverityUnknown  Severity = "unknown"
)

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
