package threat

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

func NormalizeMD5(md5 string) (string, error) {
	md5 = strings.TrimSpace(strings.ToLower(md5))
	ok, err := regexp.MatchString("^[a-fA-F0-9]{32}$", md5)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("md5 hash is not correct")
	}
	return md5, nil
}

func New(input CreateThreat, md5 string) (Threat, error) {
	md5, err := NormalizeMD5(md5)
	if err != nil {
		return Threat{}, err
	}
	return Threat{
		MD5:         md5,
		Name:        input.Name,
		Description: input.Description,
		Category:    input.Category,
		Severity:    input.Severity,
		Tags:        input.Tags,
		FirstSeen:   input.FirstSeen,
		LastSeen:    input.LastSeen,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}, nil
}
