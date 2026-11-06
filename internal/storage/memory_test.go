package storage

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/chesnokov-an/SafeBoardGo2026/internal/threat"
)

var _ Store = (*Memory)(nil)

const testMD5 = "d41d8cd98f00b204e9800998ecf8427e"

func ptr[T any](v T) *T {
	return &v
}

func testThreat(md5, name string) threat.Threat {
	return threat.Threat{
		MD5:         md5,
		Name:        name,
		Description: "test description",
		Category:    threat.CategoryTrojan,
		Severity:    threat.SeverityHigh,
		Tags:        []string{"demo", "test"},
		FirstSeen:   ptr(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
		LastSeen:    ptr(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)),
	}
}

func TestMemoryCreateAndGet(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()
	want := testThreat(testMD5, "Trojan.Win32.Generic")

	if err := store.Create(ctx, want); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	got, err := store.Get(ctx, testMD5)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Get() = %+v, want %+v", got, want)
	}
}

func TestMemoryCreateDuplicate(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()
	first := testThreat(testMD5, "first")

	if err := store.Create(ctx, first); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	err := store.Create(ctx, testThreat(testMD5, "second"))
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("Create() error = %v, want ErrAlreadyExists", err)
	}

	got, err := store.Get(ctx, testMD5)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !reflect.DeepEqual(got, first) {
		t.Errorf("Get() = %+v, want original %+v", got, first)
	}
}

func TestMemoryGetNotFound(t *testing.T) {
	store := NewMemory()

	_, err := store.Get(context.Background(), testMD5)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() error = %v, want ErrNotFound", err)
	}
}

func TestMemoryReplace(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()
	original := testThreat(testMD5, "original")

	if err := store.Create(ctx, original); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	updated := testThreat(testMD5, "updated")
	updated.Description = "updated description"
	updated.Category = threat.CategoryRansomware
	updated.Severity = threat.SeverityCritical
	updated.Tags = []string{"new"}
	updated.FirstSeen = ptr(time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC))
	updated.LastSeen = ptr(time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC))

	if err := store.Replace(ctx, updated); err != nil {
		t.Fatalf("Replace() error = %v", err)
	}

	got, err := store.Get(ctx, testMD5)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !reflect.DeepEqual(got, updated) {
		t.Errorf("Get() = %+v, want %+v", got, updated)
	}
}

func TestMemoryReplaceNotFound(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()

	err := store.Replace(ctx, testThreat(testMD5, "missing"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Replace() error = %v, want ErrNotFound", err)
	}

	if _, err := store.Get(ctx, testMD5); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get() after failed Replace error = %v, want ErrNotFound", err)
	}
}

func TestMemoryGetReturnsCopy(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()
	want := testThreat(testMD5, "Trojan")

	if err := store.Create(ctx, want); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	got, err := store.Get(ctx, testMD5)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	got.Tags[0] = "mutated"
	*got.FirstSeen = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

	again, err := store.Get(ctx, testMD5)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !reflect.DeepEqual(again, want) {
		t.Errorf("store was mutated through Get(): got %+v, want %+v", again, want)
	}
}

func TestMemoryCreateStoresCopy(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()
	want := testThreat(testMD5, "Trojan")
	input := testThreat(testMD5, "Trojan")

	if err := store.Create(ctx, input); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	input.Tags[0] = "mutated"
	*input.FirstSeen = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

	got, err := store.Get(ctx, testMD5)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("store was mutated through input: got %+v, want %+v", got, want)
	}
}

func TestMemoryReplaceStoresCopy(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()

	if err := store.Create(ctx, testThreat(testMD5, "original")); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	want := testThreat(testMD5, "updated")
	input := testThreat(testMD5, "updated")

	if err := store.Replace(ctx, input); err != nil {
		t.Fatalf("Replace() error = %v", err)
	}

	input.Tags[0] = "mutated"
	*input.LastSeen = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

	got, err := store.Get(ctx, testMD5)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("store was mutated through input: got %+v, want %+v", got, want)
	}
}

func TestCloneThreatPreservesNilAndEmptyTags(t *testing.T) {
	base := testThreat(testMD5, "Trojan")

	base.Tags = nil
	if got := cloneThreat(base); got.Tags != nil {
		t.Errorf("cloneThreat(nil tags).Tags = %v, want nil", got.Tags)
	}

	base.Tags = []string{}
	if got := cloneThreat(base); got.Tags == nil {
		t.Error("cloneThreat(empty tags).Tags = nil, want non-nil empty slice")
	}
}

func TestMemoryConcurrentCreateSameKey(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()

	const goroutines = 50
	results := make(chan error, goroutines)

	var wg sync.WaitGroup
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- store.Create(ctx, testThreat(testMD5, "same"))
		}()
	}

	wg.Wait()
	close(results)

	successes := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrAlreadyExists):
			// expected
		default:
			t.Errorf("Create() error = %v, want nil or ErrAlreadyExists", err)
		}
	}

	if successes != 1 {
		t.Errorf("successful creates = %d, want 1", successes)
	}
}

func TestMemoryConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()

	const goroutines = 50
	var wg sync.WaitGroup

	for i := range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()

			md5 := fmt.Sprintf("%032x", i)
			original := testThreat(md5, "original")

			if err := store.Create(ctx, original); err != nil {
				t.Errorf("Create(%s) error = %v", md5, err)
				return
			}

			got, err := store.Get(ctx, md5)
			if err != nil {
				t.Errorf("Get(%s) error = %v", md5, err)
				return
			}
			if !reflect.DeepEqual(got, original) {
				t.Errorf("Get(%s) = %+v, want %+v", md5, got, original)
				return
			}

			updated := testThreat(md5, "updated")
			if err := store.Replace(ctx, updated); err != nil {
				t.Errorf("Replace(%s) error = %v", md5, err)
				return
			}

			got, err = store.Get(ctx, md5)
			if err != nil {
				t.Errorf("Get(%s) after Replace error = %v", md5, err)
				return
			}
			if !reflect.DeepEqual(got, updated) {
				t.Errorf("Get(%s) after Replace = %+v, want %+v", md5, got, updated)
			}
		}()
	}

	wg.Wait()
}
