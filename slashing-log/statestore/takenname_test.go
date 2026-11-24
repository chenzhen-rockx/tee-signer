package statestore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/slashing-log"
)

// A commit skips a name taken by an object that is not a commit only if
// the object is locked in compliance mode at least as long as a commit
// gets (Options.RetainDays). An object without retention stops the commit
// (markstore.ErrNameTaken) and nothing is written past it, so a clone
// cannot commit beside the first instance once the object is deleted.
func TestCommitSkipsOnlyLockedNames(t *testing.T) {
	const days = 30
	opt := Options{RetainDays: days}
	plant := func(l *memLog, lock *markstore.ObjectLock) []string {
		var planted []string
		for v := uint64(2); v < 2+maxSkips; v++ {
			n := Name(setupA, "signer-1", v)
			l.objs[n] = [][]byte{[]byte("not a commit")}
			if lock != nil {
				l.locks[n] = *lock
			}
			planted = append(planted, n)
		}
		return planted
	}
	top := Name(setupA, "signer-1", 2+maxSkips)

	t.Run("no retention: the clone stops", func(t *testing.T) {
		l := newMemLog()
		l.locks = map[string]markstore.ObjectLock{}
		a, _ := open(t, newLocal(t), l, keysOf("image-a"), opt)
		if err := a.Put("shares/aa", []byte("x")); err != nil {
			t.Fatal(err)
		}
		b, err := open(t, newLocal(t), l, keysOf("image-a"), opt)
		if err != nil {
			t.Fatal(err)
		}
		planted := plant(l, nil)
		err = b.Put("shares/bb", []byte("b"))
		if !errors.Is(err, markstore.ErrNameTaken) || len(l.objs[top]) != 0 {
			t.Fatalf("clone commit over deletable objects: %v, objects past them: %d; want ErrNameTaken and none", err, len(l.objs[top]))
		}
		for _, n := range planted {
			delete(l.objs, n)
		}
		if err := a.Put("shares/cc", []byte("a")); err != nil {
			t.Fatalf("A once the names are free: %v", err)
		}
		if err := b.Put("shares/bb", []byte("b")); err == nil {
			t.Fatal("the clone committed after A did: two writers of one copy")
		}
	})

	t.Run("compliance for a record retention: skipped", func(t *testing.T) {
		l := newMemLog()
		l.locks = map[string]markstore.ObjectLock{}
		a, _ := open(t, newLocal(t), l, keysOf("image-a"), opt)
		if err := a.Put("shares/aa", []byte("x")); err != nil {
			t.Fatal(err)
		}
		b, _ := open(t, newLocal(t), l, keysOf("image-a"), opt)
		plant(l, &markstore.ObjectLock{Mode: "COMPLIANCE", Compliance: true, RetainUntil: time.Now().Add(days*24*time.Hour + time.Hour)})
		if err := b.Put("shares/bb", []byte("b")); err != nil || len(l.objs[top]) != 1 {
			t.Fatalf("clone commit past locked objects: %v", err)
		}
		if err := a.Put("shares/cc", []byte("a")); !errors.Is(err, ErrLost) {
			t.Fatalf("A past the same locked objects: %v, want ErrLost", err)
		}
	})

	t.Run("governance or short: the commit stops", func(t *testing.T) {
		for _, lk := range []markstore.ObjectLock{
			{Mode: "GOVERNANCE", RetainUntil: time.Now().Add(2 * days * 24 * time.Hour)},
			{Mode: "COMPLIANCE", Compliance: true, RetainUntil: time.Now().Add(24 * time.Hour)},
		} {
			l := newMemLog()
			l.locks = map[string]markstore.ObjectLock{}
			a, _ := open(t, newLocal(t), l, keysOf("image-a"), opt)
			if err := a.Put("shares/aa", []byte("x")); err != nil {
				t.Fatal(err)
			}
			plant(l, &lk)
			if err := a.Put("shares/bb", []byte("b")); !errors.Is(err, markstore.ErrNameTaken) || len(l.objs[top]) != 0 {
				t.Fatalf("%s: commit over the objects: %v", lk.Mode, err)
			}
		}
	})

	t.Run("no retention known: the commit stops", func(t *testing.T) {
		l := newMemLog()
		l.locks = map[string]markstore.ObjectLock{}
		a, _ := open(t, newLocal(t), l, keysOf("image-a"), Options{})
		if err := a.Put("shares/aa", []byte("x")); err != nil {
			t.Fatal(err)
		}
		plant(l, &markstore.ObjectLock{Mode: "COMPLIANCE", Compliance: true, RetainUntil: time.Now().Add(365 * 24 * time.Hour)})
		if err := a.Put("shares/bb", []byte("b")); !errors.Is(err, markstore.ErrNameTaken) {
			t.Fatalf("commit over locked objects without RetainDays: %v", err)
		}
	})
}

// notFoundLog answers ErrNotFound for every GET of the names in lie.
type notFoundLog struct {
	*memLog
	lie map[string]bool
}

func (l *notFoundLog) Get(ctx context.Context, e markstore.Entry) ([]byte, error) {
	if l.lie[e.Name] {
		return nil, markstore.ErrNotFound
	}
	return l.memLog.Get(ctx, e)
}

// A listed commit whose GET answers not found is not absent: the restore
// refuses to start rather than take the commit below it.
func TestListedCommitNotFoundFailsClosed(t *testing.T) {
	l := newMemLog()
	a, _ := open(t, newLocal(t), l, keysOf("image-a"), Options{})
	a.Put("shares/aa", []byte("v1"))
	a.Put("shares/aa", []byte("v2"))
	nl := &notFoundLog{memLog: l, lie: map[string]bool{Name(setupA, "signer-1", 2): true}}
	fresh := newLocal(t)
	if _, err := open(t, fresh, nl, keysOf("image-a"), Options{}); err == nil {
		v, _ := fresh.Get("shares/aa")
		t.Fatalf("restored %q over a listed commit that reads as not found; the start must fail", v)
	}
}
