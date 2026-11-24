package markstore

import (
	"context"
	"errors"
	"testing"
	"time"
)

// misread is how misreadLog answers reads of the names it lies about.
type misread int

const (
	readHonest  misread = iota
	getNotFound         // listed, but GET answers ErrNotFound
	lockFails           // the object's lock cannot be read
)

// misreadLog is memLog whose reads lie about the names in lie while its
// conditional create stays truthful.
type misreadLog struct {
	*memLog
	how misread
	lie map[string]bool
}

func (l *misreadLog) Get(ctx context.Context, e Entry) ([]byte, error) {
	if l.lie[e.Name] && l.how == getNotFound {
		return nil, ErrNotFound
	}
	return l.memLog.Get(ctx, e)
}

func (l *misreadLog) ObjectLock(ctx context.Context, e Entry) (ObjectLock, error) {
	if l.lie[e.Name] && l.how == lockFails {
		return ObjectLock{}, errors.New("injected: lock read timed out")
	}
	return l.memLog.ObjectLock(ctx, e)
}

// noLockLog is a store that cannot report an object's lock.
type noLockLog struct{ Log }

// A writer skips a name taken by an object that is not a record only if
// the object is locked in compliance mode for at least a record's
// retention (less lockMargin). Any other object stops the write with
// ErrNameTaken, without a latch and without writing past the name, so no
// writer gets past a name that someone could free later. Once the object
// is gone, the next write lands there.
func TestTakenNameSkippedOnlyWhenLocked(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	setup := testSetup("signer-1")
	keep := setup.Retention()
	long := ObjectLock{Mode: "COMPLIANCE", Compliance: true, RetainUntil: now.Add(2 * keep)}
	for _, c := range []struct {
		name  string
		lock  *ObjectLock // the lock of the object under the name; nil: none
		wrap  func(m *memLog, name string) Log
		flag  bool // the flag path: no setup, no lock days
		skips bool
	}{
		{name: "no retention"},
		{name: "governance mode", lock: &ObjectLock{Mode: "GOVERNANCE", RetainUntil: now.Add(2 * keep)}},
		{name: "compliance, one day", lock: &ObjectLock{Mode: "COMPLIANCE", Compliance: true, RetainUntil: now.Add(24 * time.Hour)}},
		{name: "compliance, a second short", lock: &ObjectLock{Mode: "COMPLIANCE", Compliance: true, RetainUntil: now.Add(keep - lockMargin - time.Second)}},
		{name: "lock read fails", lock: &long,
			wrap: func(m *memLog, name string) Log {
				return &misreadLog{memLog: m, how: lockFails, lie: map[string]bool{name: true}}
			}},
		{name: "store without object locks", lock: &long, wrap: func(m *memLog, _ string) Log { return noLockLog{m} }},
		{name: "flag path, retention not known", lock: &long, flag: true},
		{name: "compliance, exactly long enough", lock: &ObjectLock{Mode: "COMPLIANCE", Compliance: true, RetainUntil: now.Add(keep - lockMargin)}, skips: true},
		{name: "compliance, a record's retention", lock: &ObjectLock{Mode: "COMPLIANCE", Compliance: true, RetainUntil: now.Add(keep + 25*time.Hour)}, skips: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			opt := Options{Setup: setup, Clock: clockAt(&now), Log: quiet}
			var h [32]byte
			if c.flag {
				opt = Options{Log: quiet}
			} else {
				h = setup.Hash
			}
			name := func(v uint64) string { return Name(h, "signer-1", v) }
			mem := &memLog{objs: map[string][][]byte{}, locks: map[string]ObjectLock{}}
			var l Log = mem
			if c.wrap != nil {
				l = c.wrap(mem, name(5))
			}
			a, _ := New(l, "signer-1", testKey(1), opt)
			if _, _, err := a.Claim(ctx, false); err != nil {
				t.Fatal(err)
			}
			for e := uint64(5); e < 8; e++ {
				if err := a.Append(ctx, mark(e)); err != nil {
					t.Fatal(err)
				}
			}
			mem.objs[name(5)] = [][]byte{[]byte("not a record")}
			if c.lock != nil {
				mem.locks[name(5)] = *c.lock
			}
			err := a.Append(ctx, mark(9))
			_, v := a.Mark()
			if c.skips {
				if err != nil || v != 6 {
					t.Fatalf("append past a locked object: err %v, version %d, want 6", err, v)
				}
				return
			}
			if !errors.Is(err, ErrNameTaken) || v != 4 || len(mem.objs[name(6)]) != 0 {
				t.Fatalf("append over a name a deletable object holds: err %v, version %d, objects at 6: %d; "+
					"want ErrNameTaken and nothing written past the name", err, v, len(mem.objs[name(6)]))
			}
			if a.Lost() != nil {
				t.Fatalf("a taken name latched: %v", a.Lost())
			}
			// The object goes: the next write takes the name.
			delete(mem.objs, name(5))
			if err := a.Append(ctx, mark(9)); err != nil {
				t.Fatal(err)
			}
			if _, v := a.Mark(); v != 5 {
				t.Fatalf("after the object went: version %d, want 5", v)
			}
		})
	}
}

// More than maxSkips locked objects in a row stop the write too.
func TestLockedNamesBoundBySkips(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	opt := Options{Setup: testSetup("signer-1"), Clock: clockAt(&now), Log: quiet}
	name := func(v uint64) string { return Name(opt.Setup.Hash, "signer-1", v) }
	l := &memLog{objs: map[string][][]byte{}}
	m, _ := New(l, "signer-1", testKey(1), opt)
	if _, _, err := m.Claim(ctx, false); err != nil {
		t.Fatal(err)
	}
	for v := uint64(2); v < 2+maxSkips+1; v++ {
		l.objs[name(v)] = [][]byte{[]byte("junk")}
		l.lockFor(name(v), now.Add(opt.Setup.Retention()+25*time.Hour))
	}
	if err := m.Append(ctx, mark(11)); err == nil {
		t.Fatal("wrote past more locked names than maxSkips")
	}
}

// A listed object whose GET answers not found is not absent: the store
// lied, or the object went between the listing and the read. On the write
// path the read back of a taken name then fails without a skip and
// without a latch; the claim refuses to start.
func TestListedNameNotFoundFailsClosed(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	opt := Options{Setup: testSetup("signer-1"), Clock: clockAt(&now), Log: quiet}
	name := func(v uint64) string { return Name(opt.Setup.Hash, "signer-1", v) }
	written := func() *memLog {
		mem := &memLog{objs: map[string][][]byte{}}
		a, _ := New(mem, "signer-1", testKey(1), opt)
		if _, _, err := a.Claim(ctx, false); err != nil {
			t.Fatal(err)
		}
		for e := uint64(5); e < 8; e++ {
			if err := a.Append(ctx, mark(e)); err != nil {
				t.Fatal(err)
			}
		}
		return mem
	}

	t.Run("write: a clone record whose GET says not found", func(t *testing.T) {
		mem := written()
		l := &misreadLog{memLog: mem, lie: map[string]bool{}}
		a, _ := New(l, "signer-1", testKey(1), opt)
		if _, _, err := a.Claim(ctx, true); err != nil {
			t.Fatal(err)
		}
		_, va := a.Mark()
		b, _ := New(mem, "signer-1", testKey(1), opt)
		if _, _, err := b.Claim(ctx, true); err != nil {
			t.Fatal(err)
		}
		l.how, l.lie[name(va+1)] = getNotFound, true
		err := a.Append(ctx, mark(20))
		if _, v := a.Mark(); err == nil || v != va || len(mem.objs[name(va+2)]) != 0 {
			t.Fatalf("append over a listed record that reads as not found: err %v, version %d; "+
				"it must fail and write nothing past the name", err, v)
		}
		if a.Lost() != nil {
			t.Fatalf("a failed read back latched: %v", a.Lost())
		}
		l.how = readHonest
		if err := a.Append(ctx, mark(20)); !errors.Is(err, ErrLost) {
			t.Fatalf("once the read back answers: %v, want ErrLost", err)
		}
	})

	t.Run("claim: listed records that read as not found", func(t *testing.T) {
		mem := written()
		l := &misreadLog{memLog: mem, how: getNotFound, lie: map[string]bool{name(3): true, name(4): true}}
		b, _ := New(l, "signer-1", testKey(1), opt)
		got, _, err := b.Claim(ctx, true)
		if err == nil || len(mem.objs[name(5)]) != 0 {
			t.Fatalf("claim at mark target %d over records it could not read (err %v); it must fail and write nothing",
				got.TargetEpoch, err)
		}
	})
}

// Without a setup the log has no write age latch (staleLocked), which the
// skip rule needs: it never skips a taken name there, even with LockDays
// set and an object locked for longer than that.
func TestFlagPathNeverSkips(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	name := func(v uint64) string { return Name([32]byte{}, "signer-1", v) }
	l := &lockedMem{memLog: &memLog{objs: map[string][][]byte{}},
		lock: Lock{Kind: "mem", Mode: "COMPLIANCE", Compliance: true, Retention: 30 * 24 * time.Hour}}
	m, _ := New(l, "signer-1", testKey(1), Options{LockDays: 30, Now: func() time.Time { return now }, Log: quiet})
	if _, _, err := m.Claim(ctx, false); err != nil {
		t.Fatal(err)
	}
	l.objs[name(2)] = [][]byte{[]byte("junk")}
	l.lockFor(name(2), now.Add(365*24*time.Hour))
	if err := m.Append(ctx, mark(10)); !errors.Is(err, ErrNameTaken) || len(l.objs[name(3)]) != 0 {
		t.Fatalf("flag path append over a locked object: %v, objects at 3: %d; want ErrNameTaken and none", err, len(l.objs[name(3)]))
	}
}
