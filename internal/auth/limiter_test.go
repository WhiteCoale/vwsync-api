package auth

import (
	"strconv"
	"testing"
	"time"
)

func TestLimiterForgetsClientsThatNeverReturn(t *testing.T) {
	now := time.Now()
	l := NewLimiter(5, time.Minute)
	l.now = func() time.Time { return now }

	for i := 0; i < 200; i++ {
		l.Fail("ip-" + strconv.Itoa(i)) // each fails once and is never seen again
	}
	if l.Tracked() != 200 {
		t.Fatalf("tracked %d", l.Tracked())
	}
	now = now.Add(2 * time.Minute)
	l.Fail("someone-new")
	if got := l.Tracked(); got != 1 {
		t.Fatalf("expired clients stay in memory: %d tracked", got)
	}
}

func TestLimiterNeverTracksMoreThanTheCap(t *testing.T) {
	l := NewLimiter(5, time.Hour) // nothing expires, only the cap can bound the memory
	for i := 0; i < maxTracked*3; i++ {
		l.Fail("ip-" + strconv.Itoa(i))
	}
	if got := l.Tracked(); got > maxTracked {
		t.Fatalf("tracked %d clients, cap is %d", got, maxTracked)
	}
}

func TestLimiterStillBlocksAfterASweep(t *testing.T) {
	now := time.Now()
	l := NewLimiter(3, time.Minute)
	l.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		l.Fail("attacker")
	}
	now = now.Add(30 * time.Second) // within the window
	l.Fail("other")
	if blocked, _ := l.Blocked("attacker"); !blocked {
		t.Fatal("a sweep must not release a client that is still inside its window")
	}
}
