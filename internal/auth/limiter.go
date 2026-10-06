package auth

import (
	"sync"
	"time"
)

// maxTracked caps the number of clients the limiter remembers, so a flood of distinct addresses
// cannot grow memory without bound.
const maxTracked = 10000

// Limiter blocks a client after too many failed logins within a window. In memory only,
// which is enough for one process; a restart resets it.
type Limiter struct {
	mu        sync.Mutex
	max       int
	window    time.Duration
	failures  map[string][]time.Time
	lastSweep time.Time
	now       func() time.Time
}

func NewLimiter(max int, window time.Duration) *Limiter {
	return &Limiter{max: max, window: window, failures: map[string][]time.Time{}, now: time.Now}
}

// Blocked reports whether key must wait, and for how long.
func (l *Limiter) Blocked(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	recent := l.prune(key)
	if len(recent) >= l.max {
		return true, recent[0].Add(l.window).Sub(l.now())
	}
	return false, 0
}

// Fail records a failed login.
func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweep()
	l.failures[key] = append(l.prune(key), l.now())
}

// Reset forgets a client after a successful login.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, key)
}

// Tracked is the number of clients currently remembered.
func (l *Limiter) Tracked() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.failures)
}

func (l *Limiter) prune(key string) []time.Time {
	cutoff := l.now().Add(-l.window)
	recent := l.failures[key][:0]
	for _, t := range l.failures[key] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	if len(recent) == 0 {
		delete(l.failures, key)
	} else {
		l.failures[key] = recent
	}
	return recent
}

// sweep drops every expired client. prune only cleans the key being asked about, so without this a
// client that fails once and never returns would stay in memory forever. It runs at most once per
// window, and when the cap is still exceeded afterwards it evicts arbitrary clients down to 90%.
func (l *Limiter) sweep() {
	if l.now().Sub(l.lastSweep) < l.window && len(l.failures) < maxTracked {
		return
	}
	l.lastSweep = l.now()
	for key := range l.failures {
		l.prune(key)
	}
	for key := range l.failures {
		if len(l.failures) <= maxTracked*9/10 {
			break
		}
		delete(l.failures, key)
	}
}
