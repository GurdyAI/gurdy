package policy

import (
	"fmt"
	"sync"
)

const maxHistory = 5

// Store holds the evaluator in force, hot-swappable with versioned rollback
// (FR-10). Readers get a consistent evaluator+version pair per decision;
// swaps never disturb in-flight evaluations.
type Store struct {
	mu      sync.RWMutex
	current *Evaluator
	history []*Evaluator // most recent last
}

func NewStore(ev *Evaluator) *Store {
	return &Store{current: ev}
}

// Current returns the evaluator in force.
func (s *Store) Current() *Evaluator {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

// Swap installs a new evaluator; the old one goes to rollback history.
func (s *Store) Swap(ev *Evaluator) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.history = append(s.history, s.current)
	if len(s.history) > maxHistory {
		s.history = s.history[1:]
	}
	s.current = ev
}

// Rollback reinstates the previous bundle. The rolled-back-from bundle is
// discarded, not re-pushed — repeated rollback walks further into history.
func (s *Store) Rollback() (*Evaluator, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.history) == 0 {
		return nil, fmt.Errorf("policy: no bundle to roll back to")
	}
	s.current = s.history[len(s.history)-1]
	s.history = s.history[:len(s.history)-1]
	return s.current, nil
}

// Versions lists the current and rollback-history bundle versions.
func (s *Store) Versions() (current string, history []string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, ev := range s.history {
		history = append(history, ev.Version)
	}
	return s.current.Version, history
}
