package globals

import (
	"sort"
	"sync"
)

var (
	IsPaused bool
	PauseMtx sync.Mutex
	PauseCnd = sync.NewCond(&PauseMtx)

	ListGroups = make([]Group, 0)

	Groups         = make(map[uint]Group, 0)
	Rules          = make(map[uint]Rule, 0)
	Targets        = make(map[uint]Target, 0)
	Wordlists      = make(map[uint]Wordlist, 0)
	Words          = make(map[uint]Word, 0)
	ViolationScore int
	ViolationLevel int

	// BackendConfigs  *Backend
	// LogConfigs      *Log
	// ProxyConfigs    *Proxy
	// SecurityConfigs *Security
	// ServerConfigs   *Server
	// StorageConfigs  *Storage
)

func ContainsID[T Identifiable](models []Identifiable, id uint) bool {
	for _, item := range models {
		if item.GetID() == id {
			return true
		}
	}
	return false
}

func Validate(validators ...error) ListError {
	errors := make(ListError, 0)
	for _, validator := range validators {
		if validator != nil {
			errors = append(errors, validator)
		}
	}
	return errors
}

func SortGroup(groups []Group) {
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].ExecutionOrder < groups[j].ExecutionOrder
	})
}
