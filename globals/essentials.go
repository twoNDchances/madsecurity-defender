package globals

import "sync"

var (
	IsPaused bool
	PauseMtx sync.Mutex
	PauseCnd = sync.NewCond(&PauseMtx)

	capacity = 100000

	Groups    = make([]Group, 0, capacity)
	Rules     = make([]Rule, 0, capacity)
	Targets   = make([]Target, 0, capacity)
	Wordlists = make([]Wordlist, 0, capacity)
	Words     = make([]Word, 0, capacity)

	TmpGroups    = make([]Group, 0, capacity)
	TmpRules     = make([]Rule, 0, capacity)
	TmpTargets   = make([]Target, 0, capacity)
	TmpWordlists = make([]Wordlist, 0, capacity)
	TmpWords     = make([]Word, 0, capacity)
)

func ContainsID[T Identifiable](models []Identifiable, id uint) bool {
	for _, item := range models {
		if item.GetID() == id {
			return true
		}
	}
	return false
}
