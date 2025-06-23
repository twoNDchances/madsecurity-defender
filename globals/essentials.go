package globals

import "sync"

var (
	IsPaused  bool
	PauseMtx   sync.Mutex
	PauseCnd = sync.NewCond(&PauseMtx)

	capacity = 100000

	Groups    = make(ListGroup, 0, capacity)
	Rules     = make(ListRule, 0, capacity)
	Targets   = make(ListTarget, 0, capacity)
	Wordlists = make(ListWordlist, 0, capacity)
	Words     = make(ListWord, 0, capacity)
)
