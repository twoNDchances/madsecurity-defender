package globals

type (
	Identifiable interface {
		GetID() uint
	}

	Instructable interface {
		GetEntry() Entry
	}
)
