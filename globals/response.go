package globals

type Application struct {
	Groups    []Group    `json:"groups"`
	Rules     []Rule     `json:"rules"`
	Targets   []Target   `json:"targets"`
	Wordlists []Wordlist `json:"wordlists"`
	Words     []Word     `json:"words"`
}

type Revocation struct {
	Groups    ListUint `json:"groups"`
	Rules     ListUint `json:"rules"`
	Targets   ListUint `json:"targets"`
	Wordlists ListUint `json:"wordlists"`
	Words     ListUint `json:"words"`
}

type Implementation struct {
	Decisions []Decision `json:"decisions"`
	Wordlists []Wordlist `json:"wordlists"`
	Words     []Word     `json:"words"`
}

type Suspension struct {
	Decisions ListUint `json:"decisions"`
	Wordlists ListUint `json:"wordlists"`
	Words     ListUint `json:"words"`
}

// ##############################################
// ##############################################
// ##############################################

type Group struct {
	ID             uint     `json:"id"`
	ExecutionOrder uint     `json:"execution_order"`
	Level          uint     `json:"level"`
	Name           string   `json:"name"`
	Rules          ListUint `json:"rules"`
	DefenderID     uint     `json:"defender_id"`
}

func (g Group) GetID() uint {
	return g.ID
}

func (g Group) GetHashID() uint {
	return g.GetID()
}

// ##############################################
// ##############################################
// ##############################################

type Rule struct {
	ID                  uint    `json:"id"`
	Name                string  `json:"name"`
	Alias               string  `json:"alias"`
	Phase               uint8   `json:"phase"`
	TargetID            uint    `json:"target_id"`
	Comparator          string  `json:"comparator"`
	Inverse             bool    `json:"inverse"`
	Value               *string `json:"value"`
	Action              *string `json:"action"`
	ActionConfiguration *string `json:"action_configuration"`
	Severity            *string `json:"severity"`
	Log                 bool    `json:"log"`
	Time                bool    `json:"time"`
	UserAgent           bool    `json:"user_agent"`
	ClientIP            bool    `json:"client_ip"`
	Method              bool    `json:"method"`
	Path                bool    `json:"path"`
	WordlistID          *uint   `json:"wordlist_id"`
	Output              bool    `json:"output"`
	Target              bool    `json:"target"`
	Rule                bool    `json:"rule"`
}

func (r Rule) GetID() uint {
	return r.ID
}

// ##############################################
// ##############################################
// ##############################################

type Target struct {
	ID                  uint    `json:"id"`
	Name                string  `json:"name"`
	Alias               string  `json:"alias"`
	Type                string  `json:"type"`
	Engine              *string `json:"engine"`
	EngineConfiguration *string `json:"engine_configuration"`
	Phase               uint8   `json:"phase"`
	Datatype            string  `json:"datatype"`
	FinalDatatype       string  `json:"final_datatype"`
	Immutable           bool    `json:"immutable"`
	TargetID            *uint   `json:"target_id"`
	WordlistID          *uint   `json:"wordlist_id"`
}

func (t Target) GetID() uint {
	return t.ID
}

// ##############################################
// ##############################################
// ##############################################

type Wordlist struct {
	ID    uint   `json:"id"`
	Name  string `json:"name"`
	Alias string `json:"alias"`
}

func (w Wordlist) GetID() uint {
	return w.ID
}

// ##############################################
// ##############################################
// ##############################################

type Word struct {
	ID         uint   `json:"id"`
	Content    string `json:"content"`
	WordlistID uint   `json:"wordlist_id"`
}

func (w Word) GetID() uint {
	return w.ID
}

// ##############################################
// ##############################################
// ##############################################

type Decision struct {
	ID                  uint    `json:"id"`
	Name                string  `json:"name"`
	PhaseType           string  `json:"phase_type"`
	Score               int     `json:"score"`
	Action              string  `json:"action"`
	ActionConfiguration *string `json:"action_configuration"`
	WordlistID          *uint   `json:"wordlist_id"`
}

func (d Decision) GetID() uint {
	return d.ID
}
