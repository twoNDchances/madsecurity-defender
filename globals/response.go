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
}

type Identifiable interface {
	GetID() uint
}

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

type Rule struct {
	ID                  uint    `json:"id"`
	Name                string  `json:"name"`
	Alias               string  `json:"alias"`
	Phase               uint8   `json:"phase"`
	TargetID            uint    `json:"target_id"`
	Comparator          string  `json:"comparator"`
	Inverse             bool    `json:"inverse"`
	Value               string  `json:"value"`
	Action              *string `json:"action"`
	ActionConfiguration *string `json:"action_configuration"`
	Severity            *string `json:"severity"`
	Log                 bool    `json:"log"`
	Time                bool    `json:"time"`
	Status              bool    `json:"status"`
	UserAgent           bool    `json:"user_agent"`
	ClientIP            bool    `json:"client_ip"`
	Method              bool    `json:"method"`
	Path                bool    `json:"path"`
	WordlistID          *uint   `json:"wordlist_id"`
}

func (r Rule) GetID() uint {
	return r.ID
}

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
	TargetID            *uint   `json:"target_id"`
	WordlistID          *uint   `json:"wordlist_id"`
}

func (t Target) GetID() uint {
	return t.ID
}

type Wordlist struct {
	ID    uint
	Name  string
	Alias string
}

func (w Wordlist) GetID() uint {
	return w.ID
}

type Word struct {
	ID         uint
	Content    string
	WordlistID uint
}

func (w Word) GetID() uint {
	return w.ID
}
