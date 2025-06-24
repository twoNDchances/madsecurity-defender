package globals

type Application struct {
	Groups    ListGroup    `json:"groups"`
	Rules     ListRule     `json:"rules"`
	Targets   ListTarget   `json:"targets"`
	Wordlists ListWordlist `json:"wordlists"`
	Words     ListWord     `json:"words"`
}

type Revocation struct {
	Groups    ListUint `json:"groups"`
	Rules     ListUint `json:"rules"`
	Targets   ListUint `json:"targets"`
	Wordlists ListUint `json:"wordlists"`
}

type Group struct {
	ID             uint     `json:"id"`
	ExecutionOrder uint     `json:"execution_order"`
	Level          uint     `json:"level"`
	Name           string   `json:"name"`
	Rules          ListUint `json:"rules"`
	DefenderID     uint     `json:"defender_id"`
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

type Wordlist struct {
	ID    uint
	Name  string
	Alias string
}

type Word struct {
	ID         uint
	Content    string
	WordlistID uint
}
