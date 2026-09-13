package access

// AccessContext — данные доступа, прикрепляемые к запросу после успешной проверки прав.
type AccessContext struct {
	User      string
	Role      string
	Group     string
	Condition AccessContextCondition
}

// AccessContextCondition — правила видимости/фильтрации полей, вычисленные по условиям политики.
type AccessContextCondition struct {
	Show   []string
	Hide   []string
	Filter map[string][]string
}

type Policy struct {
	Conditions  map[string]map[string][]Condition  `json:"conditions"`
	Permissions map[string]map[string][]Permission `json:"permissions"`
}

type Permission struct {
	ID       string           `json:"id,omitempty"`
	Role     string           `json:"role"`
	Service  string           `json:"service"`
	Resource string           `json:"resource"`
	Action   PermissionAction `json:"action"`
	Effect   PermissionEffect `json:"effect"`
}

type PermissionAction string
type PermissionScope string
type PermissionEffect string

const (
	PermissionScopeOwn PermissionScope = "own"
	PermissionScopeAny PermissionScope = "any"
)

const (
	PermissionActionAll     PermissionAction = "all"
	PermissionActionRead    PermissionAction = "read"
	PermissionActionWrite   PermissionAction = "write"
	PermissionActionEdit    PermissionAction = "edit"
	PermissionActionDelete  PermissionAction = "delete"
	PermissionActionExecute PermissionAction = "execute"
)

const (
	PermissionEffectAllow PermissionEffect = "allow"
	PermissionEffectDeny  PermissionEffect = "deny"
)

type Condition struct {
	ID        string           `json:"id,omitempty"`
	Group     string           `json:"group"`
	Service   string           `json:"service"`
	Resource  string           `json:"resource"`
	Action    PermissionAction `json:"action"`
	Operation string           `json:"operation"`
	Field     string           `json:"field"`

	// при работе с полями оставляется пустым;
	// если нужны конкретные значения, то они указываются тут
	Value []string `json:"value"`
}

type ConditionOperation string

const (
	ConditionOperationFilter ConditionOperation = "filter"
	ConditionOperationHide   ConditionOperation = "hide"
	ConditionOperationShow   ConditionOperation = "show"
)
