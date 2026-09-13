package access

type AccessError string

const (
	Forbidden    AccessError = "forbidden"
	Unauthorized AccessError = "unauthorized"
)
