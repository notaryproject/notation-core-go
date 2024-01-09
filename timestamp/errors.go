package timestamp

// MalformedRequestError is used when timestamping request is malformed.
type MalformedRequestError struct {
	msg string
}

func (e MalformedRequestError) Error() string {
	if e.msg != "" {
		return e.msg
	}
	return "malformed timestamping request"
}
