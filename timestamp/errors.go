package timestamp

// MalformedRequestError is used when timestamping request is malformed.
type MalformedRequestError struct {
	msg string
}

func (e MalformedRequestError) Error() string {
	return e.msg
}
