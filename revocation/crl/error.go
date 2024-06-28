package crl

type staledDeltaCRL struct{}

func (e staledDeltaCRL) Error() string {
	return "delta CRL is staled"
}

type noDeltaCRL struct{}

func (e noDeltaCRL) Error() string {
	return "no delta CRL found"
}
