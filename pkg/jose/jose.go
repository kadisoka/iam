package jose

type HeaderParameter string

func (name HeaderParameter) String() string { return string(name) }
