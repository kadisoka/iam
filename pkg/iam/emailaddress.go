package iam

import (
	"regexp"
	"strings"

	"github.com/citadelium/pkg/errors"
	dataerrs "github.com/citadelium/pkg/errors/data"
)

//NOTE: actually, it's not recommended to use regex to
// identify if a string is an email address:
// https://www.regular-expressions.info/email.html
var emailAddressRE = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
var emailAddressDomainRE = regexp.MustCompile("^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

func IsValidEmailAddress(str string) bool {
	return emailAddressRE.MatchString(str)
}

type EmailAddress struct {
	localPart  string
	domainPart string
	rawInput   string
}

func EmailAddressFromString(str string) (EmailAddress, error) {
	parts := strings.SplitN(str, "@", 2)
	if len(parts) < 2 {
		return EmailAddress{}, dataerrs.ErrMalformed
	}
	//TODO(exa): normalize localPart and domainPart
	if parts[0] == "" {
		return EmailAddress{}, errors.EntMsg("local part", "empty")
	}
	if parts[1] == "" || !emailAddressDomainRE.MatchString(parts[1]) {
		return EmailAddress{}, errors.Ent("domain part", nil)
	}
	//TODO(exa): perform more extensive checking

	return EmailAddress{
		localPart:  parts[0],
		domainPart: strings.ToLower(parts[1]),
		rawInput:   str,
	}, nil
}

//TODO: at least common address convention
func (emailAddress EmailAddress) IsValid() bool {
	return emailAddress.localPart != "" && emailAddress.domainPart != ""
}

func (emailAddress EmailAddress) String() string {
	return emailAddress.localPart + "@" + emailAddress.domainPart
}

func (emailAddress EmailAddress) LocalPart() string {
	return emailAddress.localPart
}

func (emailAddress EmailAddress) DomainPart() string {
	return emailAddress.domainPart
}

func (emailAddress EmailAddress) RawInput() string {
	return emailAddress.rawInput
}
