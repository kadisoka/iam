package iam

import (
	"strconv"
	"strings"

	"github.com/nyaruka/phonenumbers"
)

// PhoneNumber represents a phone number as we need.
type PhoneNumber struct {
	countryCode    int32
	nationalNumber int64
	rawInput       string
	isValid        bool
}

func NewPhoneNumber(countryCode int32, nationalNumber int64) PhoneNumber {
	return PhoneNumber{countryCode: countryCode, nationalNumber: nationalNumber}
}

func PhoneNumberFromString(phoneNumberStr string) (PhoneNumber, error) {
	// Check if the country code is doubled
	if parts := strings.Split(phoneNumberStr, "+"); len(parts) == 3 {
		// We assume that the first part was automatically added at the client
		phoneNumberStr = "+" + parts[2]
	}

	parsedPhoneNumber, err := phonenumbers.Parse(phoneNumberStr, "")
	if err != nil {
		return PhoneNumber{}, err
	}

	phoneNumber := PhoneNumber{
		countryCode:    *parsedPhoneNumber.CountryCode,
		nationalNumber: int64(*parsedPhoneNumber.NationalNumber),
		rawInput:       phoneNumberStr,
		isValid:        phonenumbers.IsValidNumber(parsedPhoneNumber),
	}

	return phoneNumber, nil
}

func (phoneNumber PhoneNumber) IsValid() bool { return phoneNumber.isValid }

func (phoneNumber PhoneNumber) CountryCode() int32    { return phoneNumber.countryCode }
func (phoneNumber PhoneNumber) NationalNumber() int64 { return phoneNumber.nationalNumber }
func (phoneNumber PhoneNumber) RawInput() string      { return phoneNumber.rawInput }

//TODO: get E.164 string
//TODO: consult the standards
func (phoneNumber PhoneNumber) String() string {
	if phoneNumber.countryCode == 0 && phoneNumber.nationalNumber == 0 {
		return "+"
	}
	return "+" + strconv.FormatInt(int64(phoneNumber.countryCode), 10) +
		strconv.FormatInt(phoneNumber.nationalNumber, 10)
}
