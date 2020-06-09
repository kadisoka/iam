package iam

type IAMService interface {
	ServiceClient

	UserService

	TerminalService

	// This below is reserverd for S2S services.
	UserTerminalService
}
