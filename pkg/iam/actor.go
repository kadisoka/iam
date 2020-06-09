package iam

// Actor provides information about who or what performed an action.
//
//TODO: assuming actor
type Actor struct {
	// UserID is the ID of the user who performed the action. This might be
	// empty if the action was performed by non-user-representing agent.
	UserID UserID
	// TerminalID is the ID of the terminal where the action was initiated
	// from.
	TerminalID TerminalID
}
