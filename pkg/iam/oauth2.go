package iam

import (
	"github.com/citadelium/pkg/api/oauth2"
)

type OAuth2TokenResponse struct {
	oauth2.TokenResponse

	UserID string `json:"user_id,omitempty" schema:"user_id,omitempty"`

	TerminalID     string `json:"terminal_id,omitempty" schema:"terminal_id,omitempty"`
	TerminalSecret string `json:"terminal_secret,omitempty" schema:"terminal_secret,omitempty"`
}

// The OAuth2AuthorizePostResponse is used for responding successful POST /authorize
// request.
type OAuth2AuthorizePostResponse struct {
	RedirectURI string `json:"redirect_uri"`
}
