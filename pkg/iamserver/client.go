package iamserver

import (
	"encoding/csv"
	"errors"
	"os"
	"strings"

	"github.com/citadelium/iam/pkg/iam"
)

type ClientStaticDataProvider struct {
	clients map[iam.ClientID]*iam.Client
}

func NewClientStaticDataProviderFromCSVFilename(
	filename string, skipRows int,
) (*ClientStaticDataProvider, error) {
	csvFile, err := os.Open(filename)
	if err != nil {
		//TODO: translate errors
		return nil, err
	}
	defer csvFile.Close()

	rows, err := csv.NewReader(csvFile).ReadAll()
	if err != nil {
		//TODO: translate errors
		return nil, err
	}

	if len(rows) < (skipRows) {
		return nil, errors.New("header row required")
	}

	displayNameIdx := -1
	secretIdx := -1
	platformTypeIdx := -1
	requiredScopesIdx := -1
	oauth2RedirectURIIdx := -1

	for idx, key := range rows[0] {
		switch key {
		case "display_name":
			displayNameIdx = idx
		case "secret":
			secretIdx = idx
		case "platform_type":
			platformTypeIdx = idx
		case "required_scopes":
			requiredScopesIdx = idx
		case "oauth2_redirect_uri":
			oauth2RedirectURIIdx = idx
		}
	}

	indexexdValue := func(ls []string, idx int) string {
		if idx < 0 {
			return ""
		}
		if idx >= len(ls) {
			return ""
		}
		return ls[idx]
	}

	clList := map[iam.ClientID]*iam.Client{}
	for _, r := range rows[skipRows:] {
		var clID iam.ClientID
		clID, err = iam.ClientIDFromString(r[0])
		if err != nil {
			return nil, err
		}

		var requiredScopes []string
		if requiredScopeStr := indexexdValue(r, requiredScopesIdx); requiredScopeStr != "" {
			parts := strings.Split(requiredScopeStr, " ")
			if len(parts) == 1 {
				parts = strings.Split(requiredScopeStr, ",")
			}
			if len(parts) > 1 {
				for _, v := range parts {
					scopeStr := strings.TrimSpace(v)
					if scopeStr != "" {
						requiredScopes = append(requiredScopes, scopeStr)
					}
				}
			} else {
				requiredScopes = append(requiredScopes, requiredScopeStr)
			}
		}

		var redirectURIs []string
		if redirectURIStr := indexexdValue(r, oauth2RedirectURIIdx); redirectURIStr != "" {
			parts := strings.Split(redirectURIStr, ",")
			if len(parts) > 1 {
				for _, v := range parts {
					uriStr := strings.TrimSpace(v)
					if uriStr != "" {
						redirectURIs = append(redirectURIs, uriStr)
					}
				}
			} else {
				redirectURIs = append(redirectURIs, redirectURIStr)
			}
		}

		clList[clID] = &iam.Client{
			ID:                clID,
			DisplayName:       indexexdValue(r, displayNameIdx),
			Secret:            indexexdValue(r, secretIdx),
			PlatformType:      indexexdValue(r, platformTypeIdx),
			RequiredScopes:    requiredScopes,
			OAuth2RedirectURI: redirectURIs,
		}
	}

	return &ClientStaticDataProvider{clList}, nil
}

func (clientStaticDataStore *ClientStaticDataProvider) GetClient(
	clientID iam.ClientID,
) (*iam.Client, error) {
	cl := clientStaticDataStore.clients[clientID]
	return cl, nil
}
