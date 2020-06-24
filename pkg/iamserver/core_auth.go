package iamserver

import (
	"crypto/rand"
	"time"

	oldjwt "github.com/dgrijalva/jwt-go"
	apperrs "github.com/kadisoka/foundation/pkg/app/errors"
	"github.com/kadisoka/foundation/pkg/errors"
	"github.com/lib/pq"
	"github.com/square/go-jose/v3/jwt"

	"github.com/kadisoka/iam/pkg/iam"
	"github.com/kadisoka/iam/pkg/jose/jws"
)

func (core *Core) GenerateAccessTokenJWT(
	callCtx iam.CallContext,
	terminalID iam.TerminalID,
	userID iam.UserID,
) (tokenString string, err error) {
	if callCtx == nil {
		return "", errors.ArgMsg("callCtx", "missing")
	}

	jwtKeyChain := core.JWTKeyChain()
	if jwtKeyChain == nil {
		return "", apperrs.NewConfigurationMsg("JWT key chain is not configured")
	}
	signerKey, signerKeyID := jwtKeyChain.GetSigner()
	if signerKey == nil || signerKeyID == "" {
		return "", apperrs.NewConfigurationMsg("JWT key chain does not have any signing key")
	}

	authID, issueTime, err := core.
		generateAuthorizationID(callCtx, terminalID)
	if err != nil {
		return "", err
	}

	tokenClaims := &iam.AccessTokenClaims{
		Claims: jwt.Claims{
			ID:       authID.String(),
			IssuedAt: jwt.NewNumericDate(issueTime),
			Issuer:   core.RealmName(),
			Expiry:   jwt.NewNumericDate(issueTime.Add(iam.AccessTokenTTLDefault)),
			Subject:  userID.String(),
		},
		AuthorizedParty: terminalID.ClientID().String(),
		TerminalID:      terminalID.String(),
	}

	tokenData := oldjwt.NewWithClaims(oldjwt.SigningMethodRS256, tokenClaims)
	tokenData.Header[jws.JOSEHeaderParameterKeyID.String()] = signerKeyID
	tokenString, err = tokenData.SignedString(signerKey)
	return tokenString, err
}

func (core *Core) GenerateRefreshTokenJWT(
	terminalID iam.TerminalID,
	terminalSecret string,
) (tokenString string, err error) {
	jwtKeyChain := core.JWTKeyChain()
	if jwtKeyChain == nil {
		return "", apperrs.NewConfigurationMsg("JWT key chain is not configured")
	}
	signerKey, signerKeyID := jwtKeyChain.GetSigner()
	if signerKey == nil || signerKeyID == "" {
		return "", apperrs.NewConfigurationMsg("JWT key chain does not have any signing key")
	}

	issueTime := time.Now().UTC()

	tokenClaims := &iam.RefreshTokenClaims{
		NotBefore:      issueTime.Unix(),
		ExpiresAt:      issueTime.Add(iam.RefreshTokenTTLDefault).Unix(),
		TerminalID:     terminalID.String(),
		TerminalSecret: terminalSecret,
	}

	tokenData := oldjwt.NewWithClaims(oldjwt.SigningMethodRS256, tokenClaims)
	tokenData.Header[jws.JOSEHeaderParameterKeyID.String()] = signerKeyID
	tokenString, err = tokenData.SignedString(signerKey)
	return tokenString, err
}

func (core *Core) generateAuthorizationID(
	callCtx iam.CallContext,
	terminalID iam.TerminalID,
) (authID iam.AuthorizationID, issueTime time.Time, err error) {
	authCtx := callCtx.Authorization()

	const attemptNumMax = 3
	timeZero := time.Time{}
	tNow := timeZero
	var instanceID iam.AuthorizationInstanceID

	// Note:
	// - 0xffffffffffffff00 - timestamp
	// - 0x00000000000000ff - random
	genInstanceID := func(ts int64) (iam.AuthorizationInstanceID, error) {
		idBytes := make([]byte, 1)
		_, err := rand.Read(idBytes)
		if err != nil {
			return iam.AuthorizationInstanceIDZero, errors.Wrap("generation", err)
		}
		return iam.AuthorizationInstanceID((ts << 8) | int64(idBytes[0])), nil
	}

	for attemptNum := 0; ; attemptNum++ {
		tNow = time.Now().UTC()
		instanceID, err = genInstanceID(tNow.Unix())
		if err != nil {
			return iam.AuthorizationIDZero, timeZero, err
		}
		_, err = core.db.
			Exec(
				`INSERT INTO terminal_authorizations (`+
					`terminal_id, authorization_id, creation_time, creation_user_id, creation_terminal_id`+
					`) VALUES (`+
					`$1, $2, $3, $4, $5`+
					`)`,
				terminalID, instanceID, tNow, authCtx.UserIDPtr(), authCtx.TerminalIDPtr())
		if err == nil {
			break
		}

		pqErr, _ := err.(*pq.Error)
		if pqErr != nil &&
			pqErr.Code == "23505" &&
			pqErr.Constraint == "terminal_authorizations_pkey" {
			if attemptNum >= attemptNumMax {
				return iam.AuthorizationIDZero, timeZero, errors.Wrap("insert max attempts", err)
			}
			continue
		}
		return iam.AuthorizationIDZero, timeZero, errors.Wrap("insert", err)
	}

	return iam.AuthorizationID{
		TerminalID: terminalID,
		InstanceID: instanceID,
	}, tNow, nil
}
