package iamserver

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"golang.org/x/crypto/argon2"

	"github.com/kadisoka/iam/pkg/iam"
)

var (
	ErrPasswordHashFormatInvalid       = errors.New("hash format invalid")
	ErrPasswordHashVersionIncompatible = errors.New("hash version incompatible")
)

var argon2PasswordHashParamsEncoding = base64.RawStdEncoding

type argon2PasswordHashingParams struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

//TODO:make this configurable
var passwordHashingParams = argon2PasswordHashingParams{
	Memory:      64 * 1024,
	Iterations:  3,
	Parallelism: 2,
	SaltLength:  16,
	KeyLength:   32,
}

func (core *Core) SetUserPassword(
	callCtx iam.CallContext,
	userID iam.UserID,
	plainTextPassword string,
) error {
	authCtx := callCtx.Authorization()
	if !authCtx.IsUserContext() || authCtx.UserID != userID {
		return errors.New("forbidden")
	}

	hashedPassword, err := core.hashPassword(plainTextPassword)
	if err != nil {
		return err
	}

	tNow := time.Now().UTC()
	return doTx(core.db, func(tx *sqlx.Tx) error {
		_, txErr := core.db.Exec(
			`UPDATE user_passwords SET `+
				`deletion_time = $1, deletion_user_id = $2, deletion_terminal_id = $3 `+
				`WHERE user_id = $4 AND deletion_time IS NULL`,
			tNow, authCtx.UserID, authCtx.TerminalID(), userID)
		if txErr != nil {
			return txErr
		}
		_, txErr = core.db.Exec(
			`INSERT INTO user_passwords `+
				`(user_id, password, creation_time, creation_user_id, creation_terminal_id) `+
				`VALUES ($1, $2, $3, $4, $5) `,
			userID, hashedPassword,
			tNow, authCtx.UserID, authCtx.TerminalID())
		return nil
	})
}

func (core *Core) MatchUserPassword(
	userID iam.UserID,
	plainTextPassword string,
) (ok bool, err error) {
	hashedPassword, err := core.getUserHashedPassword(userID)
	if err != nil {
		return false, err
	}
	if hashedPassword == "" && plainTextPassword == hashedPassword {
		return true, err
	}
	return core.comparePasswordAndHashedPassword(plainTextPassword, hashedPassword)
}

func (core *Core) getUserHashedPassword(
	userID iam.UserID,
) (hashedPassword string, err error) {
	err = core.db.
		QueryRow(
			`SELECT password `+
				`FROM user_passwords `+
				`WHERE user_id = $1 AND deletion_time IS NULL`,
			userID).
		Scan(&hashedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}

	return hashedPassword, nil
}

func (core *Core) hashPassword(
	password string,
) (encodedHashedPassword string, err error) {
	params := passwordHashingParams

	// generate a chryptographically secure random salt
	salt, err := core.generatePasswordSalt(params.SaltLength)
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	// Base64 encode the salt and hashed password.
	b64Salt := argon2PasswordHashParamsEncoding.EncodeToString(salt)
	b64Hash := argon2PasswordHashParamsEncoding.EncodeToString(hash)

	// Return string using the standard encoded hash representation.
	encodedHashedPassword = fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, params.Memory, params.Iterations, params.Parallelism,
		b64Salt, b64Hash)

	return encodedHashedPassword, nil
}

func (core *Core) generatePasswordSalt(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (core *Core) comparePasswordAndHashedPassword(
	password, encodedHashedPassword string,
) (match bool, err error) {
	// Extract the parameters, salt and derived key from the encoded password
	// hash
	if encodedHashedPassword == "" {
		return false, nil
	}

	params, salt, hash, err := core.
		decodePasswordHash(encodedHashedPassword)
	if err != nil {
		return false, err
	}

	// Derive the key from the other password using the same parameters
	otherHash := argon2.IDKey([]byte(password), salt,
		params.Iterations, params.Memory, params.Parallelism, params.KeyLength)

	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return true, nil
	}

	return false, nil
}

func (core *Core) decodePasswordHash(
	encodedHashedPassword string,
) (params *argon2PasswordHashingParams, salt, hash []byte, err error) {
	vals := strings.Split(encodedHashedPassword, "$")

	if len(vals) != 6 {
		return nil, nil, nil, ErrPasswordHashFormatInvalid
	}

	var version int
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}

	if version != argon2.Version {
		return nil, nil, nil, ErrPasswordHashVersionIncompatible
	}

	params = &argon2PasswordHashingParams{}
	_, err = fmt.Sscanf(vals[3],
		"m=%d,t=%d,p=%d",
		&params.Memory, &params.Iterations, &params.Parallelism)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err = argon2PasswordHashParamsEncoding.DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, err
	}

	params.SaltLength = uint32(len(salt))

	hash, err = argon2PasswordHashParamsEncoding.DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, err
	}

	params.KeyLength = uint32(len(hash))

	return params, salt, hash, nil
}
