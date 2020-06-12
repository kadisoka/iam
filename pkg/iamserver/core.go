//

package iamserver

import (
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/golang-lru"
	"github.com/jmoiron/sqlx"
	"github.com/kadisoka/foundation/pkg/app"
	"github.com/kadisoka/foundation/pkg/errors"
	mediastore "github.com/kadisoka/foundation/pkg/media/store"
	_ "github.com/lib/pq"

	"github.com/kadisoka/iam/pkg/iam"
	"github.com/kadisoka/iam/pkg/iamserver/eav10n"
	"github.com/kadisoka/iam/pkg/iamserver/pnv10n"

	// SMS delivery service providers
	_ "github.com/kadisoka/iam/pkg/iamserver/pnv10n/nexmo"
	_ "github.com/kadisoka/iam/pkg/iamserver/pnv10n/telesign"
	_ "github.com/kadisoka/iam/pkg/iamserver/pnv10n/twilio"

	// Media object storage modules
	_ "github.com/kadisoka/foundation/pkg/media/store/minio"
	_ "github.com/kadisoka/foundation/pkg/media/store/s3"
)

const secretFilesDir = "/run/secrets"

type Core struct {
	realmName                 string
	db                        *sqlx.DB
	registeredUserIDCache     *lru.ARCCache
	deletedUserAccountIDCache *lru.ARCCache

	iam.ServiceClient //TODO: not specifically client

	clientDataProvider iam.ClientDataProvider
	mediaStore         *mediastore.Store

	eaVerifier *eav10n.Verifier
	pnVerifier *pnv10n.Verifier
}

func (core Core) RealmName() string { return core.realmName }

// NewCoreByConfig creates an instance of Core designed for use
// in identity provider services.
func NewCoreByConfig(coreCfg CoreConfig, appApp app.App) (*Core, error) {
	appInfo := appApp.AppInfo()
	appName := appInfo.Name

	realmName := coreCfg.RealmName
	if realmName == "" {
		realmName = appName
	}
	iamDB, err := connectPostgres(coreCfg.DBURL)
	if err != nil {
		return nil, errors.Wrap("DB connection", err)
	}

	//TODO: get from secret storage (e.g., vault or AWS secret manager)
	jwtPrivateKeyFilename := filepath.Join(secretFilesDir, "jwt.key")
	jwtKeyChain, err := iam.NewJWTKeyChainFromFiles(jwtPrivateKeyFilename, "")
	if err != nil {
		return nil, errors.Wrap("JWT key chain loading", err)
	}

	// NOTE: We should store these data into a database instead of CSV file.
	clientDataCSVFilename := filepath.Join(secretFilesDir, "clients.csv")
	clientDataProvider, err := NewClientStaticDataProviderFromCSVFilename(
		clientDataCSVFilename, 1)
	if err != nil {
		return nil, errors.Wrap("client data loading", err)
	}

	log.Info().Msg("Initializing media service...")
	log.Info().Msgf("Registered media object storage service integrations: %v",
		mediastore.ModuleNames())
	mediaStore, err := mediastore.New(coreCfg.Media)
	if err != nil {
		return nil, errors.Wrap("file service initialization", err)
	}

	log.Info().Msg("Initializing email-address verification services...")
	eaVerifier := eav10n.NewVerifier(appApp.AppInfo(), iamDB, coreCfg.EAV)

	log.Info().Msg("Initializing phone-number verification service...")
	log.Info().Msgf("Registered SMS delivery service integrations: %v", pnv10n.ModuleNames())
	pnVerifier := pnv10n.NewVerifier(appName, iamDB, coreCfg.PNV)

	registeredUserIDCache, err := lru.NewARC(65535)
	if err != nil {
		panic(err)
	}
	deletedUserAccountIDCache, err := lru.NewARC(65535)
	if err != nil {
		panic(err)
	}

	inst := &Core{
		realmName:                 realmName,
		db:                        iamDB,
		registeredUserIDCache:     registeredUserIDCache,
		deletedUserAccountIDCache: deletedUserAccountIDCache,
		clientDataProvider:        clientDataProvider,
		mediaStore:                mediaStore,
		eaVerifier:                eaVerifier,
		pnVerifier:                pnVerifier,
	}

	clientBase, err := iam.NewServiceClient(nil, jwtKeyChain, inst)
	if err != nil {
		panic(err)
	}

	inst.ServiceClient = clientBase

	return inst, nil
}

func (core *Core) IsTestPhoneNumber(phoneNumber iam.PhoneNumber) bool {
	return phoneNumber.CountryCode() == 1 &&
		phoneNumber.NationalNumber() > 5550000 &&
		phoneNumber.NationalNumber() <= 5559999
}

func (core *Core) IsTestEmailAddress(emailAddress iam.EmailAddress) bool {
	return false
}

func connectPostgres(dbURL string) (*sqlx.DB, error) {
	var db *sqlx.DB
	parsedURL, err := url.Parse(dbURL)
	if err != nil {
		return nil, err
	}

	var maxIdleConns, maxOpenConns int64
	queryPart := parsedURL.Query()
	if maxIdleConnsStr := queryPart.Get("max_idle_conns"); maxIdleConnsStr != "" {
		queryPart.Del("max_idle_conns")
		maxIdleConns, err = strconv.ParseInt(maxIdleConnsStr, 10, 32)
		if err != nil {
			return nil, errors.Wrap("unable to parse max_idle_conns query parameter", err)
		}
	}
	if maxOpenConnsStr := queryPart.Get("max_open_conns"); maxOpenConnsStr != "" {
		queryPart.Del("max_open_conns")
		maxOpenConns, err = strconv.ParseInt(maxOpenConnsStr, 10, 32)
		if err != nil {
			return nil, errors.Wrap("unable to parse max_open_conns query parameter", err)
		}
	}
	if maxIdleConns == 0 {
		maxIdleConns = 2
	}
	if maxOpenConns == 0 {
		maxOpenConns = 8
	}

	parsedURL.RawQuery = queryPart.Encode()
	dbURL = parsedURL.String()
	for {
		db, err = sqlx.Connect("postgres", dbURL)
		if err == nil {
			break
		}
		if !strings.Contains(err.Error(), "connect: connection refused") {
			return nil, err
		}
		const retryDuration = 5 * time.Second
		time.Sleep(retryDuration)
	}
	if db != nil {
		db.SetMaxIdleConns(int(maxIdleConns))
		db.SetMaxOpenConns(int(maxOpenConns))
	}
	return db, nil
}

type CoreConfig struct {
	RealmName string            `env:"REALM_NAME"`
	DBURL     string            `env:"DB_URL,required"`
	Media     mediastore.Config `env:"MEDIA"`
	EAV       eav10n.Config     `env:"EAV"`
	PNV       pnv10n.Config     `env:"PNV"`
}

// CoreConfigSkeleton returns an instance of CoreConfig which has been
// configured to load config based on the internal system configuration.
// One kind of usages for a skeleton is to generate a template or documentations.
func CoreConfigSkeleton() CoreConfig {
	return CoreConfig{
		Media: mediastore.ConfigSkeleton(),
		PNV:   pnv10n.ConfigSkeleton(),
	}
}

func CoreConfigSkeletonPtr() *CoreConfig {
	cfg := CoreConfigSkeleton()
	return &cfg
}
