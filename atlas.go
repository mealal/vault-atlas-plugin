package atlas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/database/dbplugin"
	"github.com/hashicorp/vault/sdk/database/helper/credsutil"
	"github.com/hashicorp/vault/sdk/database/helper/dbutil"
	"github.com/mitchellh/mapstructure"
)

type atlasConnectionProducer struct {
	Username    string `json:"username" structs:"username" mapstructure:"username"`
	Password    string `json:"password" structs:"password" mapstructure:"password"`
	GroupID     string `json:"groupID" structs:"groupID" mapstructure:"groupID"`
	APIId       string `json:"apiID" structs:"apiID" mapstructure:"apiID"`
	APIKey      string `json:"apiKey" structs:"apiKey" mapstructure:"apiKey"`
	Initialized bool
	RawConfig   map[string]interface{}
	Type        string
	sync.Mutex
}

// Atlas is an implementation of Database interface
type Atlas struct {
	*atlasConnectionProducer
	credsutil.CredentialsProducer
}

type mongodbRole struct {
	Role string `json:"role" bson:"role"`
	DB   string `json:"db"   bson:"db"`
}

type mongodbRoles []mongodbRole

type atlasStatement struct {
	DB    string       `json:"db"`
	Roles mongodbRoles `json:"roles"`
}

//New function
func New() (interface{}, error) {
	db := new()
	dbType := dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.secretValues)
	return dbType, nil
}

func new() *Atlas {
	connProducer := &atlasConnectionProducer{}
	connProducer.Type = atlasTypeName

	credsProducer := &credsutil.SQLCredentialsProducer{
		DisplayNameLen: 15,
		RoleNameLen:    15,
		UsernameLen:    100,
		Separator:      "-",
	}

	return &Atlas{
		atlasConnectionProducer: connProducer,
		CredentialsProducer:     credsProducer,
	}
}

//Run function
func Run(apiTLSConfig *api.TLSConfig) error {
	dbType, err := New()
	if err != nil {
		return err
	}

	dbplugin.Serve(dbType.(dbplugin.Database), api.VaultPluginTLSProvider(apiTLSConfig))

	return nil
}

//Type of database
func (m *Atlas) Type() (string, error) {
	return atlasTypeName, nil
}

//CreateUser function
func (m *Atlas) CreateUser(ctx context.Context, statements dbplugin.Statements, usernameConfig dbplugin.UsernameConfig, expiration time.Time) (username string, password string, err error) {
	if m == nil {
		return "", "", fmt.Errorf("NIL detected")
	}
	m.Lock()
	defer m.Unlock()

	statements = dbutil.StatementCompatibilityHelper(statements)

	if len(statements.Creation) == 0 {
		return "", "", dbutil.ErrEmptyCreationStatement
	}

	username, err = m.GenerateUsername(usernameConfig)
	if err != nil {
		return "", "", err
	}

	password, err = m.GeneratePassword()
	if err != nil {
		return "", "", err
	}

	var mongoCS atlasStatement
	err = json.Unmarshal([]byte(statements.Creation[0]), &mongoCS)
	if err != nil {
		return "", "", err
	}

	if len(mongoCS.Roles) == 0 {
		return "", "", fmt.Errorf("roles array is required in creation statement")
	}

	// Default to "admin" if no db provided
	if mongoCS.DB == "" {
		mongoCS.DB = "admin"
	}

	var roles []Roles
	for _, role := range mongoCS.Roles {
		var atlasRole Roles
		atlasRole.RoleName = role.Role
		if role.DB == "" {
			atlasRole.DatabaseName = "admin"
		} else {
			atlasRole.DatabaseName = role.DB
		}
		roles = append(roles, atlasRole)
	}

	err = createAtlasUser(m.GroupID, m.APIId, m.APIKey, username, password, mongoCS.DB, roles)
	if err != nil {
		return "", "", err
	}
	return username, password, nil
}

//RenewUser function
func (m *Atlas) RenewUser(ctx context.Context, statements dbplugin.Statements, username string, expiration time.Time) error {
	return nil
}

//RevokeUser function
func (m *Atlas) RevokeUser(ctx context.Context, statements dbplugin.Statements, username string) error {
	m.Lock()
	defer m.Unlock()

	statements = dbutil.StatementCompatibilityHelper(statements)

	// If no revocation statements provided, pass in empty JSON
	var revocationStatement string
	switch len(statements.Revocation) {
	case 0:
		revocationStatement = `{}`
	case 1:
		revocationStatement = statements.Revocation[0]
	default:
		return fmt.Errorf("expected 0 or 1 revocation statements, got %d", len(statements.Revocation))
	}

	// Unmarshal revocation statements into mongodbRoles
	var mongoCS atlasStatement
	err := json.Unmarshal([]byte(revocationStatement), &mongoCS)
	if err != nil {
		return err
	}

	err = deleteAtlasUser(m.GroupID, m.APIId, m.APIKey, username)
	if err != nil {
		return err
	}
	return nil
}

// RotateRootCredentials is not currently supported on MongoDB
func (m *Atlas) RotateRootCredentials(ctx context.Context, statements []string) (map[string]interface{}, error) {
	return nil, errors.New("root credential rotation is not currently implemented in this database secrets engine")
}

func (c *atlasConnectionProducer) secretValues() map[string]interface{} {
	return map[string]interface{}{
		c.Password: "[password]",
	}
}

func (c *atlasConnectionProducer) Initialize(ctx context.Context, conf map[string]interface{}, verifyConnection bool) error {
	_, err := c.Init(ctx, conf, verifyConnection)
	return err
}

func (c *atlasConnectionProducer) Init(ctx context.Context, conf map[string]interface{}, verifyConnection bool) (map[string]interface{}, error) {
	c.Lock()
	defer c.Unlock()
	c.RawConfig = conf

	err := mapstructure.WeakDecode(conf, c)
	if err != nil {
		return nil, err
	}

	if len(c.APIId) == 0 {
		return nil, fmt.Errorf("apiID cannot be empty")
	}

	if len(c.APIKey) == 0 {
		return nil, fmt.Errorf("apiKey cannot be empty")
	}

	if len(c.GroupID) == 0 {
		return nil, fmt.Errorf("groupID cannot be empty")
	}

	c.Initialized = true
	return conf, nil
}

//Close function
func (m *Atlas) Close() error {
	return nil
}
