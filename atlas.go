package atlas

// Used source code from https://github.com/desteves/mongodb-atlas-service-broker/

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"io"
	"strings"
	"context"
	"sync"
	"time"
	"errors"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/plugins"
	"github.com/hashicorp/vault/plugins/helper/database/credsutil"
	"github.com/hashicorp/vault/builtin/logical/database/dbplugin"
	"github.com/hashicorp/vault/plugins/helper/database/connutil"
	"github.com/hashicorp/vault/plugins/helper/database/dbutil"
	mgo "gopkg.in/mgo.v2"
)

// const
const (

	ErrorCode404 = "CLUSTER_NOT_FOUND"

	UserDatabaseStore = "admin"
	UserRoleDatabase  = "admin"
	UserRoleName      = "readWriteAnyDatabase"
	atlasHost         = "https://cloud.mongodb.com"
	atlasURI          = "/api/atlas/v1.0"
	atlasTypeName     = "atlas"
)

type atlasConnectionProducer struct {
	Username      string `json:"username" structs:"username" mapstructure:"username"`
	Password      string `json:"password" structs:"password" mapstructure:"password"`
	Initialized   bool
	RawConfig     map[string]interface{}
	Type          string
	session       *mgo.Session
	safe          *mgo.Safe
	sync.Mutex
}

// Atlas is an implementation of Database interface
type Atlas struct {
	*atlasConnectionProducer
	credsutil.CredentialsProducer
}

// Roles --
type Roles struct {
	CollectionName string `json:"collectionName,omitempty"`
	DatabaseName   string `json:"databaseName"`
	RoleName       string `json:"roleName"`
}

// BindRequest struct - Bind Settings
type bindRequest struct {
	DatabaseName    string  `json:"databaseName"`
	Password        string  `json:"password"`
	Roles           []Roles `json:"roles"`
	Username        string  `json:"username"`
	DeleteAfterDate string  `json:"deleteAfterDate,omitempty"`
	GroupID         string  `json:"groupId"`
}

type mongodbRole struct {
	Role string `json:"role" bson:"role"`
	DB   string `json:"db"   bson:"db"`
}

type mongodbRoles []mongodbRole

type atlasStatement struct {
	DB      string       `json:"db"`
	Roles   mongodbRoles `json:"roles"`
	groupID string       `json:"groupID"`
	apiID   string       `json:"apiID"`
	apiKey  string       `json:"apiKey"`
}

type Response struct {
	DatabaseName    string  `json:"databaseName,omitempty"`
	DeleteAfterDate string  `json:"deleteAfterDate,omitempty"`
	GroupID         string  `json:"groupId,omitempty"`
	Roles           []Roles `json:"roles,omitempty"`
	Username        string  `json:"username,omitempty"`
	Error			int     `json:"error,omitempty"`
	ErrorCode		string  `json:"errorCode,omitempty"`
	ErrorText		string  `json:"detail,omitempty"`
	ErrorReason		string  `json:"reason,omitempty"`
}

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
		CredentialsProducer:       credsProducer,
	}
}

func Run(apiTLSConfig *api.TLSConfig) error {
	dbType, err := New()
	if err != nil {
		return err
	}

	plugins.Serve(dbType.(*Atlas), apiTLSConfig)

	return nil
}

func (m *Atlas) Type() (string, error) {
	return atlasTypeName, nil
}

func (m *Atlas) getConnection(ctx context.Context) (*mgo.Session, error) {
	session, err := m.Connection(ctx)
	if err != nil {
		return nil, err
	}

	return session.(*mgo.Session), nil
}

func (m *Atlas) CreateUser(ctx context.Context, statements dbplugin.Statements, usernameConfig dbplugin.UsernameConfig, expiration time.Time) (username string, password string, err error) {
	m.Lock()
	defer m.Unlock()

	statements = dbutil.StatementCompatibilityHelper(statements)

	if len(statements.Creation) == 0 {
		return "", "", dbutil.ErrEmptyCreationStatement
	}

	_ , err = m.getConnection(ctx)
	if err != nil {
		return "", "", err
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

	err = CreateAtlasUser(mongoCS.groupID, mongoCS.apiID, mongoCS.apiKey, username, password, mongoCS.DB, roles)
	if  err != nil {
		return "", "", err
	}
	return username, password, nil
}

func (m *Atlas) RenewUser(ctx context.Context, statements dbplugin.Statements, username string, expiration time.Time) error {
	return nil
}

func (m *Atlas) RevokeUser(ctx context.Context, statements dbplugin.Statements, username string) error {
	m.Lock()
	defer m.Unlock()

	statements = dbutil.StatementCompatibilityHelper(statements)

	var err error
	_, err = m.getConnection(ctx)
	if err != nil {
		return err
	}

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
	err = json.Unmarshal([]byte(revocationStatement), &mongoCS)
	if err != nil {
		return err
	}

	err = DeleteAtlasUser(mongoCS.groupID, mongoCS.apiID, mongoCS.apiKey, username);
	switch {
	case err == nil, err == mgo.ErrNotFound:
	default:
		return err
	}
	return nil
}

// RotateRootCredentials is not currently supported on MongoDB
func (m *Atlas) RotateRootCredentials(ctx context.Context, statements []string) (map[string]interface{}, error) {
	return nil, errors.New("root credential rotation is not currently implemented in this database secrets engine")
}

// Does the digest handshake and assembles the actuall http call to make
func setupRequest(apiID string, apiKey string, argMethod string, argURI string, argPostBody []byte) (*http.Request, error) {
	uri := atlasURI + argURI
	url := atlasHost + uri
	emptyRequest := http.Request{}
	req, err := http.NewRequest(argMethod, url, nil)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error - setupRequest - Failed http response. Resp: %+v, Err: %+v", resp, err)
		return &emptyRequest, err
	}
	defer resp.Body.Close()
	digestParts := digestParts(resp)
	digestParts["uri"] = uri
	digestParts["method"] = argMethod

	username := apiID
	if len(username) == 0 {
		err := fmt.Errorf("apiID variable not set!")
		log.Printf("Error - setupRequest. Err: %+v", err)
		return &emptyRequest, err
	}

	password := apiKey
	if len(password) == 0 {
		err := fmt.Errorf("apiKey variable not set!")
		log.Printf("Error - setupRequest. Err: %+v", err)
		return &emptyRequest, err
	}

	digestParts["username"] = username
	digestParts["password"] = password
	if argPostBody == nil {
		req, err = http.NewRequest(argMethod, url, nil)
	} else {
		req, err = http.NewRequest(argMethod, url, bytes.NewBuffer(argPostBody))
	}
	req.Header.Set("Authorization", getDigestAuthrization(digestParts))
	req.Header.Set("Content-Type", "application/json")
	return req, nil

}

func doPOST(apiID string, apiKey string, argURI string, argPostBody []byte) ([]byte, error) {
	req, err := setupRequest(apiID, apiKey, http.MethodPost, argURI, argPostBody)
	if err != nil {
		log.Printf("Error - DoPOST - Failed setupRequest call. Req: %+v, Err: %+v", req, err)
		return []byte{}, err
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error - DoPOST - Failed http response. Resp: %+v, Err: %+v", resp, err)
		return []byte{}, err
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error - DoPOST - Failed parsing body response. Data: %+v, Err: %+v", data, err)
		return []byte{}, err
	}
	return data, nil
}

func doDELETE(apiID string, apiKey string, argURI string) ([]byte, error) {
	req, err := setupRequest(apiID, apiKey, http.MethodDelete, argURI, nil)
	if err != nil {
		log.Printf("Error - DoDELETE - Failed setupRequest call. Req: %+v, Err: %+v", req, err)
		return []byte{}, err
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error - DoDELETE - Failed http response. Resp: %+v, Err: %+v", resp, err)
		return []byte{}, err
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error - DoDELETE - Failed parsing body response. Data: %+v, Err: %+v", data, err)
		return []byte{}, err
	}
	return data, nil
}

func CreateAtlasUser(groupID string, apiID string, apiKey string, username string, password string, database string, roles []Roles) error {
	// https://docs.atlas.mongodb.com/reference/api/database-users-create-a-user/
	if len(groupID) == 0 {
		err := fmt.Errorf("ATLAS_GROUP_ID env variable not set!")
		log.Printf("Error - NewUser. Err: %+v", err)
		return err
	}

	uri := "/groups/" + groupID + "/databaseUsers"
	request := bindRequest{}
	request.DatabaseName = database
	request.GroupID = groupID
	request.Roles = roles
	request.Username = username
	request.Password = password
	params, err := json.Marshal(request)
	if err != nil {
		log.Printf("Error - Bind - Failed Marshal. JSON: %+v, Err: %+v", params, err)
		return err
	}

	body, err := doPOST(apiID, apiKey, uri, params)
	if err != nil {
		log.Printf("Error - NewUser - Failed doPOST call.  Body: %+v, Err: %+v", body, err)
		return err
	}
	returnObject := Response{}
	err = json.Unmarshal(body, &returnObject)
	if err != nil {
		log.Printf("Error - NewUser - Failed Unmarshal. Response: %+v, Err: %+v", returnObject, err)
		return err
	}
	if returnObject.Error != 0 {
		err = errors.New(returnObject.ErrorText)
	}
	return err
}

func DeleteAtlasUser(groupID string, apiID string, apiKey string, username string) error {
	//https://docs.atlas.mongodb.com/reference/api/database-users-delete-a-user/
	//DELETE /api/atlas/v1.0/groups/{GROUP-ID}/databaseUsers/admin/{USERNAME}
	if len(groupID) == 0 {
		err := fmt.Errorf("ATLAS_GROUP_ID env variable not set!")
		log.Printf("Error - DeleteUser. Err: %+v", err)
		return err
	}
	uri := "/groups/" + groupID + "/databaseUsers/admin/" + username
	body, err := doDELETE(apiID, apiKey, uri)
	if err != nil {
		log.Printf("Error - DeleteUser - Failed DoDELETE call.  Err: %+v", err)
	}
	if len(body) != 0 {
		returnObject := Response{}
		err = json.Unmarshal(body, &returnObject)
		if err != nil {
			log.Printf("Error - NewUser - Failed Unmarshal. Response: %+v, Err: %+v", returnObject, err)
			return err
		}
		if returnObject.Error != 0 {
			err = errors.New(returnObject.ErrorText)
		}
	}
	return err
}

func digestParts(resp *http.Response) map[string]string {
	result := map[string]string{}
	if len(resp.Header["Www-Authenticate"]) > 0 {
		wantedHeaders := []string{"nonce", "realm", "qop"}
		responseHeaders := strings.Split(resp.Header["Www-Authenticate"][0], ",")
		for _, r := range responseHeaders {
			for _, w := range wantedHeaders {
				if strings.Contains(r, w) {
					result[w] = strings.Split(r, `"`)[1]
				}
			}
		}
	}
	return result
}

func getMD5(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

func getCnonce() string {
	b := make([]byte, 8)
	io.ReadFull(rand.Reader, b)
	return fmt.Sprintf("%x", b)[:16]
}

func getDigestAuthrization(digestParts map[string]string) string {
	d := digestParts
	ha1 := getMD5(d["username"] + ":" + d["realm"] + ":" + d["password"])
	ha2 := getMD5(d["method"] + ":" + d["uri"])
	nonceCount := 00000001
	cnonce := getCnonce()
	response := getMD5(fmt.Sprintf("%s:%s:%v:%s:%s:%s", ha1, d["nonce"], nonceCount, cnonce, d["qop"], ha2))
	authorization := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", cnonce="%s", nc="%v", qop="%s", response="%s"`,
		d["username"], d["realm"], d["nonce"], d["uri"], cnonce, nonceCount, d["qop"], response)
	return authorization
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
	c.Initialized = true
	return conf, nil
}


func (c *atlasConnectionProducer) Connection(_ context.Context) (interface{}, error) {
	if !c.Initialized {
		return nil, connutil.ErrNotInitialized
	}

	if c.session != nil {
		if err := c.session.Ping(); err == nil {
			return c.session, nil
		}
		c.session.Close()
	}

	info := mgo.DialInfo{
		Addrs:    strings.Split(atlasHost, ","),
		Database: atlasURI,
		Timeout:  10 * time.Second,
	}
	var err error
	c.session, err = mgo.DialWithInfo(&info)
	if err != nil {
		return nil, err
	}

	if c.safe != nil {
		c.session.SetSafe(c.safe)
	}

	c.session.SetSyncTimeout(1 * time.Minute)
	c.session.SetSocketTimeout(1 * time.Minute)

	return c.session, nil
}

func (c *atlasConnectionProducer) Close() error {
	c.Lock()
	defer c.Unlock()

	if c.session != nil {
		c.session.Close()
	}

	c.session = nil

	return nil
}