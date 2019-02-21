package atlas

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

// Used source code from https://github.com/desteves/mongodb-atlas-service-broker/

// const
const (
	atlasHost     = "https://cloud.mongodb.com"
	atlasURI      = "/api/atlas/v1.0"
	atlasTypeName = "atlas"
)

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

type response struct {
	DatabaseName    string  `json:"databaseName,omitempty"`
	DeleteAfterDate string  `json:"deleteAfterDate,omitempty"`
	GroupID         string  `json:"groupId,omitempty"`
	Roles           []Roles `json:"roles,omitempty"`
	Username        string  `json:"username,omitempty"`
	Error           int     `json:"error,omitempty"`
	ErrorCode       string  `json:"errorCode,omitempty"`
	ErrorText       string  `json:"detail,omitempty"`
	ErrorReason     string  `json:"reason,omitempty"`
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
		err := fmt.Errorf("apiID variable not set")
		log.Printf("Error - setupRequest. Err: %+v", err)
		return &emptyRequest, err
	}

	password := apiKey
	if len(password) == 0 {
		err := fmt.Errorf("apiKey variable not set")
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

func createAtlasUser(groupID string, apiID string, apiKey string, username string, password string, database string, roles []Roles) error {
	// https://docs.atlas.mongodb.com/reference/api/database-users-create-a-user/
	if len(groupID) == 0 {
		err := fmt.Errorf("groupID variable not set")
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
	returnObject := response{}
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

func deleteAtlasUser(groupID string, apiID string, apiKey string, username string) error {
	//https://docs.atlas.mongodb.com/reference/api/database-users-delete-a-user/
	//DELETE /api/atlas/v1.0/groups/{GROUP-ID}/databaseUsers/admin/{USERNAME}
	if len(groupID) == 0 {
		err := fmt.Errorf("groupID variable not set")
		log.Printf("Error - DeleteUser. Err: %+v", err)
		return err
	}
	uri := "/groups/" + groupID + "/databaseUsers/admin/" + username
	body, err := doDELETE(apiID, apiKey, uri)
	if err != nil {
		log.Printf("Error - DeleteUser - Failed DoDELETE call.  Err: %+v", err)
	}
	if len(body) != 0 {
		returnObject := response{}
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
