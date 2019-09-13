//© Copyright 2018-2019 Hewlett Packard Enterprise Development LP.

// Package redfish defines the generic redfish interfaces for controlling server hardware.
package redfish

// Redfish protocol version V1

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"

	"github.hpe.com/PIaaS/log"
	//"github.com/quattronetworks/quake/controller/pkg/redfish/log"
)

// TODO: Do we need a common base class for resources?
// @odata.id == Resource URI
// @odata.etag == Resource ETag, also found in the header field ETag
// @odata.type == #Namespace.TypeName

// Redfish field with a URL string value
type idT struct {
	ID string `json:"@odata.id"`
}

type collectionT struct {
	ETag    string `json:"-"` // fill in from the response ETag header
	Name    string `json:"Name"`
	Members []idT  `json:"Members"`
	Count   int    `json:"Members@odata.count"`
}

type sessionsT struct {
	collectionT
	Oem map[string]struct {
		Links struct {
			idT
		}
	}
}

type oemManagerT struct {
	HostName               string
	ManagerFirmwareVersion string
	ManagerType            string
}

type oemT struct {
	Manager []oemManagerT
}

// ServiceRoot defines the iLO supported attributes for the redfish resource.
// From the redfish spec: UUID "should be an exact match of the UUID
// value returned in a 200-OK from an SSDP M-SEARCH request during discovery.
// Versioning string
//     Major: Incompatible or breaking change, not backwards compoaiblt
//     Minor: Minor update, new attributes/functionality added but nothing removed.
//            Compatible with previous minor versions
//     Errata: Bug fix in minor version
// Schema versioning - odata.type should be considered opaque in iLO 5
// iLO 	    @odata.type Format
// ------   -------------------------------------------------------
// iLO 4 	"@odata.type": "ComputerSystem.1.0.0.ComputerSystem"
// iLO 5 	"@odata.type": "ComputerSystem.v1_1_0.ComputerSystem"
type serviceRootT struct {
	etag           string
	redfishVersion string // Major.Minor.Errata
	uuid           string
	Oem            oemManagerT
	systems        string
	chassis        string
	managers       string
	sessionService string
	sessions       string
}

// ServiceRootRawT defines the Redfish service root object supported by this package
type ServiceRootRawT struct {
	RedfishVersion string
	UUID           string
	Oem            map[string]oemT
	Systems        idT
	Chassis        idT
	Managers       idT
	SessionService idT
	Links          struct{ Sessions idT }
}

// SystemT represents the redfish Systems resource, add version specific details as needed
type SystemT struct {
	ETag         string `json:"-"`          // fill in from the response ETag header
	PowerState   string `json:"PowerState"` // one of {On, Off, Unknown, Reset}
	UUID         string `json:"UUID"`
	SerialNumber string `json:"SerialNumber"`
	UIDState     string `json:"IndicatorLED"`
	Bios         idT    // iLO5 (for iLO4 use Oem.Hp.Links["BIOS"])
	Oem          struct {
		Hp struct {
			Links map[string]idT
		}
	}
	Actions struct {
		Reset struct {
			AllowableValues []string `json:"ResetType@Redfish.AllowableValues"`
			Target          string   `json:"target"`
		} `json:"#ComputerSystem.Reset"`
	} `json:"Actions"`
}

// BiosT represents the redfish Bios resource
type BiosT struct {
	ETag       string `json:"-"`
	Attributes struct {
		BootMode          string
		VirtualSerialPort string
	}
	Settings struct {
		SettingsObject idT
	} `json:"@Redfish.Settings"`
	Links struct {
		Settings struct {
			Href string `json:"href"`
		}
	} `json:"links"`
}

type msgObjectT struct {
	Type              string   `json:"@odata.type,omitempty"`
	MessageID         string   `json:"MessageId,omitempty"` // RegistryName.MajorVersion.MinorVersion.MessageKey
	Message           string   `json:"Message,omitempty"`
	RelatedProperties []string `json:"RelatedProperties,omitempty"`
	MessageArgs       []string `json:"MessageArgs,omitempty"`
	Severity          string   `json:"Severity,omitempty"`
	Resolution        string   `json:"Resolution,omitempty"`
}

// Where the HTTP status code indicates a failure, the response body contains an extended error resource
//   - (1.0) Services shall return the extended error resource when a status code of 400 or 500 is returned.
//   - (1.0) Services should return the extended error resource when a status code 400 or greater is returned.
//   - (1.6) Services should return the extended error resource when a status code 400 or greater is returned.
//   - (1.6) Services may return the extended error resource when other status codes are returned for those
//           codes and operations that allow a response body.
//   - (1.0/1.6) Services should return the extended error resource when a status code 400 or greater is returned.
// Extended error messages MUST NOT provide privileged info when authentication failures occur
type extendedError struct {
	Error struct {
		Code         string       `json:"code"`
		Message      string       `json:"message"`
		ExtendedInfo []msgObjectT `json:"@Message.ExtendedInfo"`
	}
}

// Internal REST operations supported in a session object
type hdrMapT map[string]string
type restOpsI interface {
	// Core rest operations
	login(rpath string)
	logout() error
	postResource(rpath string, body string, hdrs []string) (hdrMapT, []byte, error)
	patchResource(rpath string, body string, hdrs []string) (hdrMapT, []byte, error)
	getResource(rpath string, hdrs []string) (hdrMapT, []byte, error)
	getCollection(rpath string) (*collectionT, error)
}

type utilityOpsI interface {
	// temp or debug utilities
	getMembers(rpath string) ([]string, error)
	DoPatch(rpath, body string)
	DoPost(rpath, body string)
	DoGet(rpath string)
}

var httpClient *http.Client

func init() {
	setClient(makeClient())
}

func getClient() *http.Client {
	return httpClient
}

// setClient is used for internal redfish tets
func setClient(c *http.Client) {
	httpClient = c
}

func makeClient() *http.Client {
	/* The Client/Transport object is created once and
	 * XXX: will eventually need to use certificates */
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout: defaultTLSTimeOut,
	}
	return &http.Client{Transport: tr, Timeout: defaultClientTimeout}
}

// URI = scheme:[//authority]path[?query][#fragment]
// authority = [userinfo@]host[:port] ... for us its just host[:port]
func (s *Session) buildURL(rpath string) string {
	if rpath[0] != '/' {
		return fmt.Sprintf("%s://%s/%s", scheme, s.Address, rpath)
	}
	return fmt.Sprintf("%s://%s%s", scheme, s.Address, rpath)
}

/* wrapper for standard http NewRequest function, adds required properties for Redfish. */
func makeRequest(method string, url string, body string, token string) (*http.Request, error) {
	// create request object and convert body into a byte reader
	// will set the content-length header
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	// Redfish requires all servers to support application/json
	// Header OData-Vdersion 4.0 is what places iLO into redfish mode
	req.Header.Add("OData-Version", "4.0")
	req.Header.Add("Accept", "application/json;charset=utf-8")
	if len(body) > 0 {
		req.Header.Add("Content-Type", "application/json;charset=utf-8")
	}
	// The GO HTTP libray will add Content-Length

	// add auth token if provided
	if token != "" {
		req.Header.Add("X-Auth-Token", token)
	}
	return req, nil
}

func (s *Session) newError(err error, code StatusCodeT, format string, a ...interface{}) *RFishError {
	if s == nil {
		return newError(err, "", code, format, a...)
	}
	return newError(err, s.Address, code, format, a...)
}

func (s *Session) login(rpath string) error {
	log.Trace.Printf("login(%s) at %s", s.User, rpath)

	body := fmt.Sprintf(`{"UserName": "%s", "Password": "%s"}`, s.User, s.Password)
	h := []string{"Location", "X-Auth-Token"}

	hdrs, _, err := s.postResource(rpath, body, h)
	if err != nil {
		return updateError(err, "login failed")
	}
	s.url = hdrs["Location"]
	s.token = hdrs["X-Auth-Token"]

	log.Trace.Printf("rfish login %s succeeded, Session URL %s", s.Address, s.url)

	return nil
}

func (s *Session) logout() error {
	log.Trace.Printf("logout(%s, %s)", s.Address, s.url)
	if s.url == "" {
		s.token = "" // just in case
		return nil
	}

	req, err := makeRequest(http.MethodDelete, s.url, "", s.token)
	if err != nil {
		return s.newError(err, StatusCodeInternalError, "logout - makerequest error")
	}

	resp, err := s.doRequest(req)
	if err != nil {
		return err
	}

	data, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return s.newError(err, StatusCodeFmtError, "logout - read response error")
	}

	// check status code (resp.StatusCode) to ensure session was closed
	if err := s.ckStatusCode("DELETE", s.url, resp, data); err != nil {
		return err
	}

	s.token = ""
	s.url = ""

	return nil
}

func (s *Session) doRequest(req *http.Request) (*http.Response, error) {
	client := getClient()
	// Returned errors are type *url.Error
	resp, err := client.Do(req)
	if err != nil {
		// Errors:
		//   net.url.Error{Op: "xx", URL: "xx", Err: <error>}
		//     <error> ==
		//       net.OpError{Op: "xx", Net: "tcp", Source: <net.Addr>, Addr: <net.Addr>, Err: <error>}
		//         <error> == os.SyscallError{Syscall: "connect", Err: <error>}
		//           <error> == ETIMEDOUT (110)
		//   httpError{err: xx, timeout: xx}
		code := StatusCodeConnectError
		if uerr, ok := err.(*url.Error); ok {
			if noerr, ok := uerr.Err.(*net.OpError); ok {
				if scerr, ok := noerr.Err.(*os.SyscallError); ok {
					switch scerr.Err {
					case syscall.ECONNREFUSED:
						code = StatusCodeConnRefused
					case syscall.ETIMEDOUT:
						code = StatusCodeConnTimeOut
					case syscall.ENETUNREACH: // or EHOSTUNREACH
						code = StatusCodeNoRoute
					default:
					}
				}
			}
		}
		return nil, s.newError(err, code, "doRequest - Error sending request to BMC")
	}
	return resp, nil
}

func (s *Session) ckStatusCode(op string, url string, resp *http.Response, data []byte) error {
	if resp.StatusCode < http.StatusMultipleChoices {
		return nil
	}

	msgID := "<missing extended error info>"
	if len(data) > 0 {
		var rederr extendedError
		if err := json.Unmarshal(data, &rederr); err == nil {
			// Assume just one extendedInfo message
			if len(rederr.Error.ExtendedInfo) > 0 {
				msgID = rederr.Error.ExtendedInfo[0].MessageID
			}
		}
	}

	iloErr := newIloError(op, url, resp.StatusCode, msgID)

	var code StatusCodeT
	switch resp.StatusCode {
	case http.StatusNotFound:
		code = StatusCodeNotFound
	case http.StatusUnauthorized:
		// Either the session has expired or user has insufficient permission.
		// MessageID will end in "NoValidSession" if the session has expired
		if iloErr.MsgKey() == "NoValidSession" {
			code = StatusCodeNoSession
			s.url = ""
			s.token = ""
			s.reset(s.User, s.Password)
		} else {
			code = StatusCodeAuthError
		}
	case http.StatusBadRequest:
		// HTTP response code 400 is the standard iLO error code.
		if op == "POST" && iloErr.MsgKey() == "UnauthorizedLoginAttempt" {
			// iLO returns BadRequest error if authentication fails (bad password or userName)
			// This is the only place where the static code should be set to StatusCodeBadCreds.
			code = StatusCodeBadCreds
		} else {
			code = StatusCodeBadRequest
		}
	default:
		code = StatusCodeHTTPError
	}

	return s.newError(iloErr, code, "")
}

// From redfish spec:
// V1.0/1.6
// - Services shall support the DELETE method for resources that can be deleted.
// - If the resource can never be deleted, status code 405 shall be returned.
// - Services should return status code 405 if the client specifies a DELETE request against a collection.
// - Services may return HTTP status code 404 or a success code if the resource has already been deleted.
// - Services may return a representation of the just deleted resource in the response body.
// V1.6 Only
// - Services may allow the "@Redfish.OperationApplyTime" property to be included in the body of the request.
func (s *Session) deleteResource(rpath string, hdrs []string) (hdrMapT, error) {
	return nil, nil
}

// Post: The PUT method is used to completely replace a resource. Properties omitted from the request body
// are reset to their default value.
// V1.0/V1.6
// - If a service does not implement this method, a status code 405 shall be returned.
// - Services should return status code 405 if the client specifies a PUT request against a collection.
// - The PUT operation should be idempotent in the absence of outside changes to the resource, with the possible
//   exception that ETAG values may change as the result of this operation.
// V1.6
// - Services may reject requests which do not include properties required by the resource definition (schema).
func (s *Session) postResource(rpath string, body string, hdrs []string) (hdrMapT, []byte, error) {
	// construct REST HTTP message, i.e. create request message
	url := s.buildURL(rpath)
	log.Trace.Printf("postResource(%s): %s", url, body)

	req, err := makeRequest(http.MethodPost, url, body, s.token)
	if err != nil {
		return nil, nil, s.newError(err, StatusCodeInternalError, "postResource - makerequest error")
	}

	resp, err := s.doRequest(req)
	if err != nil {
		return nil, nil, err
	}

	data, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return nil, nil, s.newError(err, StatusCodeFmtError, "postResource - read response error")
	}

	if err := s.ckStatusCode("POST", url, resp, data); err != nil {
		return nil, nil, err
	}

	// Location : URL for this s (i.e. resource created from the POST)
	// X-Auth-Token : contains the assigned auth token for this s
	// ETag: Assign resource ETAG
	hdrMap := hdrMapT{}
	for _, hdr := range hdrs {
		hdrMap[hdr] = resp.Header.Get(hdr)
	}
	log.Trace.Printf("postResource %s succeeded, Session URL %s", s.Address, s.url)

	return hdrMap, data, nil
}

// Patch
// V1.0/V1.6
// - Services shall support the PATCH method to update a resource.
// - On success, the response may contain a representation of the resource after the update was done
// - If the resource or all properties can never be updated, HTTP status code 405 shall be returned.
// - If the client specifies a PATCH request against a Resource Collection, HTTP status code 405 should be returned.
// - The PATCH operation should be idempotent in the absence of outside changes to the resource, though the original
//   ETag value may no longer match.
// - In the case of a request including modification to several properties, if one or more properties in the request
//   can never be updated, such as when a property is read only, unknown, or unsupported, an HTTP status code of 200
//   shall be returned along with a representation of the resource containing a Message annotation specifying the
//   non-updatable properties. In this success case, other properties may be updated in the resource.
// - Services may accept a PATCH with an empty JSON object. An empty JSON object in this context means no changes to
//   the resource are being requested.
// V1.6 Only
// - In the case of a request modifying a single property, if the property in the request can never be updated,
//   such as when the property is read only, unknown, or unsupported, an HTTP status code of 400 shall be returned
//   along with a representation of the resource containing a Message annotation specifying the non-updatable property.
func (s *Session) patchResource(rpath string, body string, hdrs []string) (hdrMapT, []byte, error) {
	// construct REST HTTP message, i.e. create request message
	url := s.buildURL(rpath)
	log.Trace.Printf("patchResource(%s): %s", url, body)

	req, err := makeRequest(http.MethodPatch, url, body, s.token)
	if err != nil {
		return nil, nil, s.newError(err, StatusCodeInternalError, "patchResource - makerequest error")
	}

	resp, err := s.doRequest(req)
	if err != nil {
		return nil, nil, err
	}

	data, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return nil, nil, s.newError(err, StatusCodeFmtError, "patchResource - read response error")
	}

	// check for success or failuer of request (HTTP status):
	//   Post/Put: 201 (http.StatusCreated) but accept a 204 (no body).
	// (iLO only lists 308 as a possible error code) 4XX and
	// above is an error
	if err := s.ckStatusCode("PATCH", url, resp, data); err != nil {
		return nil, nil, err
	}

	// Location : URL for this s (i.e. resource created from the POST)
	// X-Auth-Token : contains the assigned auth token for this s
	// ETag: Assign resource ETAG
	hdrMap := hdrMapT{}
	for _, hdr := range hdrs {
		hdrMap[hdr] = resp.Header.Get(hdr)
	}
	log.Trace.Printf("patchResource %s succeeded, Session URL %s", s.Address, s.url)

	return hdrMap, data, nil
}

// getResource: preconditions - session Address and Token are valid
func (s *Session) getResource(rpath string, hdrs []string) (hdrMapT, []byte, error) {
	url := s.buildURL(rpath)
	req, rferr := makeRequest(http.MethodGet, url, "", s.token)
	if rferr != nil {
		return nil, nil, s.newError(rferr, StatusCodeInternalError, "getResource - makeRequest error")
	}
	resp, err := s.doRequest(req)
	if err != nil {
		return nil, nil, err
	}

	data, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return nil, nil, s.newError(err, StatusCodeFmtError, "getResource - read response error")
	}

	if err := s.ckStatusCode("GET", url, resp, data); err != nil {
		return nil, nil, err
	}
	//fmt.Printf("Response:\n\t%v\n", resp)
	// Location : URL for this session (i.e. resource created from the POST)
	// X-Auth-Token : contains the assigned auth token for this session
	// ETag: Assign resource ETAG
	hdrMap := hdrMapT{}
	for _, hdr := range hdrs {
		hdrMap[hdr] = resp.Header.Get(hdr)
	}

	return hdrMap, data, nil
}

// GetMembers: preconditions - session Address and Token are valid
func (s *Session) getCollection(rpath string) (*collectionT, error) {
	h := []string{"ETag"}
	hdrs, data, rferr := s.getResource(rpath, h)
	if rferr != nil {
		return nil, rferr
	}

	var result collectionT
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, s.newError(err, StatusCodeFmtError, "getCollection - format error")
	}
	result.ETag = hdrs["ETag"]

	members := make([]string, len(result.Members))
	for i, s := range result.Members {
		members[i] = s.ID
	}

	log.Trace.Printf("getCollection(%s): ETag %s, Body %q", result.ETag, s.buildURL(rpath), members)
	return &result, nil
}

// GetMembers: preconditions - session Address and Token are valid. Returns list of member URLs,
// on error returns RFishError object (superset of error interface).
func (s *Session) getMembers(rpath string) ([]string, error) {
	result, rferr := s.getCollection(rpath)
	if rferr != nil {
		return nil, rferr
	}

	members := make([]string, len(result.Members))
	for i, s := range result.Members {
		members[i] = s.ID
	}

	log.Trace.Printf("getMembers(%s): Body %q", s.buildURL(rpath), members)
	return members, nil
}

// Some utilities for testing ... temporary

// DoPatch is temp
func (s *Session) DoPatch(rpath, body string) error {
	if _, _, err := s.patchResource(rpath, body, nil); err != nil {
		return updateError(err, "DoPatch(%s)", s.Address)
	}
	return nil
}

// DoPost - temporary utility
func (s *Session) DoPost(rpath, body string) error {
	if _, _, err := s.postResource(rpath, body, nil); err != nil {
		return updateError(err, "DoPatch(%s)", s.Address)
	}
	return nil
}

// DoGet - temporary utility
func (s *Session) DoGet(rpath string) ([]byte, error) {
	_, data, err := s.getResource(rpath, nil)
	if err != nil {
		return nil, updateError(err, "DoPatch(%s)", s.Address)
	}
	return data, nil
}

// ListSessions returns a slice of strings (list of session URLs for all active sessions)
func ListSessions() ([]string, error) {
	var all []string
	for _, s := range SessionCache.cache {
		ss, err := s.getMembers(sessionsURL)
		if err != nil {
			return nil, err
		}
		all = append(all, ss...)
	}
	return all, nil
}
