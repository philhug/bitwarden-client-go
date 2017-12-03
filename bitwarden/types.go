package bitwarden

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
)

const (
	CipherType_Folder     = iota
	CipherType_Login      = iota
	CipherType_SecureNote = iota
	CipherType_Card       = iota
	CipherType_Identity   = iota
)

type Account struct {
	Id                 string `json:"id"`
	Name               string `json:"name"`
	Email              string `json:"email"`
	MasterPasswordHash string `json:"masterPasswordHash"`
	MasterPasswordHint string `json:"masterPasswordHint"`
	Key                string `json:"key"`
	RefreshToken       string `json:"-"`
}

// The data we store
type Cipher struct {
	Type                int
	FolderId            *string // Must be pointer to output null in json. Android app will crash if not null
	OrganizationId      *string
	Favorite            bool
	Edit                bool
	Id                  string
	Login               *loginData      `json:"Login,omitempty"`
	Card                *cardData       `json:"Card,omitempty"`
	SecureNote          *secureNoteData `json:"SecureNote,omitempty"`
	Identity            *identityData   `json:"Identity,omitempty"`
	Data                interface{}
	Attachments         []string
	OrganizationUseTotp bool
	RevisionDate        Time
}

type Profile struct {
	Id                 string
	Name               string
	Email              string
	EmailVerified      bool
	Premium            bool
	MasterPasswordHint string
	Culture            string
	TwoFactorEnabled   bool
	Key                string
	PrivateKey         string
	SecurityStamp      string
	Organizations      []string
	Object             string
}

type SyncData struct {
	Profile Profile
	Folders []Folder
	Ciphers []CipherDetailsResponse `json:"Ciphers,omitempty"`
	Domains Domains
	Object  string
}

type Domains struct {
	EquivalentDomains       []string
	GlobalEquivalentDomains []GlobalEquivalentDomains
	Object                  string
}

type GlobalEquivalentDomains struct {
	Type     int
	Domains  []string
	Excluded bool
}

type Time struct {
	time.Time
}

func (t *Time) UnmarshalJSON(b []byte) error {
	st := strings.Trim(string(b), "Z\"")

	s := fmt.Sprintf("\"%sZ\"", st)
	return t.Time.UnmarshalJSON([]byte(s))
}

func (t Time) MarshalJSON() ([]byte, error) {
	b, err := t.Time.MarshalJSON()
	s := string(b[:len(b)-2]) + "\""
	return []byte(s), err
}

type Folder struct {
	Id           string
	Name         string
	Object       string
	RevisionDate Time
}

type List struct {
	Object string
	Data   interface{}
}

// Experimental
type Response struct {
	// TODO
	Object string
}

type CipherMiniResponse struct {
	Response

	Id             string
	OrganizationId *string
	Type           int
	Data           interface{}
	Attachments    []string
	RevisionDate   Time
}

type CipherResponse struct {
	CipherMiniResponse

	FolderId            *string // Must be pointer to output null in json. Android app will crash if not null
	Favorite            bool
	Edit                bool
	OrganizationUseTotp bool
}

type CipherDetailsResponse struct {
	CipherResponse
	CollectionIds []string
}

type CipherMiniDetailsResponse struct {
	CipherMiniResponse
	CollectionIds []string
}

type CipherData struct {
	Name   string
	Notes  *string
	Fields []string
}

type loginData struct {
	CipherData
	URI      string  `json:"uri"`
	Username string  `json:"username"`
	Password string  `json:"password"`
	ToTp     *string `json:"totp"`
}

type cardData struct {
	CipherData
	CardholderName string
	Brand          string
	Number         string
	ExpMonth       string
	ExpYear        string
	Code           string
}

type identityData struct {
	CipherData
	Title          string
	FirstName      string
	MiddleName     string
	LastName       string
	Address1       string
	Address2       string
	Address3       string
	City           string
	State          string
	PostalCode     string
	Country        string
	Company        string
	Email          string
	Phone          string
	SSN            string
	Username       string
	PassportNumber string
	LicenseNumber  string
}

type secureNoteData struct {
	CipherData
}

func (cmr *CipherMiniResponse) ToCipher() Cipher {
	cipher := Cipher{Id: cmr.Id, Type: cmr.Type, RevisionDate: cmr.RevisionDate, OrganizationId: cmr.OrganizationId, Attachments: cmr.Attachments}
	v, _ := json.Marshal(cmr.Data)
	switch cipher.Type {
	case CipherType_Login:
		json.Unmarshal(v, &cipher.Login)
	case CipherType_Card:
		json.Unmarshal(v, &cipher.Card)
	case CipherType_Identity:
		json.Unmarshal(v, &cipher.Identity)
	case CipherType_SecureNote:
		json.Unmarshal(v, &cipher.SecureNote)
	default:
		log.Fatal("invalid cipher type")
	}

	return cipher
}

func NewCipherMiniResponse(cipher Cipher) CipherMiniResponse {
	cmr := CipherMiniResponse{Id: cipher.Id, Type: cipher.Type, RevisionDate: cipher.RevisionDate, OrganizationId: cipher.OrganizationId, Attachments: cipher.Attachments}
	switch cipher.Type {
	case CipherType_Login:
		cmr.Data = cipher.Login
	case CipherType_Card:
		cmr.Data = cipher.Card
	case CipherType_Identity:
		cmr.Data = cipher.Identity
	case CipherType_SecureNote:
		cmr.Data = cipher.SecureNote
	default:
		log.Fatal("invalid cipher type")
	}

	cmr.Object = "cipherMini"
	return cmr
}

func (cmr *CipherResponse) ToCipher() Cipher {
	cipher := cmr.CipherMiniResponse.ToCipher()

	cipher.FolderId = cmr.FolderId
	cipher.Favorite = cmr.Favorite
	cipher.Edit = cmr.Edit
	cipher.OrganizationUseTotp = cmr.OrganizationUseTotp
	return cipher
}

func NewCipherResponse(cipher Cipher) CipherResponse {
	cr := CipherResponse{CipherMiniResponse: NewCipherMiniResponse(cipher), FolderId: cipher.FolderId, Favorite: cipher.Favorite, Edit: cipher.Edit, OrganizationUseTotp: cipher.OrganizationUseTotp}

	cr.Object = "cipher"
	return cr
}

func (cdr *CipherDetailsResponse) ToCipher() Cipher {
	cipher := cdr.CipherResponse.ToCipher()

	//cipher.CollectionIds = cdr.CollectionIds // TODO
	return cipher
}

func NewCipherDetailsResponse(cipher Cipher) CipherDetailsResponse {
	cr := NewCipherResponse(cipher)
	cdr := CipherDetailsResponse{CipherResponse: cr}

	cdr.CollectionIds = nil // TODO collections

	cdr.Object = "cipherDetails"
	return cdr
}

func (cmdr *CipherMiniDetailsResponse) ToCipher() Cipher {
	cipher := cmdr.CipherMiniResponse.ToCipher()

	//cipher.CollectionIds = cdr.CollectionIds // TODO
	return cipher
}

func NewCipherMiniDetailsResponse(cipher Cipher) CipherMiniDetailsResponse {
	cmr := NewCipherMiniResponse(cipher)
	cmdr := CipherMiniDetailsResponse{CipherMiniResponse: cmr}

	cmdr.CollectionIds = nil // TODO collections

	cmdr.Object = "cipherMiniDetails"
	return cmdr
}
