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

const (
	FieldType_Text    = iota
	FieldType_Hidden  = iota
	FieldType_Boolean = iota
)

const (
	SecureNoteType_Generic = iota
)

type Keys struct {
	EncryptedPrivateKey string `json:"encryptedPrivateKey"`
	PublicKey           string `json:"publicKey"`
}

type Account struct {
	Id                 string  `json:"id"`
	Name               string  `json:"name"`
	Email              string  `json:"email"`
	MasterPasswordHash string  `json:"masterPasswordHash"`
	MasterPasswordHint *string `json:"masterPasswordHint,omitempty"`
	Key                string  `json:"key"`
	Keys               Keys    `json:"keys"`
	RefreshToken       string  `json:"-"`
}

type User struct {
	Id                              string
	Name                            string
	Email                           string
	EmailVerified                   bool
	MasterPassword                  string
	MasterPasswordHint              string
	Culture                         string
	SecurityStamp                   string
	TwoFactorProviders              string
	TwoFactorRecoveryCode           string
	EquivalentDomains               string
	ExcludedGlobalEquivalentDomains string
	AccountRevisionDate             Time
	Key                             string
	PublicKey                       string
	PrivateKey                      string
	//Premium                       bool
	//PremiumExpirationDate         Time
	//Storage                       int
	MaxStorageGb int
	//Gateway                       int
	//GatewayCustomerId             string
	//GatewaySubscriptionId         string
	CreationDate Time
	RevisionDate Time
}

// The data we store
type Cipher struct {
	Type                int
	FolderId            *string // Must be pointer to output null in json. Android app will crash if not null
	OrganizationId      *string
	Favorite            bool
	Edit                bool
	Id                  string          `json:"Id,omitempty"`
	Login               *LoginData      `json:"Login,omitempty"`
	Card                *CardData       `json:"Card,omitempty"`
	SecureNote          *SecureNoteData `json:"SecureNote,omitempty"`
	Identity            *IdentityData   `json:"Identity,omitempty"`
	Attachments         []string
	OrganizationUseTotp bool
	RevisionDate        *Time `json:"RevisionDate,omitempty"`
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
	RevisionDate *Time
}

type List struct {
	Object string
	Data   interface{}
}

// Experimental
// Request objects
type CipherRequest struct {
	Type           int
	OrganizationId *string
	FolderId       *string
	Favorite       bool
	Name           *string
	Notes          *string
	Fields         *[]FieldData
	Attachments    *[]string

	Login      *LoginData      `json:"Login,omitempty"`
	Card       *CardData       `json:"Card,omitempty"`
	SecureNote *SecureNoteData `json:"SecureNote,omitempty"`
	Identity   *IdentityData   `json:"Identity,omitempty"`

	RevisionDate *Time
}

func (cr *CipherRequest) FromCipher(c Cipher) error {
	j, err := json.Marshal(c)
	if err != nil {
		return err
	}
	err = json.Unmarshal(j, cr)
	switch c.Type {
	case CipherType_Login:
		cr.Name = c.Login.Name
		cr.Fields = c.Login.Fields
		cr.Login.Name = nil
		cr.Login.Fields = nil
	case CipherType_Card:
		cr.Name = c.Card.Name
		cr.Fields = c.Card.Fields
		cr.Card.Name = nil
		cr.Card.Fields = nil
	case CipherType_Identity:
		cr.Name = c.Identity.Name
		cr.Fields = c.Identity.Fields
		cr.Identity.Name = nil
		cr.Identity.Fields = nil
	case CipherType_SecureNote:
		cr.Name = c.SecureNote.Name
		cr.Fields = c.SecureNote.Fields
		cr.SecureNote.Name = nil
		cr.SecureNote.Fields = nil
	default:
		log.Fatal("invalid cipher type")
	}
	return err
}

func (cr *CipherRequest) ToCipher() (Cipher, error) {
	var c Cipher
	j, err := json.Marshal(cr)
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(j, &c)
	switch c.Type {
	case CipherType_Login:
		c.Login.Name = cr.Name
		c.Login.Fields = cr.Fields
	case CipherType_Card:
		c.Card.Name = cr.Name
		c.Card.Fields = cr.Fields
	case CipherType_Identity:
		c.Identity.Name = cr.Name
		c.Identity.Fields = cr.Fields
	case CipherType_SecureNote:
		c.SecureNote.Name = cr.Name
		c.SecureNote.Fields = cr.Fields
	default:
		log.Fatal("invalid cipher type")
	}

	return c, err
}

// Response objects
type Response struct {
	// TODO
	Object string
}

type ErrorResponse struct {
	Response

	ExceptionMessage    string
	ExceptionStackTrace string
	Message             string
	ValidationErrors    map[string][2]string
}

type CipherMiniResponse struct {
	Response

	Id             string
	OrganizationId *string
	Type           int
	Data           interface{}
	Attachments    []string
	RevisionDate   *Time
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

type FieldData struct {
	Type  int
	Name  string
	Value string
}

type CipherData struct {
	Name   *string      `json:"Name,omitempty"`
	Notes  *string      `json:"Notes,omitempty"`
	Fields *[]FieldData `json:"Fields,omitempty"`
}

type LoginData struct {
	CipherData
	URI      *string `json:"Uri"`
	Username *string `json:"Username"`
	Password *string `json:"Password"`
	ToTp     *string `json:"Totp"`
}

type CardData struct {
	CipherData
	CardholderName *string
	Brand          *string
	Number         *string
	ExpMonth       *string
	ExpYear        *string
	Code           *string
}

type IdentityData struct {
	CipherData
	Title          *string
	FirstName      *string
	MiddleName     *string
	LastName       *string
	Address1       *string
	Address2       *string
	Address3       *string
	City           *string
	State          *string
	PostalCode     *string
	Country        *string
	Company        *string
	Email          *string
	Phone          *string
	SSN            *string
	Username       *string
	PassportNumber *string
	LicenseNumber  *string
}

type SecureNoteData struct {
	CipherData
	Type string // is int, but sent as string from web
}

type ProfileOrganizationResponse struct {
}

type ProfileResponse struct {
	Response
	Id                 string
	Name               string
	Email              string
	EmailVerified      bool
	Premium            bool
	MasterPasswordHint *string
	Culture            string
	TwoFactorEnabled   bool
	Key                string
	PrivateKey         string
	SecurityStamp      *string

	Organizations *[]ProfileOrganizationResponse
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

func (c *Cipher) UnMarshalData(v []byte) error {
	switch c.Type {
	case CipherType_Login:
		json.Unmarshal(v, &c.Login)
	case CipherType_Card:
		json.Unmarshal(v, &c.Card)
	case CipherType_Identity:
		json.Unmarshal(v, &c.Identity)
	case CipherType_SecureNote:
		json.Unmarshal(v, &c.SecureNote)
	default:
		log.Fatal("invalid cipher type")
	}
	return nil
}

func (c *Cipher) MarshalData() ([]byte, error) {
	var v interface{}
	switch c.Type {
	case CipherType_Login:
		v = c.Login
	case CipherType_Card:
		v = c.Card
	case CipherType_Identity:
		v = c.Identity
	case CipherType_SecureNote:
		v = c.SecureNote
	default:
		log.Fatal("invalid cipher type")
	}
	return json.Marshal(v)
}

func NewProfileResponse(user Account) ProfileResponse {
	return ProfileResponse{
		Response:           Response{"profile"},
		Id:                 user.Id,
		Name:               user.Name,
		Email:              user.Email,
		EmailVerified:      true, // user.EmailVerified
		Premium:            true, //
		MasterPasswordHint: nil,  // user.MasterPasswordHint,
		Culture:            "en-US",
		TwoFactorEnabled:   false,
		Key:                user.Key,
		PrivateKey:         user.Keys.EncryptedPrivateKey,
		SecurityStamp:      nil, // user.SecurityStamp,
		Organizations:      nil,
	}
}
