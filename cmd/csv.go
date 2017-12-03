package cmd

import (
	"log"

	"fmt"
	"github.com/philhug/bitwarden-client-go/bitwarden"
)

const (
	BITWARDEN_HEADER = "folder,favorite,type,name,notes,fields,login_uri,login_username,login_password,login_totp"
	LASTPASS_HEADER  = "url,username,password,extra,name,grouping,fav"
)

type CsvRecord struct {
	bitwarden.Cipher
	Folder string
}

func (csv *CsvRecord) ToCsv(header string) ([]string, error) {
	ciph := csv.Cipher
	switch ciph.Type {
	case bitwarden.CipherType_Login:
		var name string
		var notes string
		var uri string
		var username string
		var password string
		if ciph.Login.Name != nil {
			name = *ciph.Login.Name
		}
		if ciph.Login.Notes != nil {
			notes = *ciph.Login.Notes
		}
		if ciph.Login.URI != nil {
			uri = *ciph.Login.URI
		}
		if ciph.Login.Username != nil {
			username = *ciph.Login.Username
		}
		if ciph.Login.Password != nil {
			password = *ciph.Login.Password
		}
		return []string{csv.Folder, "", "login", name, notes, "", uri, username, password, ""}, nil
	case bitwarden.CipherType_SecureNote:
		var name string
		var notes string
		if ciph.SecureNote.Name != nil {
			name = *ciph.SecureNote.Name
		}
		if ciph.SecureNote.Notes != nil {
			notes = *ciph.SecureNote.Notes
		}
		return []string{csv.Folder, "", "note", name, notes, "", "", "", "", ""}, nil

	default:
		log.Println("unknown cipher type, skipping... ", ciph.Type)
	}
	return nil, nil
}

func (csv *CsvRecord) FromCsv(header string, record []string) error {
	ciph := &csv.Cipher

	switch header {
	case BITWARDEN_HEADER:
		// folder,favorite,type,name,notes,fields,login_uri,login_username,login_password,login_totp
		csv.Folder = record[0]
		ciph.Favorite = record[1] == "1"
		switch record[2] {
		case "login":
			ciph.Type = bitwarden.CipherType_Login
			ld := bitwarden.LoginData{
				CipherData: bitwarden.CipherData{
					Name:  &record[3],
					Notes: &record[4],
				},
				// Fields = record[5],
				URI:      &record[6],
				Username: &record[7],
				Password: &record[8],
				ToTp:     &record[9],
			}
			ciph.Login = &ld
		case "note":
			ciph.Type = bitwarden.CipherType_SecureNote
			snd := bitwarden.SecureNoteData{
				CipherData: bitwarden.CipherData{
					Name:  &record[3],
					Notes: &record[4],
				},
			}
			ciph.SecureNote = &snd
		default:
			return fmt.Errorf("unknown cipher type ", record[2])
		}

	case LASTPASS_HEADER:
		// url,username,password,extra,name,grouping,fav
		csv.Folder = record[5]
		ciph.Favorite = record[6] == "1"
		switch record[0] {
		case "http://sn":
			ciph.Type = bitwarden.CipherType_SecureNote
			snd := bitwarden.SecureNoteData{
				CipherData: bitwarden.CipherData{
					Notes: &record[3],
					Name:  &record[4],
				},
			}
			ciph.SecureNote = &snd
		default: // assume it's login data
			ciph.Type = bitwarden.CipherType_Login
			ld := bitwarden.LoginData{
				CipherData: bitwarden.CipherData{
					Notes: &record[3],
					Name:  &record[4],
				},
				// Fields = record[5],
				URI:      &record[0],
				Username: &record[1],
				Password: &record[2],
			}
			ciph.Login = &ld
		}

	default:
		return fmt.Errorf("Unknown CSV header: %s", header)
	}

	return nil
}
