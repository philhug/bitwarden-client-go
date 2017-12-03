package cmd

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"encoding/json"
	"github.com/philhug/bitwarden-client-go/bitwarden"
	"github.com/spf13/cobra"
)

var importCmd = &cobra.Command{
	Use:   "import [ciphers|folders|sync-raw|lastpass] import.json",
	Short: "Import data into Bitwarden",
	Long:  `Imports passwords into bitwarden from a json or csv file.`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 2 {
			return errors.New("requires at least 2 arg")
		}

		format = args[0]
		if len(args) > 1 {
			filename = args[1]
		}

		if IsValidImportFormat(args[0]) {
			return nil
		}
		return fmt.Errorf("invalid import format specified: %s", args[0])
	},
	Run: func(cmd *cobra.Command, args []string) {

		log.Println("Import called for: " + userName)
		log.Println("Format: " + format)
		log.Println("Input file: " + filename)

		client, err := bitwarden.NewUserPasswordAuthClient(userName, password)
		if err != nil {
			log.Fatal(err)
		}

		var profile bitwarden.Account
		profile, err = client.Account.GetProfile()
		if err != nil {
			log.Fatal(err)
		}

		dk := bitwarden.MakeKey(password, userName)

		cs, err := bitwarden.NewCipherString(profile.Key)
		if err != nil {
			log.Fatal(err)
		}

		mk, err := cs.DecryptKey(dk, bitwarden.AesCbc256_HmacSha256_B64)
		if err != nil {
			log.Fatal(err)
		}

		ciphers, err := client.Cipher.ListCiphers()
		if err != nil {
			log.Fatal(err)
		}
		for _, ciph := range ciphers {
			err := ciph.Decrypt(mk)
			if err != nil {
				log.Fatal(err)
			}
		}

		folders, err := client.Folder.ListFolders()
		if err != nil {
			log.Fatal(err)
		}
		for i, f := range folders {
			err := f.Decrypt(mk)
			folders[i] = f
			if err != nil {
				log.Fatal(err)
			}
		}

		switch format {
		case "bitwarden-csv",
			"lastpass-csv",
			"csv":
			// folder,favorite,type,name,notes,fields,login_uri,login_username,login_password,login_totp

			f, err := os.Open(filename)
			if err != nil {
				log.Fatal(err)
			}
			defer f.Close()

			r := bufio.NewReader(f)
			header, _, err := r.ReadLine()

			cr := csv.NewReader(r)

			folder := bitwarden.Folder{}
			folder.Name = fmt.Sprintf("Import from %s", time.Now().Format(time.RFC822))
			log.Printf("Importing into new folder \"%s\"", folder.Name)

			folder.Encrypt(mk)

			fldr, err := client.Folder.AddFolder(&folder)
			if err != nil {
				log.Fatal(err)
			}

			for {
				record, err := cr.Read()
				if err == io.EOF {
					break
				}
				if err != nil {
					log.Fatal(err)
				}
				csr := CsvRecord{}
				err = csr.FromCsv(string(header), record)
				if err != nil {
					log.Fatal(err)
				}
				csr.Cipher.FolderId = &fldr.Id

				j, _ := json.MarshalIndent(csr.Cipher, "", "  ")
				log.Println(string(j))
				break
				err = csr.Cipher.Encrypt(mk)
				if err != nil {
					log.Fatal(err)
				}
				_, err = client.Cipher.AddCipher(&csr.Cipher)
				if err != nil {
					log.Fatal(err)
				}
			}
			log.Println("Import completed.")
		case "ciphers":

		case "folders":

		case "sync-raw":
			sync, err := client.Sync.GetSync()
			if err != nil {
				log.Fatal(err)
			}

			ciphs := make([]bitwarden.Cipher, len(sync.Ciphers))

			for i, ciph := range sync.Ciphers {
				c := ciph.ToCipher()
				err := c.Decrypt(mk)
				if err != nil {
					log.Fatal(err)
				}
				ciphs[i] = c
			}

		case "sync-decrypted":
			sync, err := client.Sync.GetSync()
			if err != nil {
				log.Fatal(err)
			}

			ciphs := make([]bitwarden.Cipher, len(sync.Ciphers))

			for i, ciph := range sync.Ciphers {
				c := ciph.ToCipher()
				err := c.Decrypt(mk)
				if err != nil {
					log.Fatal(err)
				}
				ciphs[i] = c
			}

			for i, f := range sync.Folders {
				err := f.Decrypt(mk)
				sync.Folders[i] = f
				if err != nil {
					log.Fatal(err)
				}
			}
		}
	},
}

func IsValidImportFormat(format string) bool {
	switch format {
	case
		"folders",
		"ciphers",
		"sync-decrypted",
		"csv":
		return true
	}
	return false
}

func init() {
	RootCmd.AddCommand(importCmd)
}
