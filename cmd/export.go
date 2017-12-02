package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/philhug/bitwarden-client-go/bitwarden"
	"github.com/spf13/cobra"
)

var format string
var filename string

var exportCmd = &cobra.Command{
	Use:   "export [ciphers|folders|sync-raw] export.json",
	Short: "Export Bitwarden data",
	Long: `Export passwords from bitwarden into a json file.

Export format can be imported again with bitwarden import
command.`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("requires at least one arg")
		}

		format = args[0]
		if len(args) > 1 {
			filename = args[1]
		}

		if IsValidExportFormat(args[0]) {
			return nil
		}
		return fmt.Errorf("invalid export format specified: %s", args[0])
	},
	Run: func(cmd *cobra.Command, args []string) {

		log.Println("Export called for: " + userName)
		log.Println("Format: " + format)
		log.Println("Output file: " + filename)

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

		mk, err := cs.Decrypt(dk)
		if err != nil {
			log.Fatal(err)
		}

		var j []byte

		switch format {
		case "ciphers":
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
			j, _ = json.MarshalIndent(ciphers, "", "  ")

		case "folders":
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

			j, _ = json.MarshalIndent(folders, "", "  ")

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
			j, _ = json.MarshalIndent(sync, "", "  ")

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
			j, _ = json.MarshalIndent(ciphs, "", "  ")
		}
		if filename == "" {
			fmt.Println(string(j))
		} else {
			ioutil.WriteFile(filename, j, 0644)
		}
	},
}

func IsValidExportFormat(format string) bool {
	switch format {
	case
		"folders",
		"ciphers",
		"sync-decrypted":
		return true
	}
	return false
}

func init() {
	RootCmd.AddCommand(exportCmd)
}
