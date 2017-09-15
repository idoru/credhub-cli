package commands

import (
	"fmt"

	"github.com/cloudfoundry-incubator/credhub-cli/client"
	"github.com/cloudfoundry-incubator/credhub-cli/config"

	"bufio"
	"os"
	"strings"

	"github.com/cloudfoundry-incubator/credhub-cli/credhub"
	"github.com/cloudfoundry-incubator/credhub-cli/credhub/credentials"
	"github.com/cloudfoundry-incubator/credhub-cli/credhub/credentials/values"
	"github.com/cloudfoundry-incubator/credhub-cli/errors"
	"github.com/cloudfoundry-incubator/credhub-cli/util"
)

type SetCommand struct {
	CredentialIdentifier string `short:"n" required:"yes" long:"name" description:"Name of the credential to set"`
	Type                 string `short:"t" long:"type" description:"Sets the credential type. Valid types include 'value', 'json', 'password', 'user', 'certificate', 'ssh' and 'rsa'."`
	NoOverwrite          bool   `short:"O" long:"no-overwrite" description:"Credential is not modified if stored value already exists"`
	Value                string `short:"v" long:"value" description:"[Value, JSON] Sets the value for the credential"`
	CaName               string `short:"m" long:"ca-name" description:"[Certificate] Sets the root CA to a stored CA credential"`
	Root                 string `short:"r" long:"root" description:"[Certificate] Sets the root CA from file or value"`
	Certificate          string `short:"c" long:"certificate" description:"[Certificate] Sets the certificate from file or value"`
	Private              string `short:"p" long:"private" description:"[Certificate, SSH, RSA] Sets the private key from file or value"`
	Public               string `short:"u" long:"public" description:"[SSH, RSA] Sets the public key from file or value"`
	Username             string `short:"z" long:"username" description:"[User] Sets the username value of the credential"`
	Password             string `short:"w" long:"password" description:"[Password, User] Sets the password value of the credential"`
	OutputJson           bool   `          long:"output-json" description:"Return response in JSON format"`
}

func (cmd SetCommand) Execute([]string) error {
	cmd.Type = strings.ToLower(cmd.Type)

	if cmd.Type == "" {
		return errors.NewSetEmptyTypeError()
	}

	if cmd.Value == "" && (cmd.Type == "value" || cmd.Type == "json") {
		promptForInput("value: ", &cmd.Value)
	}

	if cmd.Password == "" && (cmd.Type == "password" || cmd.Type == "user") {
		promptForInput("password: ", &cmd.Password)
	}

	cfg := config.ReadConfig()

	var credhubClient *credhub.CredHub

	if clientCredentialsInEnvironment() {
		credhubClient, err = newCredhubClient(&cfg, os.Getenv("CREDHUB_CLIENT"), os.Getenv("CREDHUB_SECRET"), true)
	} else {
		credhubClient, err = newCredhubClient(&cfg, config.AuthClient, config.AuthPassword, false)
	}
	if err != nil {
		return err
	}

	err = config.ValidateConfig(cfg)
	if err != nil {
		if !clientCredentialsInEnvironment() {
			return err
		}
	}

	credential, err := MakeRequest(cmd, cfg, credhubClient)
	if err != nil {
		return err
	}

	printCredential(cmd.OutputJson, credential)

	return nil
}

func MakeRequest(cmd SetCommand, config config.Config, credhubClient *credhub.CredHub) (interface{}, error) {
	var output interface{}

	if cmd.Type == "ssh" || cmd.Type == "rsa" {
		var err error

		publicKey, err := util.ReadFileOrStringFromField(cmd.Public)
		if err != nil {
			return nil, err
		}

		privateKey, err := util.ReadFileOrStringFromField(cmd.Private)
		if err != nil {
			return nil, err
		}

		request = client.NewSetRsaSshRequest(config, cmd.CredentialIdentifier, cmd.Type, publicKey, privateKey, !cmd.NoOverwrite)
	} else if cmd.Type == "certificate" {
		var err error

		root, err := util.ReadFileOrStringFromField(cmd.Root)
		if err != nil {
			return nil, err
		}

		certificate, err := util.ReadFileOrStringFromField(cmd.Certificate)
		if err != nil {
			return nil, err
		}

		privateKey, err := util.ReadFileOrStringFromField(cmd.Private)
		if err != nil {
			return nil, err
		}

		request = client.NewSetCertificateRequest(config, cmd.CredentialIdentifier, root, cmd.CaName, certificate, privateKey, !cmd.NoOverwrite)

	} else if cmd.Type == "user" {
		value := values.User{
			cmd.Username,
			cmd.Password,
		}
		var userCredential credentials.User
		userCredential, err = credhubClient.SetUser(cmd.CredentialIdentifier, value, !cmd.NoOverwrite)
		output = interface{}(userCredential)

	} else if cmd.Type == "password" {
		request = client.NewSetCredentialRequest(config, cmd.Type, cmd.CredentialIdentifier, cmd.Password, !cmd.NoOverwrite)
	} else if cmd.Type == "json" {
		request = client.NewSetJsonCredentialRequest(config, cmd.Type, cmd.CredentialIdentifier, cmd.Value, !cmd.NoOverwrite)
	} else {
		request = client.NewSetCredentialRequest(config, cmd.Type, cmd.CredentialIdentifier, cmd.Value, !cmd.NoOverwrite)
	}

	if err != nil {
		return nil, err
	}

	return output, nil
}

func promptForInput(prompt string, value *string) {
	fmt.Printf(prompt)
	reader := bufio.NewReader(os.Stdin)
	val, _ := reader.ReadString('\n')
	*value = string(strings.TrimSpace(val))
}
