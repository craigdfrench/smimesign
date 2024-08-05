//go:generate goversioninfo -file-version=$GIT_VERSION -ver-major=$VERSION_MAJOR -ver-minor=$VERSION_MINOR -ver-patch=$VERSION_PATCH -platform-specific=true windows-installer/versioninfo.json

package main

import (
	"fmt"
	"github.com/github/smimesign/certstore"
	"github.com/gliderlabs/ssh"
	"github.com/pborman/getopt/v2"
	"github.com/pkg/errors"
	"io"
	"log"
	"os"
)

var (
	// This can be set at build time by running
	// go build -ldflags "-X main.versionString=$(git describe --tags)"
	versionString = "undefined"

	// default timestamp authority URL. This can be set at build time by running
	// go build -ldflags "-X main.defaultTSA=${https://whatever}"
	defaultTSA = ""

	// Action flags
	helpFlag        = getopt.BoolLong("help", 'h', "print this help message")
	versionFlag     = getopt.BoolLong("version", 'v', "print the version number")
	signFlag        = getopt.BoolLong("sign", 's', "make a signature")
	verifyFlag      = getopt.BoolLong("verify", 0, "verify a signature")
	listKeysFlag    = getopt.BoolLong("list-keys", 0, "show keys")
	listeningServer = getopt.BoolLong("listening-server", 'l', "SSH Server")

	// Option flags
	localUserOpt    = getopt.StringLong("local-user", 'u', "", "use USER-ID to sign", "USER-ID")
	detachSignFlag  = getopt.BoolLong("detach-sign", 'b', "make a detached signature")
	armorFlag       = getopt.BoolLong("armor", 'a', "create ascii armored output")
	statusFdOpt     = getopt.IntLong("status-fd", 0, -1, "write special status strings to the file descriptor n.", "n")
	keyFormatOpt    = getopt.EnumLong("keyid-format", 0, []string{"long"}, "long", "select  how  to  display key IDs.", "{long}")
	tsaOpt          = getopt.StringLong("timestamp-authority", 't', defaultTSA, "URL of RFC3161 timestamp authority to use for timestamping", "url")
	includeCertsOpt = getopt.IntLong("include-certs", 0, -2, "-3 is the same as -2, but ommits issuer when cert has Authority Information Access extension. -2 includes all certs except root. -1 includes all certs. 0 includes no certs. 1 includes leaf cert. >1 includes n from the leaf. Default -2.", "n")

	// Remaining arguments
	fileArgs []string

	idents []certstore.Identity

	// these are changed in tests
	stdin  io.ReadCloser  = os.Stdin
	stdout io.WriteCloser = os.Stdout
	stderr io.WriteCloser = os.Stderr
)

func main() {
	getopt.SetParameters("[files]")
	getopt.Parse()
	fileArgs = getopt.Args()

	if *listeningServer {
		ssh.Handle(func(s ssh.Session) {
			getopt.Reset()
			getopt.SetParameters("[files]")
			getopt.CommandLine.Parse(s.Command())
			fileArgs = getopt.Args()

			err := populateIdentities()
			if err != nil {
				return
			}
			/*
				dir, err := os.Getwd()
				if err != nil {
					fmt.Fprintln(s.Stderr(), err)
				}


				//fmt.Fprintln(s.Stderr(), "Current working directory: %s", dir)
				/*
					_, err = io.WriteString(s.Stderr(),
						fmt.Sprintf(
							"smimesign tool\nUser %s\nLocal %s\nRemote %s\nCommand %s\nEnviron:%s\nPermissions:%s",
							s.User(),
							s.LocalAddr(),
							s.RemoteAddr(),
							s.Command(),
							s.Environ(),
							s.Permissions()))
					if err != nil {
						return
					}
			*/
			err = runCommand(s, s, s.Stderr())
			if err != nil {
				fmt.Fprintln(s.Stderr(), err)
				//os.Exit(1)
			}
			/*
				if *listKeysFlag {
					err := commandListKeys(s)
					if err != nil {
						return
					}
				} else {
					all, err := io.ReadAll(s)
					if err != nil {
						return
					}

					_, err = io.WriteString(s, string(all))
					if err != nil {
						return
					}
				}
			*/

		})

		log.Fatal(ssh.ListenAndServe(":2222", nil))

	} else {
		if err := runCommand(os.Stdin, os.Stderr, os.Stderr); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}

func populateIdentities() error {
	// Open certificate store
	store, err := certstore.Open()
	if err != nil {
		return errors.Wrap(err, "failed to open certificate store")
	}
	//defer store.Close()

	// Get list of identities
	idents, err = store.Identities()
	if err != nil {
		return errors.Wrap(err, "failed to get identities from certificate store")
	}
	//for _, ident := range idents {
	//	defer ident.Close()
	//}
	return nil
}

func runCommand(reader io.Reader, writer io.Writer, errorWriter io.Writer) error {
	// Parse CLI args

	getopt.HelpColumn = 40
	// Parse the options from the input string

	err := populateIdentities()
	if err != nil {
		return err
	}

	if *helpFlag {
		getopt.PrintUsage(writer)
		return nil
	}

	if *versionFlag {
		_, _ = fmt.Fprintln(writer, versionString)
		return nil
	}

	if *listeningServer {
		fmt.Fprintln(writer, "SSH session Listening on port 2222")

	}

	if *signFlag {
		if *verifyFlag || *listKeysFlag {
			return errors.New("specify --help, --sign, --verify, or --list-keys")
		} else if len(*localUserOpt) == 0 {
			return errors.New("specify a USER-ID to sign with")
		} else if *statusFdOpt == 1 {
			return commandSign(
				reader,
				writer,
				writer)
		} else if *statusFdOpt == 2 {
			return commandSign(
				reader,
				writer,
				errorWriter,
			)
		}
	}

	if *verifyFlag {
		if *signFlag || *listKeysFlag {
			return errors.New("specify --help, --sign, --verify, or --list-keys")
		} else if len(*localUserOpt) > 0 {
			return errors.New("local-user cannot be specified for verification")
		} else if *detachSignFlag {
			return errors.New("detach-sign cannot be specified for verification")
		} else if *armorFlag {
			return errors.New("armor cannot be specified for verification")
		} else {
			return commandVerify(reader, writer, errorWriter)
		}
	}

	if *listKeysFlag {
		if *signFlag || *verifyFlag {
			return errors.New("specify --help, --sign, --verify, or --list-keys")
		} else if len(*localUserOpt) > 0 {
			return errors.New("local-user cannot be specified for list-keys")
		} else if *detachSignFlag {
			return errors.New("detach-sign cannot be specified for list-keys")
		} else if *armorFlag {
			return errors.New("armor cannot be specified for list-keys")
		} else {
			return commandListKeys(writer)
		}
	}

	return errors.New("specify --help, --sign, --verify, or --list-keys")
}

func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destinationFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destinationFile.Close()

	_, err = io.Copy(destinationFile, sourceFile)
	if err != nil {
		return err
	}

	err = destinationFile.Sync()
	if err != nil {
		return err
	}

	return nil
}
