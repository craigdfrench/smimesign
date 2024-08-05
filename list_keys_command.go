package main

import (
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/pkg/errors"
)

func commandListKeys(writer io.Writer) error {
	for j, ident := range idents {
		if j > 0 {
			fmt.Print("\n")
		}

		cert, err := ident.Certificate()
		if err != nil {
			fmt.Fprintln(os.Stderr, "WARNING:", errors.Wrap(err, "failed to get identity certificate"))
			continue
		}

		if cert.KeyUsage&x509.KeyUsageDigitalSignature > 0 && !cert.IsCA {
			_, _ = fmt.Fprintln(writer, "       ID:", certHexFingerprint(cert))
			_, _ = fmt.Fprintln(writer, "      S/N:", cert.SerialNumber.Text(16))
			_, _ = fmt.Fprintln(writer, "Algorithm:", cert.SignatureAlgorithm.String())
			_, _ = fmt.Fprintln(writer, " Validity:", cert.NotBefore.String(), "-", cert.NotAfter.String())
			_, _ = fmt.Fprintln(writer, "   Issuer:", cert.Issuer.ToRDNSequence().String())
			_, _ = fmt.Fprintln(writer, "  Subject:", cert.Subject.ToRDNSequence().String())
			_, _ = fmt.Fprintln(writer, "   Emails:", strings.Join(certEmails(cert), ", "))
		}
	}

	return nil
}
