package cli_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/idzoid/cryptozoid/asymmetric/ec"
	"github.com/idzoid/cryptozoid/internal/cli"
)

func TestEcGenerateCommandSupportsCurves(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "P256", input: "P256", want: "P-256"},
		{name: "P384", input: "p384", want: "P-384"},
		{name: "P521", input: "P521", want: "P-521"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			cmd := cli.EcGenCommand{
				Curve: test.input,
				Name:  "test-key",
				Path:  dir,
			}
			if err := cmd.Execute(nil); err != nil {
				t.Fatal(err)
			}

			privatePath := filepath.Join(dir, "test-key_private.pem")
			publicPath := filepath.Join(dir, "test-key_public.pem")
			privateData, err := os.ReadFile(privatePath)
			if err != nil {
				t.Fatal(err)
			}
			publicData, err := os.ReadFile(publicPath)
			if err != nil {
				t.Fatal(err)
			}

			privateKey, err := ec.PemToECDSAKey(privateData)
			if err != nil {
				t.Fatal(err)
			}
			if got := ec.CurveName(privateKey); got != test.want {
				t.Fatalf("private curve = %q, want %q", got, test.want)
			}
			if _, err := ec.PemToECDSAPublic(publicData); err != nil {
				t.Fatal(err)
			}

			info, err := os.Stat(privatePath)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := info.Mode().Perm(), os.FileMode(0600); got != want {
				t.Fatalf("private key permissions = %o, want %o", got, want)
			}
		})
	}
}

func TestEcGenerateCommandRejectsUnsupportedCurve(t *testing.T) {
	cmd := cli.EcGenCommand{Curve: "P512", Name: "test-key", Path: t.TempDir()}
	if err := cmd.Execute(nil); err == nil {
		t.Fatal("expected unsupported curve to return an error")
	}
}
