package cli

import (
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/idzoid/cryptozoid/ec"
	"github.com/idzoid/cryptozoid/pack"
	"github.com/idzoid/cryptozoid/symmetric"
)

const (
	CurveP256      = "P256"
	CurveP384      = "P384"
	CurveP521      = "P521"
	DefaultKeyName = "ec_private"
)

var validCurves = map[string]bool{
	CurveP256: true,
	CurveP384: false,
	CurveP521: false,
}

var keyGens = map[string]func() (*ecdh.PrivateKey, error){
	CurveP256: ec.GenEcdhP256PrivateKey,
}

var keymanagerConstructors = map[string]func(priv *ecdh.PrivateKey) ec.EcdhKeyManager{
	CurveP256: ec.NewEcdhP256KeyManager,
}

type EcdhCommand struct {
	Generate EcdhGenCommand     `command:"generate" description:"Generate ECDH Key"`
	Encrypt  EcdhEncryptCommand `command:"encrypt" description:"Encrypt a value using an ECDH Key"`
	Decrypt  EcdhDecryptCommand `command:"decrypt" description:"Decrypt a secret using an ECDH Key"`
}

type EcdhGenCommand struct {
	Curve string `short:"c" long:"curve" description:"Elliptic curve to use (P256, P384, P521)" default:"P256"`
	Name  string `short:"n" long:"name" description:"Name to be used to generate the Private Key file" default:"ec"`
}

func (cmd *EcdhGenCommand) Execute(args []string) error {
	if cmd.Curve == "" {
		cmd.Curve = CurveP256
	}
	if cmd.Name == "" {
		cmd.Curve = DefaultKeyName
	}
	enabled, ok := validCurves[strings.ToUpper(cmd.Curve)]
	if !ok {
		return fmt.Errorf("invalid curve: %s. Allowed values (P256, P384, P521)", cmd.Curve)
	}

	if !enabled {
		return fmt.Errorf("curve %s isn't enabled", cmd.Curve)
	}
	keyGen, ok := keyGens[cmd.Curve]
	if !ok {
		return fmt.Errorf("key gen for the curve %s was not found", cmd.Curve)
	}
	keymanagerConstructor, ok := keymanagerConstructors[cmd.Curve]
	if !ok {
		return fmt.Errorf("key manager for the curve %s was not found", cmd.Curve)
	}
	key, err := keyGen()
	if err != nil {
		return fmt.Errorf("error generating a %s key: %s", cmd.Curve, err)
	}

	keymanager := keymanagerConstructor(key)

	privPemBytes, err := keymanager.PrivateKeyToPem()
	if err != nil {
		return fmt.Errorf("error generating a %s key: %s", cmd.Curve, err)
	}

	err = os.WriteFile(fmt.Sprintf("%s_private.pem", cmd.Name), privPemBytes, 0600)
	if err != nil {
		return fmt.Errorf("error generating a %s key: %s", cmd.Curve, err)
	}

	pubPemBytes, err := keymanager.PublicKeyToPem()
	if err != nil {
		return fmt.Errorf("error generating a %s key: %s", cmd.Curve, err)
	}
	err = os.WriteFile(fmt.Sprintf("%s_public.pem", cmd.Name), pubPemBytes, 0600)
	if err != nil {
		return fmt.Errorf("error generating a %s key: %s", cmd.Curve, err)
	}

	privBytes, err := keymanager.PrivateKeyBytes()
	if err != nil {
		return fmt.Errorf("error generating a %s key: %s", cmd.Curve, err)
	}

	pubBytes, err := keymanager.PublicKeyBytes()
	if err != nil {
		return fmt.Errorf("error generating a %s key: %s", cmd.Curve, err)
	}

	fmt.Println("EC key pair generated and saved to ec_private.pem and ec_public.pem")
	fmt.Printf("Private Key(bytes): %x\n", privBytes)
	fmt.Printf("Public Key(bytes): %x\n", pubBytes)
	fmt.Println("Curve:", keymanager.CurveName())
	fmt.Println("Private Key Size:", len(privBytes))
	fmt.Println("Public Key Size:", len(pubBytes))

	return nil
}

type EcdhEncryptPositionalArgs struct {
	Text string `description:"Text to be encrypted"`
}

type EcdhEncryptCommand struct {
	Key  string                    `short:"k" long:"key" description:"Private key file to be used for encryption"`
	Args EcdhEncryptPositionalArgs `positional-args:"yes"`
}

func (cmd *EcdhEncryptCommand) Execute(args []string) error {
	if cmd.Key == "" {
		return errors.New("empty Key file. Please inform the Private Key file to be used")
	}

	fi, err := os.Stdin.Stat()
	if err != nil {
		return err
	}

	plain := cmd.Args.Text
	if (fi.Mode() & os.ModeCharDevice) == 0 {
		input, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		plain = string(input)
	}

	if plain == "" {
		return errors.New("empty Text. Please infor a Text to be encryped")
	}

	_, err = os.Stat(cmd.Key)

	if err != nil {
		return err
	}

	data, err := os.ReadFile(cmd.Key)
	if err != nil {
		return err
	}

	pk, err := ec.EcdhP256PemToPrivateKey(data)
	if err != nil {
		return err
	}
	curve := strings.ReplaceAll(fmt.Sprintf("%s", pk.Curve()), "-", "")
	keymanagerConstructor, ok := keymanagerConstructors[curve]
	if !ok {
		return fmt.Errorf("key manager for the curve %s was not found", curve)
	}

	keymanager := keymanagerConstructor(pk)
	sharedSecret, err := keymanager.DeriveSharedSecret(pk.PublicKey())
	if err != nil {
		return err
	}
	nonce, err := symmetric.NewAESGCMNonce()
	if err != nil {
		return err
	}

	ciphertext, err := symmetric.EncryptAESGCM(sharedSecret, nonce, []byte(plain))
	if err != nil {
		return err
	}

	secret := pack.BigEndianCombine(ciphertext, nonce)
	result := base64.StdEncoding.EncodeToString([]byte(secret))

	fmt.Println(result)

	return nil
}

type EcdhDecryptPositionalArgs struct {
	Secret string `description:"Secret to be decrypted"`
}

type EcdhDecryptCommand struct {
	Key  string                    `short:"k" long:"key" description:"Private key file to be used for decryption"`
	Args EcdhDecryptPositionalArgs `positional-args:"yes"`
}

func (cmd *EcdhDecryptCommand) Execute(args []string) error {
	if cmd.Key == "" {
		return errors.New("empty Key file. Please inform the Private Key file to be used")
	}

	fi, err := os.Stdin.Stat()
	if err != nil {
		return err
	}

	secret := cmd.Args.Secret
	if (fi.Mode() & os.ModeCharDevice) == 0 {
		input, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		secret = string(input)
	}

	if secret == "" {
		return errors.New("empty Secret. Please infor a Secret to be decrypted")
	}

	_, err = os.Stat(cmd.Key)

	if err != nil {
		return err
	}

	data, err := os.ReadFile(cmd.Key)
	if err != nil {
		return err
	}

	pk, err := ec.EcdhP256PemToPrivateKey(data)
	if err != nil {
		return err
	}
	curve := strings.ReplaceAll(fmt.Sprintf("%s", pk.Curve()), "-", "")
	keymanagerConstructor, ok := keymanagerConstructors[curve]
	if !ok {
		return fmt.Errorf("key manager for the curve %s was not found", curve)
	}

	keymanager := keymanagerConstructor(pk)
	sharedSecret, err := keymanager.DeriveSharedSecret(pk.PublicKey())
	if err != nil {
		return err
	}
	nonce, err := symmetric.NewAESGCMNonce()
	if err != nil {
		return err
	}
	packed, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return err
	}

	ciphertext, nonce, err := pack.BigEndianSeparate(packed)
	if err != nil {
		return err
	}
	plain, err := symmetric.DecryptAESGCM(sharedSecret, nonce, ciphertext)
	if err != nil {
		return err
	}

	fmt.Println(string(plain))

	return nil
}
