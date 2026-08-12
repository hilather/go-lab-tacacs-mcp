package config

import (
	"io"
	"io/fs"
	"os"

	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
)

// ReadOptions controls secret-file and environment resolution.
type ReadOptions struct {
	// AllowEnvironment permits environment references. Default false.
	AllowEnvironment bool
	// StrictFiles rejects symlinks. Default true when unset via StrictFilesSet.
	StrictFiles    bool
	StrictFilesSet bool
	// MaxBytes is the maximum secret file size. Zero means DefaultMaxSecretBytes.
	MaxBytes int64
	// LookupEnv overrides environment lookup (tests).
	LookupEnv func(string) (string, bool)
	// Lstat and Open override filesystem access (tests).
	Lstat func(string) (fs.FileInfo, error)
	Open  func(string) (fs.File, error)
}

func (o ReadOptions) strictFiles() bool {
	if o.StrictFilesSet {
		return o.StrictFiles
	}
	return true
}

func (o ReadOptions) maxBytes() int64 {
	if o.MaxBytes <= 0 {
		return DefaultMaxSecretBytes
	}
	return o.MaxBytes
}

// FileLookup resolves secret references to raw bytes using ReadOptions.
// Callers must wipe the returned buffer. Errors never include the secret value.
func FileLookup(opts ReadOptions) SecretLookup {
	return func(ref SecretRef) ([]byte, error) {
		return readSecretBytes(ref, opts)
	}
}

// ReadSecret loads the referenced bytes into a typed holder for ref.Purpose.
// Errors never include the secret value.
func ReadSecret(ref SecretRef, opts ReadOptions) (credentials.Purpose, any, error) {
	raw, err := readSecretBytes(ref, opts)
	if err != nil {
		return ref.Purpose, nil, err
	}
	defer wipeBytes(raw)
	switch ref.Purpose {
	case credentials.PurposeLoginVerifier:
		if err := credentials.ValidatePHC(raw); err != nil {
			return ref.Purpose, nil, yamlError("login verifier is not a valid argon2id PHC string")
		}
		return ref.Purpose, credentials.NewLoginVerifier(raw), nil
	case credentials.PurposeChallengeSecret:
		return ref.Purpose, credentials.NewChallengeSecret(raw), nil
	case credentials.PurposeEnableVerifier:
		if err := credentials.ValidatePHC(raw); err != nil {
			return ref.Purpose, nil, yamlError("enable verifier is not a valid argon2id PHC string")
		}
		return ref.Purpose, credentials.NewEnableVerifier(raw), nil
	case credentials.PurposeLegacySharedSecret:
		return ref.Purpose, credentials.NewSharedSecret(raw), nil
	case credentials.PurposeAPIBearerToken:
		return ref.Purpose, credentials.NewTokenMaterial(raw), nil
	case credentials.PurposeTLSPrivateKey:
		return ref.Purpose, credentials.NewTLSPrivateKey(raw), nil
	case credentials.PurposeTLSPSK:
		return ref.Purpose, credentials.NewTLSPSK(raw), nil
	default:
		return ref.Purpose, nil, yamlError("unknown secret purpose")
	}
}

func readSecretBytes(ref SecretRef, opts ReadOptions) ([]byte, error) {
	if !ref.Set() {
		return nil, yamlError("secret reference requires file or environment")
	}
	if ref.File != "" && ref.Environment != "" {
		return nil, yamlError("secret reference must set exactly one of file or environment")
	}
	var raw []byte
	var err error
	if ref.Environment != "" {
		raw, err = readEnvSecret(ref.Environment, opts)
	} else {
		raw, err = readFileSecret(ref.File, opts)
	}
	if err != nil {
		return nil, err
	}
	return trimSecret(raw, ref.PreserveTrailingNewline), nil
}

func readEnvSecret(name string, opts ReadOptions) ([]byte, error) {
	if !opts.AllowEnvironment {
		return nil, yamlError("environment secret references are disabled")
	}
	lookup := opts.LookupEnv
	if lookup == nil {
		lookup = os.LookupEnv
	}
	v, ok := lookup(name)
	if !ok {
		return nil, secretFileError("environment", "environment secret is not set")
	}
	return []byte(v), nil
}

func readFileSecret(path string, opts ReadOptions) ([]byte, error) {
	lstat := opts.Lstat
	if lstat == nil {
		lstat = os.Lstat
	}
	info, err := lstat(path)
	if err != nil {
		return nil, secretFileError(path, "secret file is not readable")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		if opts.strictFiles() {
			return nil, secretFileError(path, "secret path is a symlink")
		}
		info, err = os.Stat(path)
		if err != nil {
			return nil, secretFileError(path, "secret file is not readable")
		}
	}
	if info.IsDir() {
		return nil, secretFileError(path, "secret path is a directory")
	}
	if info.Mode().Perm()&0o002 != 0 {
		return nil, secretFileError(path, "secret file is world-writable")
	}
	if info.Size() > opts.maxBytes() {
		return nil, secretFileError(path, "secret file exceeds maximum size")
	}

	open := opts.Open
	if open == nil {
		open = func(p string) (fs.File, error) { return os.Open(p) }
	}
	f, err := open(path)
	if err != nil {
		return nil, secretFileError(path, "secret file is not readable")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, opts.maxBytes()+1))
	if err != nil {
		wipeBytes(data)
		return nil, secretFileError(path, "secret file is not readable")
	}
	if int64(len(data)) > opts.maxBytes() {
		wipeBytes(data)
		return nil, secretFileError(path, "secret file exceeds maximum size")
	}
	return data, nil
}

func trimSecret(b []byte, preserve bool) []byte {
	if preserve || len(b) == 0 {
		return b
	}
	if b[len(b)-1] != '\n' {
		return b
	}
	b = b[:len(b)-1]
	if len(b) > 0 && b[len(b)-1] == '\r' {
		b = b[:len(b)-1]
	}
	return b
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
