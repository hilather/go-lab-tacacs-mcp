package registry

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func decodeYAML(path string, dest any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(dest); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}
