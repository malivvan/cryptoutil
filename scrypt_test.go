package cryptoutil

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestScryptConfig_EncodeDecode(t *testing.T) {
	encodedConfig := ScryptConfigLow.Encode()
	config, err := DecodeScryptConfig(encodedConfig)
	assert.NoError(t, err)

	assert.Equal(t, ScryptConfigLow.N, config.N)
	assert.Equal(t, ScryptConfigLow.R, config.R)
	assert.Equal(t, ScryptConfigLow.P, config.P)
}
