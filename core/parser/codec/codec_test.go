package codec

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetCodec(t *testing.T) {
	_, err := GetCodec("noop").Decode(nil)
	assert.NotNil(t, err)
}
