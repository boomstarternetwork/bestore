package bestore

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_MockStore_implementsStore(t *testing.T) {
	//var _ Store = NewMockStore()
	var ms interface{} = NewMockStore()
	_, ok := ms.(Store)
	assert.True(t, ok)
}
