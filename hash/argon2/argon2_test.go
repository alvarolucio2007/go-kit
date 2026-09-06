package argon2_test

import (
	"testing"

	"github.com/alvarolucio2007/go-kit/hash/argon2"
	"github.com/go-faker/faker/v4"
	"github.com/go-openapi/testify/v2/require"
)

type FakePassword struct {
	Password string `faker:"word"`
}

func TestPassword(t *testing.T) {
	fakePassword := FakePassword{}
	err := faker.FakeData(&fakePassword)
	require.NoError(t, err)
	hashedPassword, err := argon2.HashPassword(fakePassword.Password)

	require.NoError(t, err)
	require.NotEmpty(t, hashedPassword)

	isSame, err := argon2.CheckPassword(fakePassword.Password, hashedPassword)
	require.NoError(t, err)
	require.True(t, isSame)

	hashedPassword2, err := argon2.HashPassword(fakePassword.Password)
	require.NoError(t, err)
	require.NotEmpty(t, hashedPassword2)
	require.NotEqual(t, hashedPassword, hashedPassword2)
}
