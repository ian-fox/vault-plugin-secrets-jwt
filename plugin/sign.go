package jwtsecrets

import (
	"errors"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func (b *backend) sign(expiry time.Time, claims map[string]interface{}) (string, error) {

	key, err := b.getKey(expiry)
	if err != nil {
		return "", errors.New("error getting key: " + err.Error())
	}

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key.Key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", key.ID))
	if err != nil {
		return "", errors.New("error signing claims: " + err.Error())
	}

	token, err := jwt.Signed(sig).Claims(claims).CompactSerialize()
	if err != nil {
		return "", errors.New("error serializing jwt: " + err.Error())
	}

	return token, nil
}
