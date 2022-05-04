package common

import (
	"crypto/md5"
	"errors"
)

type Auth struct {
	Token    []byte
	tokenMD5 []byte
}

func (a *Auth) Decrypt(text []byte) ([]byte, error) {
	textNew := []byte{}

	// Fetch first 4 bytes to xor
	tMd5, err := a.getTokenMD5()
	if err != nil {
		return nil, err
	}

	for _, b := range text {
		for i := 3; i >= 0; i-- {
			b = b ^ tMd5[i]
		}
		textNew = append(textNew, b)
	}

	return textNew, nil
}

func (a *Auth) Encrypt(text []byte) ([]byte, error) {
	textNew := []byte{}

	// Fetch first 4 bytes to xor
	tMd5, err := a.getTokenMD5()
	if err != nil {
		return nil, err
	}

	for _, b := range text {
		for i := 0; i < 4; i++ {
			b = b ^ tMd5[i]
		}
		textNew = append(textNew, b)
	}

	return textNew, nil
}

func (a *Auth) getTokenMD5() ([]byte, error) {
	if a.Token == nil {
		return nil, errors.New("auth: token is empty")
	}

	if a.tokenMD5 == nil {
		md5Handle := md5.New()
		a.tokenMD5 = md5Handle.Sum(a.Token)
	}

	return a.tokenMD5, nil
}
