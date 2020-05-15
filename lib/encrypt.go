package lib

import (
	"encoding/base64"

	"github.com/lkzcover/easyaes"
)

func decryptData(data, key string) ([]byte, error) {

	iv := data[:len(key)]
	targetBase64 := data[len(key):]

	targetByte, err := base64.StdEncoding.DecodeString(targetBase64)
	if err != nil {
		return nil, err
	}

	return easyaes.DecryptAesCBCStaticIV([]byte(key), []byte(iv), targetByte)

}
