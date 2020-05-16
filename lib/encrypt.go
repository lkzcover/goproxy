package lib

import (
	"encoding/base64"

	"github.com/lkzcover/easyaes"
)

func decryptData(data, key string) ([]byte, []byte, error) {

	rawData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, nil, err
	}

	iv := rawData[:len(key)]
	targetEncryptedData := rawData[len(key):]

	decrypt, err := easyaes.DecryptAesCBCStaticIV([]byte(key), iv, targetEncryptedData)
	return decrypt, iv, err

}
