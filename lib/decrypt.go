package lib

import (
	"encoding/base64"

	"github.com/lkzcover/easyaes"
)

func decryptURLData(data, key string) ([]byte, []byte, error) {

	rawData, err := base64.URLEncoding.DecodeString(data)
	if err != nil {
		return nil, nil, err
	}

	iv := rawData[:len(key)]
	targetEncryptedData := rawData[len(key):]

	decrypt, err := easyaes.DecryptAesCBCStaticIV([]byte(key), iv, targetEncryptedData)
	return decrypt, iv, err

}

func decryptBodyData(key string, iv, data []byte) ([]byte, error) {

	rawData, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}

	decrypt, err := easyaes.DecryptAesCBCStaticIV([]byte(key), iv, rawData)
	return decrypt, err

}
