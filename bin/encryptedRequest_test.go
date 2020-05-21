package main

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"testing"

	"github.com/lkzcover/easyaes"
)

func TestEncryptedRequest(t *testing.T) {

	urlReq := "http://localhost:9000/?target=https://google.com"

	resp, err := http.Get(urlReq)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Incorrect response status. Get: %d but Expecdet: 200", resp.StatusCode)
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("%s", string(respBody))

	urlReq = "http://localhost:9000/?type=e&target="

	key := "test123456789012"
	iv := "qWeRtYu2o4a5d6g7"

	target, err := easyaes.EncryptAesCBCStaticIV([]byte(key), []byte(iv), []byte("https://google.com"))
	if err != nil {
		t.Fatal(err)
	}

	var splitByte bytes.Buffer

	splitByte.WriteString(iv)
	splitByte.Write(target)

	urlReq = urlReq + url.QueryEscape(base64.StdEncoding.EncodeToString(splitByte.Bytes()))

	resp, err = http.Get(urlReq)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Incorrect response status. Get: %d but Expecdet: 200", resp.StatusCode)
	}

	respBody2, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	decryptResp, err := easyaes.DecryptAesCBCStaticIV([]byte(key), []byte(iv), respBody2)
	if err != nil {
		t.Fatal(err)
	}

	log.Println(string(decryptResp))
}

// TODO написать тест POST зароса
