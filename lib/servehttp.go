package lib

import (
	"bytes"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/lkzcover/easyaes"
)

type HTTPServer struct {
}

func (obj *HTTPServer) ServeHTTP(resp http.ResponseWriter, req *http.Request) {

	log.Printf("Info: from: %s req: %s", req.RemoteAddr, req.URL)

	if err := req.ParseForm(); err != nil {
		log.Printf("Error: parse form error: %s", err)
		resp.WriteHeader(http.StatusInternalServerError)

		return
	}

	proxyURLReq := req.FormValue("target")
	if len(proxyURLReq) == 0 {
		log.Println("Error: empty target url")
		resp.WriteHeader(http.StatusBadRequest)

		return
	}

	var encryptMode bool
	var key string
	encryptModeReq := req.FormValue("type")
	if len(encryptModeReq) != 0 {
		encryptMode = true

		key = os.Getenv("KEY")
		if len(key) == 0 {
			log.Println("Warning: KEY environment parameter not set")
			resp.WriteHeader(http.StatusMethodNotAllowed)

			return
		}

	}

	var proxyRespBody, target, iv []byte
	var proxyResp *http.Response
	var err error

	switch req.Method {
	case "GET":
		{
			if encryptMode {
				target, iv, err = decryptData(proxyURLReq, key)
				if err != nil {
					log.Printf("Error: encrypt target for GET request: %s, error: %s", proxyURLReq, err)
					resp.WriteHeader(http.StatusInternalServerError)

					return
				}

				proxyURLReq = string(target)

			}

			proxyResp, err = http.Get(proxyURLReq)
			if err != nil {
				log.Printf("Error: GET request: %s error: %s", proxyURLReq, err)
				resp.WriteHeader(http.StatusInternalServerError)

				return
			}

		}
	case "POST":
		{
			var reqBody []byte
			var err error

			reqBody, err = ioutil.ReadAll(req.Body)
			if err != nil {
				log.Printf("Error: request: %s read body error: %s", proxyURLReq, err)
				resp.WriteHeader(http.StatusBadRequest)

				return
			}

			if encryptMode {
				target, iv, err = decryptData(proxyURLReq, key)
				if err != nil {
					log.Printf("Error: encrypt target for POST request: %s, error: %s", proxyURLReq, err)
					resp.WriteHeader(http.StatusInternalServerError)

					return
				}

				proxyURLReq = string(target)

				reqBody, _, err = decryptData(string(reqBody), key)
				if err != nil {
					log.Printf("Error: encrypt body for POST request: %s, error: %s", proxyURLReq, err)
					resp.WriteHeader(http.StatusInternalServerError)

					return
				}

			}

			bodyReader := bytes.NewReader(reqBody)
			contentType := req.Header.Get("Content-Type")

			proxyResp, err = http.Post(proxyURLReq, contentType, bodyReader)
			if err != nil {
				log.Printf("Error: POST request: %s error: %s", proxyURLReq, err)
				resp.WriteHeader(http.StatusInternalServerError)

				return
			}

		}
	default:
		{
			log.Printf("Warning: request: %s metod: %s not implement", proxyURLReq, req.Method)

			resp.WriteHeader(http.StatusNotImplemented)

			return
		}
	}

	proxyRespBody, err = ioutil.ReadAll(proxyResp.Body)
	if err != nil {
		log.Printf("Error: request: %s read resp boady error: %s", proxyURLReq, err)
		resp.WriteHeader(http.StatusInternalServerError)

		return
	}

	if encryptMode {
		proxyRespBody, err = easyaes.EncryptAesCBCStaticIV([]byte(key), iv, proxyRespBody)
		if err != nil {
			log.Printf("Error: request: %s responce encrypt error: %s", proxyURLReq, err)
			resp.WriteHeader(http.StatusInternalServerError)

			return
		}
	}

	resp.WriteHeader(http.StatusOK)
	_, _ = resp.Write(proxyRespBody)

	return
}
