package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

const (
	clientCertURL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
)

// VerifyIDToken ...
func VerifyIDToken(idToken string, projectID string) (string, error) {
	keys, err := fetchPublicKeys()

	if err != nil {
		return "", err
	}

	parsedToken, err := jwt.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		kid := token.Header["kid"]

		rsaPublicKey := convertKey(string(*keys[kid.(string)]))

		return rsaPublicKey, nil
	})

	if err != nil {
		return "", err
	}

	if parsedToken == nil {
		return "", errors.New("Nil parsed token")
	}

	errMessage := ""

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if ok && parsedToken.Valid {
		if claims["aud"].(string) != projectID {
			errMessage = "Firebase Auth ID token has incorrect 'aud' claim: " + claims["aud"].(string)
		} else if claims["iss"].(string) != "https://securetoken.google.com/"+projectID {
			errMessage = "Firebase Auth ID token has incorrect 'iss' claim"
		} else if claims["sub"].(string) == "" || len(claims["sub"].(string)) > 128 {
			errMessage = "Firebase Auth ID token has invalid 'sub' claim"
		}
	} else {
		fmt.Println(err)
	}

	if errMessage != "" {
		return "", errors.New(errMessage)
	}

	return claims["sub"].(string), nil
}

func fetchPublicKeys() (map[string]*json.RawMessage, error) {
	resp, err := http.Get(clientCertURL)

	if err != nil {
		return nil, err
	}

	var objmap map[string]*json.RawMessage
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&objmap)

	return objmap, err
}

func convertKey(key string) interface{} {
	certPEM := key
	certPEM = strings.Replace(certPEM, "\\n", "\n", -1)
	certPEM = strings.Replace(certPEM, "\"", "", -1)
	block, _ := pem.Decode([]byte(certPEM))
	cert, _ := x509.ParseCertificate(block.Bytes)
	rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)

	return rsaPublicKey
}
