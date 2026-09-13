package access

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// FetchPublicKey загружает RSA public key (PEM, PKIX) по URL.
func FetchPublicKey(url string) (*rsa.PublicKey, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("ошибка выполнения запроса: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("неудачный ответ сервера: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения ответа: %w", err)
	}

	block, _ := pem.Decode(body)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("неверный формат публичного ключа")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга публичного ключа: %w", err)
	}

	rsaPublicKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("публичный ключ не является RSA ключом")
	}

	return rsaPublicKey, nil
}
