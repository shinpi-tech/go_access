package access

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
)

type clientAccess struct {
	client       *resty.Client
	authClient   *resty.Client
	clientId     string
	clientSecret string
	accessToken  string
	tokenMutex   sync.Mutex
}

func (r *clientAccess) GetPublicKey() (*rsa.PublicKey, error) {
	resp, err := r.authClient.R().Get("/api/auth/key/access")
	if err != nil {
		return nil, fmt.Errorf("ошибка выполнения запроса: %w", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("неудачный ответ сервера: %s", resp.Status())
	}

	block, _ := pem.Decode(resp.Body())
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

func (r *clientAccess) GetPolicy(service string) (*Policy, error) {
	var policy Policy
	res, err := r.client.R().
		SetResult(&policy).
		Get("/api/policy/" + service)

	if err != nil {
		return nil, fmt.Errorf("ошибка выполнения запроса: %w", err)
	}
	if res.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("неудачный ответ сервера: %s", res.Status())
	}
	return &policy, nil
}

func (r *clientAccess) authenticate() error {
	var token struct {
		AccessToken string `json:"accessToken"`
	}

	resp, err := r.authClient.R().
		SetQueryParam("clientId", r.clientId).
		SetBody(map[string]string{
			"clientSecret": r.clientSecret,
		}).
		SetResult(&token).
		Post("/api/auth/client")

	if err != nil {
		return fmt.Errorf("не удалось получить токен: %w", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return fmt.Errorf("не удалось получить токен: %s", resp.String())
	}

	r.accessToken = token.AccessToken
	return nil
}

func newClientAccess(authURL, clientId, clientSecret string) *clientAccess {
	authClient := resty.New().
		SetBaseURL(authURL).
		SetTimeout(10 * time.Second).
		SetRetryCount(3).
		SetRetryWaitTime(1 * time.Minute).
		SetRetryMaxWaitTime(5 * time.Minute)

	client := resty.New().
		SetBaseURL(authURL).
		SetTimeout(10 * time.Second).
		SetRetryCount(5).
		SetRetryWaitTime(1 * time.Minute).
		SetRetryMaxWaitTime(5 * time.Minute)

	accessClient := &clientAccess{
		client:       client,
		authClient:   authClient,
		clientId:     clientId,
		clientSecret: clientSecret,
	}

	client.OnBeforeRequest(func(c *resty.Client, r *resty.Request) error {
		if accessClient.accessToken == "" {
			accessClient.tokenMutex.Lock()
			defer accessClient.tokenMutex.Unlock()

			if accessClient.accessToken == "" {
				if err := accessClient.authenticate(); err != nil {
					return err
				}
			}
		}

		r.SetHeader("Authorization", "Bearer "+accessClient.accessToken)
		return nil
	})

	client.OnAfterResponse(func(c *resty.Client, r *resty.Response) error {
		if r.StatusCode() == http.StatusUnauthorized {
			accessClient.tokenMutex.Lock()
			defer accessClient.tokenMutex.Unlock()

			if err := accessClient.authenticate(); err != nil {
				return err
			}

			r.Request.SetHeader("Authorization", "Bearer "+accessClient.accessToken)
			_, err := r.Request.Execute(r.Request.Method, r.Request.URL)
			if err != nil {
				return err
			}
		}
		return nil
	})

	return accessClient
}
