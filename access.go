package access

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Access struct {
	authURL             string
	serviceName         string
	clientId            string
	clientSecret        string
	permissionUpdateLag int
	clientAccess        *clientAccess
	policy              *Policy
	publicKey           *rsa.PublicKey
	mu                  sync.RWMutex
}

func (a *Access) getPublicKey() error {
	pk, err := a.clientAccess.GetPublicKey()
	if err != nil {
		return fmt.Errorf("не удалось получить публичный ключ: %w", err)
	}

	a.publicKey = pk
	return nil
}

func (a *Access) getPolicy() error {
	policy, err := a.clientAccess.GetPolicy(a.serviceName)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.policy = policy
	a.mu.Unlock()
	return nil
}

// ValidateToken проверяет подпись JWT и возвращает его payload.
func (a *Access) ValidateToken(token string) (map[string]any, error) {
	if a.publicKey == nil {
		return nil, errors.New("публичный ключ не загружен")
	}

	parsed, err := jwt.Parse(token, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("неверный метод подписи: %v", token.Header["alg"])
		}
		return a.publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("ошибка валидации токена: %w", err)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok || !parsed.Valid {
		return nil, errors.New("токен недействителен")
	}

	payloadAny, ok := claims["payload"]
	if !ok {
		return nil, errors.New("токен недействителен")
	}

	payload, ok := payloadAny.(map[string]any)
	if !ok {
		return nil, errors.New("токен недействителен")
	}

	return payload, nil
}

// Check проверяет права на ресурс и, при успехе, возвращает контекст доступа.
// Второе значение — HTTP-статус: 200 при успехе, 401/403 при отказе.
func (a *Access) Check(token, resource string, action PermissionAction) (context *AccessContext, status int) {
	payload, err := a.ValidateToken(token)
	if err != nil {
		return nil, http.StatusUnauthorized
	}

	payloadUser, ok := payload["user"].(string)
	if !ok {
		return nil, http.StatusUnauthorized
	}

	role, ok := payload["role"].(string)
	if !ok || role == "" {
		return nil, http.StatusUnauthorized
	}

	a.mu.RLock()
	if a.policy == nil {
		a.mu.RUnlock()
		if err := a.getPolicy(); err != nil {
			return nil, http.StatusForbidden
		}
		a.mu.RLock()
	}
	defer a.mu.RUnlock()

	if a.policy == nil || a.policy.Permissions == nil {
		return nil, http.StatusForbidden
	}

	permissionsByRole, ok := a.policy.Permissions[role]
	if !ok {
		return nil, http.StatusForbidden
	}

	permissions, ok := permissionsByRole[resource]
	if !ok {
		permissions, ok = permissionsByRole["*"]
	}

	hasAllowMatch := false
	for _, permission := range permissions {
		if permission.Action == action || permission.Action == PermissionActionAll {
			if permission.Effect == PermissionEffectDeny {
				return nil, http.StatusForbidden
			}
			if permission.Effect == PermissionEffectAllow {
				hasAllowMatch = true
			}
		}
	}

	if !hasAllowMatch {
		return nil, http.StatusForbidden
	}

	group, _ := payload["group"].(string)

	var conditions []Condition
	if group != "" {
		if conditionsByGroup, ok := a.policy.Conditions[group]; ok {
			if conds, ok := conditionsByGroup[resource]; ok {
				conditions = conds
			}
		}
	}

	context = &AccessContext{
		User:      payloadUser,
		Role:      role,
		Group:     group,
		Condition: a.conditionParser(conditions, action),
	}

	return context, http.StatusOK
}

func (a *Access) conditionParser(conditions []Condition, action PermissionAction) AccessContextCondition {
	show := make([]string, 0)
	hide := make([]string, 0)
	filter := make(map[string][]string)

	for _, condition := range conditions {
		if condition.Action != action && condition.Action != PermissionActionAll {
			continue
		}

		switch condition.Operation {
		case "show":
			show = append(show, condition.Field)
		case "hide":
			hide = append(hide, condition.Field)
		case "filter":
			filter[condition.Field] = append(filter[condition.Field], condition.Value...)
		}
	}

	return AccessContextCondition{
		Show:   show,
		Hide:   hide,
		Filter: filter,
	}
}

func (a *Access) GetPublicKey() *rsa.PublicKey {
	return a.publicKey
}

// InitAccess создаёт клиент проверки прав и загружает публичный ключ и политику сервиса.
func InitAccess(
	authURL string,
	serviceName string,
	clientId, clientSecret string,
	permissionUpdateLag int,
) (*Access, error) {
	if clientId == "" {
		return nil, fmt.Errorf("clientId is empty")
	}
	if clientSecret == "" {
		return nil, fmt.Errorf("clientSecret is empty")
	}
	if permissionUpdateLag <= 0 {
		permissionUpdateLag = 1
	}

	clientAccess := newClientAccess(authURL, clientId, clientSecret)

	access := &Access{
		authURL:             authURL,
		serviceName:         serviceName,
		clientId:            clientId,
		clientSecret:        clientSecret,
		permissionUpdateLag: permissionUpdateLag,
		clientAccess:        clientAccess,
	}

	if err := access.getPublicKey(); err != nil {
		return nil, err
	}

	if err := access.getPolicy(); err != nil {
		return nil, fmt.Errorf("не удалось получить первоначальную политику: %w", err)
	}

	go func() {
		ticker := time.NewTicker(time.Duration(access.permissionUpdateLag) * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			_ = access.getPolicy()
		}
	}()

	return access, nil
}
