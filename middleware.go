package access

import (
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v3"
)

// ContextKey — ключ, под которым AccessContext кладётся в Locals запроса.
const ContextKey = "accessContext"

// Middleware проверяет JWT и права доступа к ресурсу для Fiber.
type Middleware struct {
	access *Access
}

func NewMiddleware(access *Access) *Middleware {
	return &Middleware{access: access}
}

func tokenFromHeader(c fiber.Ctx) (string, int) {
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return "", http.StatusUnauthorized
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", http.StatusUnauthorized
	}

	return parts[1], 0
}

// Permission возвращает middleware проверки прав.
//
// public=true делает маршрут публичным: запрос без токена (или с невалидным токеном)
// пропускается дальше, но при валидном токене AccessContext всё равно прикрепляется.
// public=false (по умолчанию) требует валидный токен и достаточные права.
func (m *Middleware) Permission(resource string, action PermissionAction, public ...bool) fiber.Handler {
	isPublic := len(public) > 0 && public[0]

	return func(c fiber.Ctx) error {
		token, status := tokenFromHeader(c)
		if status != 0 {
			if isPublic {
				return c.Next()
			}
			return c.SendStatus(status)
		}

		if m.access == nil {
			if isPublic {
				return c.Next()
			}
			return c.SendStatus(http.StatusUnauthorized)
		}

		accessContext, status := m.access.Check(token, resource, action)
		if status == http.StatusOK {
			c.Locals(ContextKey, accessContext)
			return c.Next()
		}

		if isPublic {
			return c.Next()
		}

		if status == http.StatusUnauthorized {
			return c.Status(status).JSON(fiber.Map{
				"error": "не верный токен",
			})
		}

		return c.Status(http.StatusForbidden).JSON(fiber.Map{
			"error": "недостаточно прав",
		})
	}
}
