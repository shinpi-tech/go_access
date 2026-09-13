# go_access

Общая библиотека проверки прав доступа (policy + JWT) и Fiber-мидлварь для микросервисов SHINPI.

## Установка

```
go get github.com/shinpi-tech/go_access
```

## Использование

```go
accessService, err := access.InitAccess(
    cfg.API.AuthURL, "catalog", cfg.API.ClientID, cfg.API.ClientSecret, 1,
)
if err != nil {
    log.Fatal(err)
}

mw := access.NewMiddleware(accessService)

// приватная проверка прав на весь раздел
api := app.Group("/catalog", mw.Permission("*", access.PermissionActionAll))

// публичный маршрут: без токена пропускается, с токеном — прикрепит контекст
api.Get("/price", mw.Permission("price", access.PermissionActionRead, true), handler)
```

`Permission(resource, action, public ...bool)`:

- `public=false` (по умолчанию) — требует валидный токен и достаточные права (401/403);
- `public=true` — запрос без токена (или с невалидным) пропускается, при валидном токене `AccessContext` кладётся в `c.Locals("accessContext")`.

`Access` периодически обновляет политику из auth-сервиса.
