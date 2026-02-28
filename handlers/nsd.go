package handlers

import (
    "encoding/json"
    "net/http"
    "strconv"

    "dns-manager/models"
    "dns-manager/services"

    "github.com/gorilla/mux"
    "github.com/gorilla/sessions"
)

func SyncNSDHandler(db *models.DB, store *sessions.CookieStore) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        
        session, _ := store.Get(r, "session")
        userID := session.Values["user_id"].(int64)
        userRole := session.Values["role"].(string)

        vars := mux.Vars(r)
        domainID, err := strconv.ParseInt(vars["domain_id"], 10, 64)
        if err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Некорректный ID домена",
            })
            return
        }

        // Проверка доступа к домену
        ok, err := models.CanAccessDomain(db, userID, userRole, domainID)
        if err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Ошибка проверки доступа: " + err.Error(),
            })
            return
        }
        if !ok {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Доступ запрещён",
            })
            return
        }

        domain, err := models.GetDomainByID(db, domainID)
        if err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Ошибка получения домена: " + err.Error(),
            })
            return
        }
        
        if domain == nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Домен не найден",
            })
            return
        }

        if err := services.GenerateZone(db, domainID); err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Ошибка генерации зоны: " + err.Error(),
            })
            return
        }

        reloaded := services.ReloadNSD()

        message := "Зона создана"
        if reloaded {
            message += " и NSD перезагружен"
        } else {
            message += ", но NSD не перезагружен (возможно нужны права sudo)"
        }

        json.NewEncoder(w).Encode(map[string]interface{}{
            "success":  true,
            "reloaded": reloaded,
            "message":  message,
        })
    }
}

func NSDStatusHandler() http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        
        running := services.CheckNSDStatus()
        perms := services.CheckPermissions()

        json.NewEncoder(w).Encode(map[string]interface{}{
            "success":     true,
            "running":     running,
            "permissions": perms,
        })
    }
}