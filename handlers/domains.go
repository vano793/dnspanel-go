package handlers

import (
    "encoding/json"
    "net/http"
    "strconv"

    "dns-manager/models"
    "dns-manager/services"

    "github.com/gorilla/mux"
    "github.com/gorilla/sessions"
    "github.com/spf13/viper"
)

func CreateDomainHandler(db *models.DB, store *sessions.CookieStore) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        
        session, _ := store.Get(r, "session")
        userID, ok := session.Values["user_id"].(int64)
        if !ok {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Не авторизован",
            })
            return
        }
        userRole, _ := session.Values["role"].(string)

        var data struct {
            Name     string `json:"name"`
            IP       string `json:"ip"`        // IP для A-записи
            SOAEmail string `json:"soa_email"` // Email для SOA
        }

        if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Ошибка чтения данных: " + err.Error(),
            })
            return
        }

        // Валидация домена
        if !services.ValidateDomain(data.Name) {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Некорректное имя домена",
            })
            return
        }

        // Валидация email
        if data.SOAEmail != "" && !services.ValidateEmail(data.SOAEmail) {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Некорректный email",
            })
            return
        }

        // Проверка существования домена
        exists, err := models.DomainExists(db, data.Name)
        if err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Ошибка проверки домена: " + err.Error(),
            })
            return
        }
        
        if exists {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Домен уже существует",
            })
            return
        }

        // Получаем настройки SOA из конфига
        soaRefresh := viper.GetInt("dns.soa.refresh")
        if soaRefresh == 0 {
            soaRefresh = 7200
        }
        soaRetry := viper.GetInt("dns.soa.retry")
        if soaRetry == 0 {
            soaRetry = 3600
        }
        soaExpire := viper.GetInt("dns.soa.expire")
        if soaExpire == 0 {
            soaExpire = 1209600
        }
        soaMinimum := viper.GetInt("dns.soa.minimum")
        if soaMinimum == 0 {
            soaMinimum = 3600
        }

        // Создаём запись домена в БД
        opts := &models.DomainCreateOptions{
            Name:         data.Name,
            UserID:       userID,
            SOAEmail:     data.SOAEmail,
            SOAPrimaryNS: "", // не используется
            SOARefresh:   soaRefresh,
            SOARetry:     soaRetry,
            SOAExpire:    soaExpire,
            SOAMinimum:   soaMinimum,
        }

        domainID, err := models.CreateDomain(db, opts)
        if err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Ошибка создания домена: " + err.Error(),
            })
            return
        }

        // Создаём SOA запись
        soaEmail := data.SOAEmail
        if soaEmail == "" {
            soaEmail = "admin." + data.Name
        }

        err = models.CreateRecord(db, &models.Record{
            DomainID: domainID,
            Type:     "SOA",
            Name:     "@",
            Content:  soaEmail,
            TTL:      viper.GetInt("default_ttl"),
        })
        if err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Ошибка создания SOA записи: " + err.Error(),
            })
            return
        }

        // Создаём NS записи из списка ns_servers (всегда, необходимо для делегирования)
        nsServers := viper.GetStringSlice("dns.ns_servers")
        if len(nsServers) == 0 {
            // Если список пуст, создаём одну NS запись с ns1.домен (для обратной совместимости)
            nsServers = []string{"ns1." + data.Name}
        }

        for _, ns := range nsServers {
            err = models.CreateRecord(db, &models.Record{
                DomainID: domainID,
                Type:     "NS",
                Name:     "@",
                Content:  ns,
                TTL:      viper.GetInt("default_ttl"),
            })
            if err != nil {
                json.NewEncoder(w).Encode(map[string]interface{}{
                    "success": false,
                    "message": "Ошибка создания NS записи: " + err.Error(),
                })
                return
            }
        }

        // Создаём A запись, если IP указан и разрешено
        allowA := viper.GetBool("security.allow_users_create_a")
        if (userRole == "admin" || allowA) && data.IP != "" {
            if !services.ValidateIP(data.IP) {
                json.NewEncoder(w).Encode(map[string]interface{}{
                    "success": false,
                    "message": "Некорректный IP адрес",
                })
                return
            }
            err = models.CreateRecord(db, &models.Record{
                DomainID: domainID,
                Type:     "A",
                Name:     "@",
                Content:  data.IP,
                TTL:      viper.GetInt("default_ttl"),
            })
            if err != nil {
                json.NewEncoder(w).Encode(map[string]interface{}{
                    "success": false,
                    "message": "Ошибка создания A записи: " + err.Error(),
                })
                return
            }
        }

        // Логирование
        username := session.Values["username"].(string)
        services.LogUserAction(db, userID, username, "create_domain", 
            "Создан домен: "+data.Name, r.RemoteAddr)

        // Генерация зоны
        services.GenerateZone(db, domainID)

        json.NewEncoder(w).Encode(map[string]interface{}{
            "success":   true,
            "domain_id": domainID,
            "message":   "Домен успешно создан",
        })
    }
}

func GetUserDomainsHandler(db *models.DB, store *sessions.CookieStore) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        
        session, _ := store.Get(r, "session")
        userID, ok := session.Values["user_id"].(int64)
        if !ok {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Не авторизован",
            })
            return
        }

        userRole := session.Values["role"].(string)
        
        var domains []models.Domain
        var err error
        
        if userRole == "admin" {
            domains, err = models.GetAllDomains(db)
        } else {
            domains, err = models.GetDomainsByUserID(db, userID)
        }
        
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        json.NewEncoder(w).Encode(domains)
    }
}

func DeleteDomainHandler(db *models.DB, store *sessions.CookieStore) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        
        session, _ := store.Get(r, "session")
        userID := session.Values["user_id"].(int64)
        userRole := session.Values["role"].(string)

        vars := mux.Vars(r)
        id, err := strconv.ParseInt(vars["id"], 10, 64)
        if err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Некорректный ID домена",
            })
            return
        }

        ok, err := models.CanAccessDomain(db, userID, userRole, id)
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

        domain, err := models.GetDomainByID(db, id)
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

        services.DeleteZoneFile(domain.Name)

        if err := models.DeleteDomain(db, id); err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Ошибка удаления домена: " + err.Error(),
            })
            return
        }

        // Логирование удаления домена
        username := session.Values["username"].(string)
        services.LogUserAction(db, userID, username, "delete_domain", 
            "Удален домен: "+domain.Name, r.RemoteAddr)

        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": true,
            "message": "Домен успешно удален",
        })
    }
}