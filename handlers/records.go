package handlers

import (
    "encoding/json"
    "net/http"
    "strconv"
    "strings"

    "dns-manager/models"
    "dns-manager/services"

    "github.com/gorilla/mux"
    "github.com/gorilla/sessions"
    "github.com/spf13/viper"
)

func GetRecordsHandler(db *models.DB, store *sessions.CookieStore) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        
        session, _ := store.Get(r, "session")
        userID := session.Values["user_id"].(int64)
        userRole := session.Values["role"].(string)

        vars := mux.Vars(r)
        domainID, err := strconv.ParseInt(vars["id"], 10, 64)
        if err != nil {
            http.Error(w, "Invalid domain ID", http.StatusBadRequest)
            return
        }

        ok, err := models.CanAccessDomain(db, userID, userRole, domainID)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        if !ok {
            http.Error(w, "Forbidden", http.StatusForbidden)
            return
        }

        records, err := models.GetRecordsByDomainID(db, domainID)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        json.NewEncoder(w).Encode(records)
    }
}

func CreateRecordHandler(db *models.DB, store *sessions.CookieStore) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        
        session, _ := store.Get(r, "session")
        userID := session.Values["user_id"].(int64)
        userRole, ok := session.Values["role"].(string)
        if !ok {
            userRole = "user"
        }
        username := session.Values["username"].(string)

        var record models.Record
        if err := json.NewDecoder(r.Body).Decode(&record); err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Ошибка чтения данных: " + err.Error(),
            })
            return
        }

        // Проверка доступа к домену
        ok, err := models.CanAccessDomain(db, userID, userRole, record.DomainID)
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

        // Получаем настройки безопасности
        allowNS := viper.GetBool("security.allow_users_create_ns")
        allowA := viper.GetBool("security.allow_users_create_a")

        // Если пользователь не admin, применяем ограничения
        if userRole != "admin" {
            if record.Type == "NS" && !allowNS {
                json.NewEncoder(w).Encode(map[string]interface{}{
                    "success": false,
                    "message": "Создание NS записей запрещено для пользователей",
                })
                return
            }
            if record.Type == "A" && !allowA {
                json.NewEncoder(w).Encode(map[string]interface{}{
                    "success": false,
                    "message": "Создание A записей запрещено для пользователей",
                })
                return
            }
        }

        domain, err := models.GetDomainByID(db, record.DomainID)
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

        nameCheck := services.ValidateRecordName(record.Name, domain.Name)
        if !nameCheck.Valid {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Ошибка в имени: " + nameCheck.Message,
            })
            return
        }
        if nameCheck.Corrected != record.Name {
            record.Name = nameCheck.Corrected
        }

        contentCheck := services.ValidateRecordContent(record.Type, record.Content, domain.Name)
        if !contentCheck.Valid {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Ошибка в значении: " + contentCheck.Message,
            })
            return
        }
        if contentCheck.Corrected != record.Content {
            record.Content = contentCheck.Corrected
        }

        if err := models.CreateRecord(db, &record); err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Ошибка сохранения записи: " + err.Error(),
            })
            return
        }

        // Логирование создания записи
        details := "Создана запись: " + record.Type + " " + record.Name + " → " + record.Content
        services.LogUserAction(db, userID, username, "create_record", details, r.RemoteAddr)

        models.IncrementDomainSerial(db, record.DomainID)
        services.GenerateZone(db, record.DomainID)

        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": true,
            "id":      record.ID,
            "message": "Запись успешно создана",
        })
    }
}

func UpdateRecordHandler(db *models.DB, store *sessions.CookieStore) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        
        session, _ := store.Get(r, "session")
        userID := session.Values["user_id"].(int64)
        userRole, ok := session.Values["role"].(string)
        if !ok {
            userRole = "user"
        }
        username := session.Values["username"].(string)

        vars := mux.Vars(r)
        id, err := strconv.ParseInt(vars["id"], 10, 64)
        if err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Некорректный ID записи",
            })
            return
        }

        var record models.Record
        if err := json.NewDecoder(r.Body).Decode(&record); err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Ошибка чтения данных: " + err.Error(),
            })
            return
        }
        record.ID = id

        existing, err := models.GetRecordByID(db, id)
        if err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Ошибка получения записи: " + err.Error(),
            })
            return
        }
        
        if existing == nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Запись не найдена",
            })
            return
        }

        ok, err = models.CanAccessDomain(db, userID, userRole, existing.DomainID)
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

        // Если пользователь не admin, проверяем разрешённые типы
        if userRole != "admin" {
            allowNS := viper.GetBool("security.allow_users_create_ns")
            allowA := viper.GetBool("security.allow_users_create_a")

            if record.Type == "NS" && !allowNS {
                json.NewEncoder(w).Encode(map[string]interface{}{
                    "success": false,
                    "message": "Редактирование NS записей запрещено для пользователей",
                })
                return
            }
            if record.Type == "A" && !allowA {
                json.NewEncoder(w).Encode(map[string]interface{}{
                    "success": false,
                    "message": "Редактирование A записей запрещено для пользователей",
                })
                return
            }
        }

        domain, err := models.GetDomainByID(db, existing.DomainID)
        if err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Ошибка получения домена: " + err.Error(),
            })
            return
        }

        nameCheck := services.ValidateRecordName(record.Name, domain.Name)
        if !nameCheck.Valid {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Ошибка в имени: " + nameCheck.Message,
            })
            return
        }

        contentCheck := services.ValidateRecordContent(record.Type, record.Content, domain.Name)
        if !contentCheck.Valid {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Ошибка в значении: " + contentCheck.Message,
            })
            return
        }

        // Сохраняем старые значения для лога
        oldContent := existing.Content
        oldName := existing.Name
        oldType := existing.Type
        oldPriority := existing.Priority
        oldTTL := existing.TTL

        if err := models.UpdateRecord(db, &record); err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Ошибка обновления записи: " + err.Error(),
            })
            return
        }

        // Логирование изменения записи
        details := "Изменена запись (ID: " + strconv.FormatInt(id, 10) + ") "
        if oldType != record.Type {
            details += "тип: " + oldType + " → " + record.Type + ", "
        }
        if oldName != record.Name {
            details += "имя: " + oldName + " → " + record.Name + ", "
        }
        if oldContent != record.Content {
            details += "значение: " + oldContent + " → " + record.Content + ", "
        }
        if oldPriority != record.Priority {
            details += "приоритет: " + strconv.Itoa(oldPriority) + " → " + strconv.Itoa(record.Priority) + ", "
        }
        if oldTTL != record.TTL {
            details += "TTL: " + strconv.Itoa(oldTTL) + " → " + strconv.Itoa(record.TTL) + ", "
        }
        details = strings.TrimSuffix(details, ", ")
        services.LogUserAction(db, userID, username, "update_record", details, r.RemoteAddr)

        models.IncrementDomainSerial(db, existing.DomainID)
        services.GenerateZone(db, existing.DomainID)

        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": true,
            "message": "Запись успешно обновлена",
        })
    }
}

func DeleteRecordHandler(db *models.DB, store *sessions.CookieStore) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        
        session, _ := store.Get(r, "session")
        userID := session.Values["user_id"].(int64)
        userRole, ok := session.Values["role"].(string)
        if !ok {
            userRole = "user"
        }
        username := session.Values["username"].(string)

        vars := mux.Vars(r)
        id, err := strconv.ParseInt(vars["id"], 10, 64)
        if err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Некорректный ID записи",
            })
            return
        }

        record, err := models.GetRecordByID(db, id)
        if err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Ошибка получения записи: " + err.Error(),
            })
            return
        }
        
        if record == nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Запись не найдена",
            })
            return
        }

        ok, err = models.CanAccessDomain(db, userID, userRole, record.DomainID)
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

        // Если пользователь не admin, проверяем разрешённые типы
        if userRole != "admin" {
            allowNS := viper.GetBool("security.allow_users_create_ns")
            allowA := viper.GetBool("security.allow_users_create_a")

            if record.Type == "NS" && !allowNS {
                json.NewEncoder(w).Encode(map[string]interface{}{
                    "success": false,
                    "message": "Удаление NS записей запрещено для пользователей",
                })
                return
            }
            if record.Type == "A" && !allowA {
                json.NewEncoder(w).Encode(map[string]interface{}{
                    "success": false,
                    "message": "Удаление A записей запрещено для пользователей",
                })
                return
            }
        }

        if record.Type == "NS" {
            nsCount, err := models.CountNSRecords(db, record.DomainID)
            if err != nil {
                json.NewEncoder(w).Encode(map[string]interface{}{
                    "success": false,
                    "message": "Ошибка проверки NS записей: " + err.Error(),
                })
                return
            }
            
            if nsCount <= 1 {
                json.NewEncoder(w).Encode(map[string]interface{}{
                    "success": false,
                    "message": "Нельзя удалить последний NS сервер",
                })
                return
            }
        }

        // Сохраняем информацию для лога
        recordType := record.Type
        recordName := record.Name
        recordContent := record.Content

        if err := models.DeleteRecord(db, id); err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Ошибка удаления записи: " + err.Error(),
            })
            return
        }

        // Логирование удаления записи
        details := "Удалена запись: " + recordType + " " + recordName + " → " + recordContent
        services.LogUserAction(db, userID, username, "delete_record", details, r.RemoteAddr)

        models.IncrementDomainSerial(db, record.DomainID)
        services.GenerateZone(db, record.DomainID)

        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": true,
            "message": "Запись успешно удалена",
        })
    }
}