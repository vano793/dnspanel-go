package handlers

import (
    "encoding/json"
    "net/http"
    "strconv"

    "dns-manager/models"
    "dns-manager/services"

    "github.com/gorilla/mux"
    "github.com/gorilla/sessions"
    "golang.org/x/crypto/bcrypt"
)

func GetUsersHandler(db *models.DB, store *sessions.CookieStore) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        
        session, _ := store.Get(r, "session")
        if session.Values["role"] != "admin" {
            http.Error(w, "Forbidden", http.StatusForbidden)
            return
        }

        users, err := models.GetAllUsers(db)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        json.NewEncoder(w).Encode(users)
    }
}

func CreateUserHandler(db *models.DB, store *sessions.CookieStore) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        
        session, _ := store.Get(r, "session")
        if session.Values["role"] != "admin" {
            http.Error(w, "Forbidden", http.StatusForbidden)
            return
        }

        var data struct {
            Username string `json:"username"`
            Email    string `json:"email"`
            Password string `json:"password"`
            Role     string `json:"role"`
        }

        if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Ошибка чтения данных",
            })
            return
        }

        if len(data.Username) < 3 {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Логин должен быть не менее 3 символов",
            })
            return
        }

        if len(data.Password) < 6 {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Пароль должен быть не менее 6 символов",
            })
            return
        }

        if !services.ValidateEmail(data.Email) {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Некорректный email",
            })
            return
        }

        existing, _ := models.GetUserByUsername(db, data.Username)
        if existing != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Пользователь уже существует",
            })
            return
        }

        hashedPassword, err := bcrypt.GenerateFromPassword([]byte(data.Password), bcrypt.DefaultCost)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        user := models.User{
            Username:     data.Username,
            Email:        data.Email,
            PasswordHash: string(hashedPassword),
            Role:         models.UserRole(data.Role),
            Active:       true,
        }

        if err := models.CreateUser(db, &user); err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Ошибка создания пользователя: " + err.Error(),
            })
            return
        }

        adminID := session.Values["user_id"].(int64)
        adminName := session.Values["username"].(string)
        services.LogUserAction(db, adminID, adminName, "create_user",
            "Создан пользователь: "+data.Username, r.RemoteAddr)

        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": true,
            "message": "Пользователь успешно создан",
        })
    }
}

func UpdateUserStatusHandler(db *models.DB, store *sessions.CookieStore) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        
        session, _ := store.Get(r, "session")
        if session.Values["role"] != "admin" {
            http.Error(w, "Forbidden", http.StatusForbidden)
            return
        }

        vars := mux.Vars(r)
        userID, err := strconv.ParseInt(vars["id"], 10, 64)
        if err != nil {
            http.Error(w, "Invalid user ID", http.StatusBadRequest)
            return
        }

        // Запретить админу деактивировать самого себя
        currentUserID := session.Values["user_id"].(int64)
        if currentUserID == userID {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Нельзя изменить статус своей учётной записи",
            })
            return
        }

        var data struct {
            Active bool `json:"active"`
        }

        if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }

        if err := models.UpdateUserStatus(db, userID, data.Active); err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": err.Error(),
            })
            return
        }

        status := "активирован"
        if !data.Active {
            status = "деактивирован"
        }

        adminID := session.Values["user_id"].(int64)
        adminName := session.Values["username"].(string)
        services.LogUserAction(db, adminID, adminName, "update_user",
            "Пользователь "+strconv.FormatInt(userID, 10)+" "+status, r.RemoteAddr)

        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": true,
            "message": "Статус пользователя обновлен",
        })
    }
}

func DeleteUserHandler(db *models.DB, store *sessions.CookieStore) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        
        session, _ := store.Get(r, "session")
        if session.Values["role"] != "admin" {
            http.Error(w, "Forbidden", http.StatusForbidden)
            return
        }

        vars := mux.Vars(r)
        userID, err := strconv.ParseInt(vars["id"], 10, 64)
        if err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Некорректный ID пользователя",
            })
            return
        }

        currentUserID := session.Values["user_id"].(int64)
        if currentUserID == userID {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Нельзя удалить свою учетную запись",
            })
            return
        }

        if err := models.DeleteUser(db, userID); err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Ошибка удаления пользователя: " + err.Error(),
            })
            return
        }

        adminName := session.Values["username"].(string)
        services.LogUserAction(db, currentUserID, adminName, "delete_user",
            "Удален пользователь ID: "+strconv.FormatInt(userID, 10), r.RemoteAddr)

        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": true,
            "message": "Пользователь успешно удален",
        })
    }
}