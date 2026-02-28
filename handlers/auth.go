package handlers

import (
    "encoding/json"
    "log"
    "net/http"
    "time"

    "dns-manager/models"

    "github.com/gorilla/sessions"
    "golang.org/x/crypto/bcrypt"
)

func LoginHandler(db *models.DB, store *sessions.CookieStore) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")

        var creds struct {
            Username string `json:"username"`
            Password string `json:"password"`
        }

        if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Ошибка чтения данных",
            })
            return
        }

        user, err := models.GetUserByUsername(db, creds.Username)
        if err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Ошибка сервера",
            })
            return
        }

        if user == nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Неверный логин или пароль",
            })
            return
        }

        if !user.Active {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Учётная запись отключена. Обратитесь к администратору.",
            })
            return
        }

        if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(creds.Password)); err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Неверный логин или пароль",
            })
            return
        }

        models.UpdateUserLastLogin(db, user.ID, r.RemoteAddr)

        session, _ := store.Get(r, "session")
        session.Values["authenticated"] = true
        session.Values["user_id"] = user.ID
        session.Values["username"] = user.Username
        session.Values["role"] = string(user.Role)

        log.Printf("Login: role set to %q (type %T)", string(user.Role), user.Role)

        if err := session.Save(r, w); err != nil {
            log.Printf("Error saving session: %v", err)
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Ошибка сохранения сессии: " + err.Error(),
            })
            return
        }

        models.CreateLoginLog(db, &models.LoginLog{
            UserID:    user.ID,
            Username:  creds.Username,
            IP:        r.RemoteAddr,
            UserAgent: r.UserAgent(),
            Success:   true,
            CreatedAt: time.Now(),
        })

        json.NewEncoder(w).Encode(map[string]interface{}{
            "success":  true,
            "message":  "Успешная авторизация",
            "username": user.Username,
            "role":     user.Role,
        })
    }
}

func LogoutHandler(store *sessions.CookieStore) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")

        session, _ := store.Get(r, "session")
        session.Values["authenticated"] = false
        delete(session.Values, "user_id")
        delete(session.Values, "username")
        delete(session.Values, "role")
        session.Save(r, w)

        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": true,
            "message": "Выход выполнен",
        })
    }
}

func ChangePasswordHandler(db *models.DB, store *sessions.CookieStore) http.HandlerFunc {
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

        var data struct {
            CurrentPassword string `json:"current_password"`
            NewPassword     string `json:"new_password"`
            ConfirmPassword string `json:"confirm_password"`
        }

        if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Ошибка чтения данных",
            })
            return
        }

        if data.NewPassword != data.ConfirmPassword {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Пароли не совпадают",
            })
            return
        }

        if len(data.NewPassword) < 6 {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Пароль должен быть не менее 6 символов",
            })
            return
        }

        user, err := models.GetUserByID(db, userID)
        if err != nil || user == nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Пользователь не найден",
            })
            return
        }

        if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(data.CurrentPassword)); err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Неверный текущий пароль",
            })
            return
        }

        hashedPassword, err := bcrypt.GenerateFromPassword([]byte(data.NewPassword), bcrypt.DefaultCost)
        if err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Ошибка хеширования пароля",
            })
            return
        }

        if err := models.UpdateUserPassword(db, userID, string(hashedPassword)); err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": "Ошибка обновления пароля: " + err.Error(),
            })
            return
        }

        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": true,
            "message": "Пароль успешно изменен",
        })
    }
}