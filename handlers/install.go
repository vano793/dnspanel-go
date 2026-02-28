package handlers

import (
    "encoding/json"
    "html/template"
    "net/http"
    "os"
    "time"

    "dns-manager/models"
    "dns-manager/services"

    "github.com/gorilla/sessions"
    "github.com/spf13/viper"
    "golang.org/x/crypto/bcrypt"
)

func InstallHandler(db *models.DB, store *sessions.CookieStore) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Проверяем, не установлена ли уже система
        if _, err := os.Stat("installed.lock"); err == nil {
            http.Redirect(w, r, "/", http.StatusSeeOther)
            return
        }

        if r.Method == "GET" {
            tmpl, err := template.ParseFiles("static/templates/install.html")
            if err != nil {
                http.Error(w, err.Error(), http.StatusInternalServerError)
                return
            }

            detectedIP := viper.GetString("server_ip")
            if detectedIP == "127.0.0.1" {
                detectedIP = services.GetServerIP()
            }

            data := struct {
                DetectedIP string
                Error      string
            }{
                DetectedIP: detectedIP,
                Error:      "",
            }

            tmpl.Execute(w, data)
            return
        }

        if r.Method == "POST" {
            var data struct {
                Username        string `json:"username"`
                Email           string `json:"email"`
                Password        string `json:"password"`
                ConfirmPassword string `json:"confirm_password"`
                ServerIP        string `json:"server_ip"`
            }

            if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
                json.NewEncoder(w).Encode(map[string]interface{}{
                    "success": false,
                    "message": "Ошибка чтения данных: " + err.Error(),
                })
                return
            }

            // Валидация
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

            if data.Password != data.ConfirmPassword {
                json.NewEncoder(w).Encode(map[string]interface{}{
                    "success": false,
                    "message": "Пароли не совпадают",
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

            if !services.ValidateIP(data.ServerIP) {
                json.NewEncoder(w).Encode(map[string]interface{}{
                    "success": false,
                    "message": "Некорректный IP адрес",
                })
                return
            }

            // Создаем пользователя-администратора
            hashedPassword, err := bcrypt.GenerateFromPassword([]byte(data.Password), bcrypt.DefaultCost)
            if err != nil {
                http.Error(w, err.Error(), http.StatusInternalServerError)
                return
            }

            user := models.User{
                Username:     data.Username,
                Email:        data.Email,
                PasswordHash: string(hashedPassword),
                Role:         "admin",
                Active:       true,
            }

            if err := models.CreateUser(db, &user); err != nil {
                json.NewEncoder(w).Encode(map[string]interface{}{
                    "success": false,
                    "message": "Ошибка при создании пользователя: " + err.Error(),
                })
                return
            }

            // Обновляем конфиг с IP
            viper.Set("server_ip", data.ServerIP)
            if err := viper.WriteConfig(); err != nil {
                // Если не получается записать, пробуем создать новый
                viper.SafeWriteConfig()
            }

            // Создаем lock файл
            if err := os.WriteFile("installed.lock", []byte(time.Now().String()), 0644); err != nil {
                json.NewEncoder(w).Encode(map[string]interface{}{
                    "success": false,
                    "message": "Ошибка при создании lock файла",
                })
                return
            }

            // Автоматический логин
            session, _ := store.Get(r, "session")
            session.Values["authenticated"] = true
            session.Values["user_id"] = user.ID
            session.Values["username"] = user.Username
            session.Values["role"] = user.Role
            session.Save(r, w)

            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": true,
                "message": "Установка завершена успешно",
            })
        }
    }
}