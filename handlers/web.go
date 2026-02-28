package handlers

import (
    "html/template"
    "net/http"

    "dns-manager/models"

    "github.com/gorilla/sessions"
    "github.com/spf13/viper"
)

func IndexHandler(db *models.DB, store *sessions.CookieStore) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        session, _ := store.Get(r, "session")
        isLoggedIn := session.Values["authenticated"] == true
        username, _ := session.Values["username"].(string)
        userRole, _ := session.Values["role"].(string)
        userID, _ := session.Values["user_id"].(int64)

        // Парсим ВСЕ необходимые шаблоны
        tmpl, err := template.ParseFiles(
            "static/templates/index.html",
            "static/templates/partials/header.html",
            "static/templates/partials/domain_list.html",
        )
        if err != nil {
            http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
            return
        }

        var domains []models.Domain
        if isLoggedIn {
            if userRole == "admin" {
                domains, err = models.GetAllDomains(db)
            } else {
                domains, err = models.GetDomainsByUserID(db, userID)
            }
            if err != nil {
                http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
                return
            }
        }

        // Передаём в шаблон настройки
        data := struct {
            IsLoggedIn         bool
            Username           string
            UserRole           string
            Domains            []models.Domain
            ServerIP           string
            AllowUsersCreateNS bool
            AllowUsersCreateA  bool
            NSServers          []string
        }{
            IsLoggedIn:         isLoggedIn,
            Username:           username,
            UserRole:           userRole,
            Domains:            domains,
            ServerIP:           viper.GetString("server_ip"),
            AllowUsersCreateNS: viper.GetBool("security.allow_users_create_ns"),
            AllowUsersCreateA:  viper.GetBool("security.allow_users_create_a"),
            NSServers:          viper.GetStringSlice("dns.ns_servers"),
        }

        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        if err := tmpl.Execute(w, data); err != nil {
            http.Error(w, "Template execution error: "+err.Error(), http.StatusInternalServerError)
        }
    }
}

func LoginPageHandler(w http.ResponseWriter, r *http.Request) {
    tmpl, err := template.ParseFiles("static/templates/login.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    tmpl.Execute(w, nil)
}