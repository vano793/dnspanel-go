package handlers

import (
    "html/template"
    "log"
    "net/http"

    "github.com/gorilla/sessions"
)

func AdminPageHandler(page string, store *sessions.CookieStore) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        session, _ := store.Get(r, "session")

        // Проверка авторизации
        auth, ok := session.Values["authenticated"].(bool)
        if !ok || !auth {
            http.Redirect(w, r, "/", http.StatusSeeOther)
            return
        }

        usernameVal, ok := session.Values["username"]
        if !ok {
            http.Redirect(w, r, "/", http.StatusSeeOther)
            return
        }
        username, ok := usernameVal.(string)
        if !ok {
            log.Printf("AdminPageHandler: username has wrong type: %T", usernameVal)
            http.Error(w, "Internal Server Error", http.StatusInternalServerError)
            return
        }

        roleVal, ok := session.Values["role"]
        if !ok {
            http.Redirect(w, r, "/", http.StatusSeeOther)
            return
        }
        role, ok := roleVal.(string)
        if !ok {
            log.Printf("AdminPageHandler: role has wrong type: %T", roleVal)
            http.Error(w, "Internal Server Error", http.StatusInternalServerError)
            return
        }

        if role != "admin" {
            http.Error(w, "Forbidden", http.StatusForbidden)
            return
        }

        tmpl, err := template.ParseFiles(
            "static/templates/admin/"+page+".html",
            "static/templates/partials/header.html",
        )
        if err != nil {
            log.Printf("AdminPageHandler template parse error: %v", err)
            http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
            return
        }

        data := struct {
            Username string
            UserRole string
        }{
            Username: username,
            UserRole: role,
        }

        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        if err := tmpl.Execute(w, data); err != nil {
            log.Printf("AdminPageHandler template execute error: %v", err)
            http.Error(w, "Template execution error: "+err.Error(), http.StatusInternalServerError)
        }
    }
}