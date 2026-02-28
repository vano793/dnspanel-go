package middleware

import (
    "net/http"

    "github.com/gorilla/sessions"
)

func AuthMiddleware(store *sessions.CookieStore) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            session, err := store.Get(r, "session")
            if err != nil {
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
                return
            }

            auth, ok := session.Values["authenticated"].(bool)
            if !ok || !auth {
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}

func AdminMiddleware(store *sessions.CookieStore) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            session, err := store.Get(r, "session")
            if err != nil {
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
                return
            }

            roleVal, ok := session.Values["role"]
            if !ok {
                http.Error(w, "Forbidden", http.StatusForbidden)
                return
            }

            role, ok := roleVal.(string)
            if !ok || role != "admin" {
                http.Error(w, "Forbidden", http.StatusForbidden)
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}
