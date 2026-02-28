package middleware

import (
    "log"
    "net/http"
    "time"
)

// LoggerMiddleware логирует каждый HTTP-запрос
func LoggerMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        // Создаём обёртку для захвата статуса ответа
        lw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
        next.ServeHTTP(lw, r)
        duration := time.Since(start)
        log.Printf("[%s] %s %s %d %v", r.RemoteAddr, r.Method, r.URL.Path, lw.statusCode, duration)
    })
}

type loggingResponseWriter struct {
    http.ResponseWriter
    statusCode int
}

func (lw *loggingResponseWriter) WriteHeader(code int) {
    lw.statusCode = code
    lw.ResponseWriter.WriteHeader(code)
}