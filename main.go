package main

import (
    "encoding/gob"
    "log"
    "net/http"
    "os"
    "time"

    "dns-manager/handlers"
    "dns-manager/middleware"
    "dns-manager/models"
    "dns-manager/services"

    "github.com/gorilla/mux"
    "github.com/gorilla/sessions"
    "github.com/spf13/viper"
    "gopkg.in/natefinch/lumberjack.v2"
)

var store *sessions.CookieStore
const Version = "1.2.0" // или ваша версия

func main() {
    // Создаём директорию логов ДО настройки логгера
    if err := os.MkdirAll("logs", 0755); err != nil {
        log.Fatal("Cannot create logs directory:", err)
    }

    // Настройка логгера (lumberjack)
    log.SetOutput(&lumberjack.Logger{
        Filename:   "logs/dns-manager.log", // можно брать из конфига, но пока жёстко
        MaxSize:    100,
        MaxBackups: 10,
        MaxAge:     30,
        Compress:   true,
    })

    log.Printf("DNS Manager v%s starting...", Version)

    if err := initConfig(); err != nil {
        log.Fatal("Failed to load config:", err)
    }

    db, err := models.InitDB(viper.GetString("database.path"))
    if err != nil {
        log.Fatal("Failed to initialize database:", err)
    }
    defer db.Close()

    secretKey := viper.GetString("session.secret")
    if secretKey == "" {
        secretKey = "dns-manager-secret-key-2026"
        viper.Set("session.secret", secretKey)
        viper.WriteConfig()
        log.Println("Generated new session secret key")
    }

    store = sessions.NewCookieStore([]byte(secretKey))
    store.Options = &sessions.Options{
        Path:     "/",
        Domain:   "",
        MaxAge:   86400 * 7,
        HttpOnly: true,
        Secure:   false,
        SameSite: http.SameSiteLaxMode,
    }

    gob.Register(models.User{})
    gob.Register(models.UserRole(""))
    gob.Register(true)
    gob.Register(int64(0))
    gob.Register("")

    services.InitValidator()
    services.InitNSDManager(
        viper.GetString("nsd.zone_dir"),
        viper.GetString("nsd.zones_conf"),
    )

    createDirectories()

    // Тестовая запись в лог
    log.Println("Logger initialized successfully")

    router := mux.NewRouter()
    router.Use(middleware.LoggerMiddleware)

    router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

    router.HandleFunc("/install", handlers.InstallHandler(db, store)).Methods("GET", "POST")
    router.HandleFunc("/api/login", handlers.LoginHandler(db, store)).Methods("POST")
    router.HandleFunc("/api/logout", handlers.LogoutHandler(store)).Methods("POST")

    api := router.PathPrefix("/api").Subrouter()
    api.Use(middleware.AuthMiddleware(store))

    api.HandleFunc("/domains", handlers.GetUserDomainsHandler(db, store)).Methods("GET")
    api.HandleFunc("/domains", handlers.CreateDomainHandler(db, store)).Methods("POST")
    api.HandleFunc("/domains/{id}", handlers.DeleteDomainHandler(db, store)).Methods("DELETE")
    api.HandleFunc("/domains/{id}/records", handlers.GetRecordsHandler(db, store)).Methods("GET")
    api.HandleFunc("/records", handlers.CreateRecordHandler(db, store)).Methods("POST")
    api.HandleFunc("/records/{id}", handlers.UpdateRecordHandler(db, store)).Methods("PUT")
    api.HandleFunc("/records/{id}", handlers.DeleteRecordHandler(db, store)).Methods("DELETE")
    api.HandleFunc("/nsd/sync/{domain_id}", handlers.SyncNSDHandler(db, store)).Methods("POST")
    api.HandleFunc("/nsd/status", handlers.NSDStatusHandler()).Methods("GET")
    api.HandleFunc("/user/change-password", handlers.ChangePasswordHandler(db, store)).Methods("POST")

    admin := api.PathPrefix("/admin").Subrouter()
    admin.Use(middleware.AdminMiddleware(store))
    admin.HandleFunc("/users", handlers.GetUsersHandler(db, store)).Methods("GET")
    admin.HandleFunc("/users", handlers.CreateUserHandler(db, store)).Methods("POST")
    admin.HandleFunc("/users/{id}/status", handlers.UpdateUserStatusHandler(db, store)).Methods("PUT")
    admin.HandleFunc("/users/{id}", handlers.DeleteUserHandler(db, store)).Methods("DELETE")
    admin.HandleFunc("/users/{id}/activity", handlers.GetUserActivityHandler(db, store)).Methods("GET")
    admin.HandleFunc("/settings", handlers.GetSettingsHandler(store)).Methods("GET")
    admin.HandleFunc("/settings", handlers.UpdateSettingsHandler(store)).Methods("POST")
    admin.HandleFunc("/logs", handlers.GetLogsHandler(store)).Methods("GET")
    // НОВЫЙ МАРШРУТ ДЛЯ ФАЙЛОВ ЗОН
    admin.HandleFunc("/zonefiles", handlers.GetZoneFilesHandler(store)).Methods("GET")

    router.HandleFunc("/", handlers.IndexHandler(db, store)).Methods("GET")
    router.HandleFunc("/admin/users", handlers.AdminPageHandler("users", store)).Methods("GET")
    router.HandleFunc("/admin/settings", handlers.AdminPageHandler("settings", store)).Methods("GET")
    router.HandleFunc("/admin/logs", handlers.AdminPageHandler("logs", store)).Methods("GET")
    router.HandleFunc("/admin/user-activity", handlers.AdminPageHandler("user_activity", store)).Methods("GET")
    // НОВАЯ СТРАНИЦА ДЛЯ ФАЙЛОВ ЗОН
    router.HandleFunc("/admin/zonefiles", handlers.AdminPageHandler("zonefiles", store)).Methods("GET")

    port := viper.GetString("server.port")
    if port == "" {
        port = "8080"
    }

    srv := &http.Server{
        Handler:      router,
        Addr:         ":" + port,
        WriteTimeout: 15 * time.Second,
        ReadTimeout:  15 * time.Second,
    }

    log.Printf("Server v%s starting on port %s", Version, port)
    log.Fatal(srv.ListenAndServe())
}

func initConfig() error {
    viper.SetConfigName("config")
    viper.SetConfigType("yaml")
    viper.AddConfigPath(".")

    viper.SetDefault("database.path", "dns.sqlite")
    viper.SetDefault("server.port", "8080")
    viper.SetDefault("server.domain", "dns.example.com")
    viper.SetDefault("server.use_domain", false)
    viper.SetDefault("session.secret", "")
    viper.SetDefault("session.secure", false)
    viper.SetDefault("session.domain", "")
    viper.SetDefault("nsd.zone_dir", "./zones/")
    viper.SetDefault("nsd.zones_conf", "./zones.conf")
    viper.SetDefault("nsd.enabled", true)
    viper.SetDefault("default_ttl", 3600)
    viper.SetDefault("server_ip", "127.0.0.1")
    viper.SetDefault("logging.level", "info")
    viper.SetDefault("logging.file", "logs/dns-manager.log")
    viper.SetDefault("logging.max_size", 100)
    viper.SetDefault("logging.max_backups", 10)
    viper.SetDefault("logging.max_age", 30)
    viper.SetDefault("security.allow_users_create_ns", true)
    viper.SetDefault("security.allow_users_create_a", true)

    if err := viper.ReadInConfig(); err != nil {
        if _, ok := err.(viper.ConfigFileNotFoundError); ok {
            log.Println("Config file not found, creating default config.yaml")
            return createDefaultConfig()
        }
        return err
    }

    log.Println("Config loaded successfully")
    return nil
}

func createDefaultConfig() error {
    config := `# DNS Manager Configuration
database:
  path: dns.sqlite

server:
  port: 8080
  domain: "dns.example.com"
  use_domain: false

session:
  secret: ""
  secure: false
  domain: ""

nsd:
  zone_dir: "./zones/"
  zones_conf: "./zones.conf"
  enabled: true

default_ttl: 3600
server_ip: "127.0.0.1"

admin:
  email: "admin@example.com"
  
logging:
  level: "info"
  file: "logs/dns-manager.log"
  max_size: 100
  max_backups: 10
  max_age: 30
  
security:
  allow_users_create_ns: true
  allow_users_create_a: true
`
    return os.WriteFile("config.yaml", []byte(config), 0600)
}

func createDirectories() {
    dirs := []string{
        "static/css",
        "static/js",
        "static/templates",
        "static/templates/partials",
        "static/templates/admin",
        viper.GetString("nsd.zone_dir"),
    }

    for _, dir := range dirs {
        if err := os.MkdirAll(dir, 0755); err != nil {
            log.Printf("Warning: cannot create directory %s: %v", dir, err)
        }
    }
}