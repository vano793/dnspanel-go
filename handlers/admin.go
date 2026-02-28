package handlers

import (
    "encoding/json"
    "net/http"
    "os"
    "strconv"
    "strings"

    "dns-manager/models"

    "github.com/gorilla/mux"
    "github.com/gorilla/sessions"
    "github.com/spf13/viper"
)

func GetSettingsHandler(store *sessions.CookieStore) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        
        session, _ := store.Get(r, "session")
        if session.Values["role"] != "admin" {
            http.Error(w, "Forbidden", http.StatusForbidden)
            return
        }

        settings := map[string]interface{}{
            "server_port":               viper.GetString("server.port"),
            "server_domain":             viper.GetString("server.domain"),
            "use_domain":                 viper.GetBool("server.use_domain"),
            "server_ip":                   viper.GetString("server_ip"),
            "nsd_zone_dir":                viper.GetString("nsd.zone_dir"),
            "nsd_zones_conf":              viper.GetString("nsd.zones_conf"),
            "nsd_enabled":                 viper.GetBool("nsd.enabled"),
            "allow_users_create_ns":      viper.GetBool("security.allow_users_create_ns"),
            "allow_users_create_a":       viper.GetBool("security.allow_users_create_a"),
            "ns_servers":                  viper.GetStringSlice("dns.ns_servers"),
        }

        json.NewEncoder(w).Encode(settings)
    }
}

func UpdateSettingsHandler(store *sessions.CookieStore) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        
        session, _ := store.Get(r, "session")
        if session.Values["role"] != "admin" {
            http.Error(w, "Forbidden", http.StatusForbidden)
            return
        }

        var data struct {
            ServerPort          string   `json:"server_port"`
            ServerDomain        string   `json:"server_domain"`
            UseDomain           bool     `json:"use_domain"`
            ServerIP            string   `json:"server_ip"`
            NsdZoneDir          string   `json:"nsd_zone_dir"`
            NsdZonesConf        string   `json:"nsd_zones_conf"`
            NsdEnabled          bool     `json:"nsd_enabled"`
            AllowUsersCreateNS  bool     `json:"allow_users_create_ns"`
            AllowUsersCreateA   bool     `json:"allow_users_create_a"`
            NSServers           []string `json:"ns_servers"`
        }

        if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }

        viper.Set("server.port", data.ServerPort)
        viper.Set("server.domain", data.ServerDomain)
        viper.Set("server.use_domain", data.UseDomain)
        viper.Set("server_ip", data.ServerIP)
        viper.Set("nsd.zone_dir", data.NsdZoneDir)
        viper.Set("nsd.zones_conf", data.NsdZonesConf)
        viper.Set("nsd.enabled", data.NsdEnabled)
        viper.Set("security.allow_users_create_ns", data.AllowUsersCreateNS)
        viper.Set("security.allow_users_create_a", data.AllowUsersCreateA)
        viper.Set("dns.ns_servers", data.NSServers)

        if err := viper.WriteConfig(); err != nil {
            if err := viper.SafeWriteConfig(); err != nil {
                json.NewEncoder(w).Encode(map[string]interface{}{
                    "success": false,
                    "message": "Ошибка сохранения конфигурации: " + err.Error(),
                })
                return
            }
        }

        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": true,
            "message": "Настройки сохранены. Перезапустите сервер для применения изменений.",
        })
    }
}

func GetLogsHandler(store *sessions.CookieStore) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        
        session, _ := store.Get(r, "session")
        if session.Values["role"] != "admin" {
            http.Error(w, "Forbidden", http.StatusForbidden)
            return
        }

        logFile := viper.GetString("logging.file")
        if logFile == "" {
            logFile = "logs/dns-manager.log"
        }

        if _, err := os.Stat(logFile); os.IsNotExist(err) {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": true,
                "logs":    "Лог-файл ещё не создан. Возможно, нет записей.",
            })
            return
        }

        content, err := os.ReadFile(logFile)
        if err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": err.Error(),
            })
            return
        }

        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": true,
            "logs":    string(content),
        })
    }
}

func GetUserActivityHandler(db *models.DB, store *sessions.CookieStore) http.HandlerFunc {
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

        loginLogs, err := models.GetLoginLogsByUserID(db, userID, 100)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        actions, err := models.GetUserActionsByUserID(db, userID, 100)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        result := map[string]interface{}{
            "success":      true,
            "login_logs":   loginLogs,
            "user_actions": actions,
        }

        json.NewEncoder(w).Encode(result)
    }
}

func GetZoneFilesHandler(store *sessions.CookieStore) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        
        session, _ := store.Get(r, "session")
        if session.Values["role"] != "admin" {
            http.Error(w, "Forbidden", http.StatusForbidden)
            return
        }

        zoneDir := viper.GetString("nsd.zone_dir")
        files, err := os.ReadDir(zoneDir)
        if err != nil {
            json.NewEncoder(w).Encode(map[string]interface{}{
                "success": false,
                "message": err.Error(),
            })
            return
        }

        var fileInfos []map[string]interface{}
        for _, f := range files {
            if f.IsDir() || !strings.HasSuffix(f.Name(), ".zone") {
                continue
            }
            info, _ := f.Info()
            fileInfos = append(fileInfos, map[string]interface{}{
                "name":    f.Name(),
                "size":    info.Size(),
                "modtime": info.ModTime().Format("2006-01-02 15:04:05"),
            })
        }

        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": true,
            "files":   fileInfos,
        })
    }
}
