package models

import (
    "database/sql"
    "fmt"

    _ "github.com/mattn/go-sqlite3"
)

type DB struct {
    *sql.DB
}

func InitDB(dataSourceName string) (*DB, error) {
    db, err := sql.Open("sqlite3", dataSourceName)
    if err != nil {
        return nil, err
    }

    if err = db.Ping(); err != nil {
        return nil, err
    }

    // Создаем таблицы
    if err = createTables(db); err != nil {
        return nil, err
    }

    return &DB{db}, nil
}

func createTables(db *sql.DB) error {
    queries := []string{
        // Таблица пользователей с ролями
        `CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            email TEXT,
            role TEXT DEFAULT 'user',
            created_at DATETIME,
            last_login DATETIME,
            last_ip TEXT,
            active BOOLEAN DEFAULT 1
        )`,

        // Таблица логов входа
        `CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            ip TEXT,
            user_agent TEXT,
            success BOOLEAN,
            created_at DATETIME
        )`,

        // Таблица действий пользователей
        `CREATE TABLE IF NOT EXISTS user_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            action TEXT,
            details TEXT,
            ip TEXT,
            created_at DATETIME
        )`,

        // Таблица доменов (обновленная)
        `CREATE TABLE IF NOT EXISTS domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            user_id INTEGER,
            soa_email TEXT,
            soa_primary_ns TEXT,
            soa_refresh INTEGER DEFAULT 7200,
            soa_retry INTEGER DEFAULT 3600,
            soa_expire INTEGER DEFAULT 1209600,
            soa_minimum INTEGER DEFAULT 3600,
            serial INTEGER DEFAULT 1,
            created_at DATETIME,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )`,

        // Таблица записей
        `CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_id INTEGER,
            type TEXT,
            name TEXT,
            content TEXT,
            priority INTEGER DEFAULT 0,
            ttl INTEGER DEFAULT 3600,
            created_at DATETIME,
            FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE
        )`,

        // Индексы
        `CREATE INDEX IF NOT EXISTS idx_records_domain_id ON records(domain_id)`,
        `CREATE INDEX IF NOT EXISTS idx_domains_user_id ON domains(user_id)`,
        `CREATE INDEX IF NOT EXISTS idx_login_logs_user_id ON login_logs(user_id)`,
        `CREATE INDEX IF NOT EXISTS idx_user_actions_user_id ON user_actions(user_id)`,
    }

    for _, query := range queries {
        if _, err := db.Exec(query); err != nil {
            return fmt.Errorf("error creating table: %v", err)
        }
    }

    return nil
}
