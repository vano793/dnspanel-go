package models

import (
    "database/sql"
    "time"
)

type UserRole string

const (
    RoleAdmin UserRole = "admin"
    RoleUser  UserRole = "user"
)

type User struct {
    ID           int64
    Username     string
    PasswordHash string
    Email        string
    Role         UserRole
    CreatedAt    time.Time
    LastLogin    *time.Time
    LastIP       string
    Active       bool
}

type LoginLog struct {
    ID        int64
    UserID    int64
    Username  string
    IP        string
    UserAgent string
    Success   bool
    CreatedAt time.Time
}

type UserAction struct {
    ID        int64
    UserID    int64
    Username  string
    Action    string
    Details   string
    IP        string
    CreatedAt time.Time
}

func CreateUser(db *DB, user *User) error {
    query := `INSERT INTO users (username, password_hash, email, role, active, created_at) 
              VALUES (?, ?, ?, ?, ?, ?)`
    
    _, err := db.Exec(query, user.Username, user.PasswordHash, user.Email, 
                     user.Role, user.Active, time.Now())
    return err
}

func GetUserByUsername(db *DB, username string) (*User, error) {
    var user User
    var lastLogin sql.NullTime
    var lastIP sql.NullString
    
    query := `SELECT id, username, password_hash, email, role, created_at, 
                     last_login, last_ip, active 
              FROM users WHERE username = ?`
    
    err := db.QueryRow(query, username).Scan(
        &user.ID, &user.Username, &user.PasswordHash, &user.Email,
        &user.Role, &user.CreatedAt, &lastLogin, &lastIP, &user.Active,
    )
    
    if err == sql.ErrNoRows {
        return nil, nil
    }
    if err != nil {
        return nil, err
    }
    
    if lastLogin.Valid {
        user.LastLogin = &lastLogin.Time
    }
    if lastIP.Valid {
        user.LastIP = lastIP.String
    }
    
    return &user, nil
}

func GetUserByID(db *DB, id int64) (*User, error) {
    var user User
    var lastLogin sql.NullTime
    var lastIP sql.NullString
    
    query := `SELECT id, username, password_hash, email, role, created_at, 
                     last_login, last_ip, active 
              FROM users WHERE id = ?`
    
    err := db.QueryRow(query, id).Scan(
        &user.ID, &user.Username, &user.PasswordHash, &user.Email,
        &user.Role, &user.CreatedAt, &lastLogin, &lastIP, &user.Active,
    )
    
    if err == sql.ErrNoRows {
        return nil, nil
    }
    if err != nil {
        return nil, err
    }
    
    if lastLogin.Valid {
        user.LastLogin = &lastLogin.Time
    }
    if lastIP.Valid {
        user.LastIP = lastIP.String
    }
    
    return &user, nil
}

func GetAllUsers(db *DB) ([]User, error) {
    rows, err := db.Query(`SELECT id, username, email, role, created_at, 
                                  last_login, last_ip, active 
                           FROM users ORDER BY created_at DESC`)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var users []User
    for rows.Next() {
        var u User
        var lastLogin sql.NullTime
        var lastIP sql.NullString
        
        if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Role, 
                           &u.CreatedAt, &lastLogin, &lastIP, &u.Active); err != nil {
            return nil, err
        }
        
        if lastLogin.Valid {
            u.LastLogin = &lastLogin.Time
        }
        if lastIP.Valid {
            u.LastIP = lastIP.String
        }
        
        users = append(users, u)
    }
    return users, nil
}

func UpdateUserLastLogin(db *DB, userID int64, ip string) error {
    query := `UPDATE users SET last_login = ?, last_ip = ? WHERE id = ?`
    _, err := db.Exec(query, time.Now(), ip, userID)
    return err
}

func UpdateUserPassword(db *DB, userID int64, passwordHash string) error {
    query := `UPDATE users SET password_hash = ? WHERE id = ?`
    _, err := db.Exec(query, passwordHash, userID)
    return err
}

func UpdateUserStatus(db *DB, userID int64, active bool) error {
    query := `UPDATE users SET active = ? WHERE id = ?`
    _, err := db.Exec(query, active, userID)
    return err
}

func DeleteUser(db *DB, userID int64) error {
    _, err := db.Exec("DELETE FROM users WHERE id = ?", userID)
    return err
}

// Login Logs
func CreateLoginLog(db *DB, log *LoginLog) error {
    query := `INSERT INTO login_logs (user_id, username, ip, user_agent, success, created_at) 
              VALUES (?, ?, ?, ?, ?, ?)`
    _, err := db.Exec(query, log.UserID, log.Username, log.IP, log.UserAgent, 
                     log.Success, time.Now())
    return err
}

func GetLoginLogs(db *DB, limit int) ([]LoginLog, error) {
    rows, err := db.Query(`
        SELECT id, user_id, username, ip, user_agent, success, created_at 
        FROM login_logs 
        ORDER BY created_at DESC 
        LIMIT ?`, limit)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var logs []LoginLog
    for rows.Next() {
        var l LoginLog
        if err := rows.Scan(&l.ID, &l.UserID, &l.Username, &l.IP, 
                           &l.UserAgent, &l.Success, &l.CreatedAt); err != nil {
            return nil, err
        }
        logs = append(logs, l)
    }
    return logs, nil
}

// GetLoginLogsByUserID возвращает логи входа конкретного пользователя
func GetLoginLogsByUserID(db *DB, userID int64, limit int) ([]LoginLog, error) {
    rows, err := db.Query(`
        SELECT id, user_id, username, ip, user_agent, success, created_at 
        FROM login_logs 
        WHERE user_id = ?
        ORDER BY created_at DESC 
        LIMIT ?`, userID, limit)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var logs []LoginLog
    for rows.Next() {
        var l LoginLog
        if err := rows.Scan(&l.ID, &l.UserID, &l.Username, &l.IP, 
                           &l.UserAgent, &l.Success, &l.CreatedAt); err != nil {
            return nil, err
        }
        logs = append(logs, l)
    }
    return logs, nil
}

// User Actions
func CreateUserAction(db *DB, action *UserAction) error {
    query := `INSERT INTO user_actions (user_id, username, action, details, ip, created_at) 
              VALUES (?, ?, ?, ?, ?, ?)`
    _, err := db.Exec(query, action.UserID, action.Username, action.Action, 
                     action.Details, action.IP, time.Now())
    return err
}

func GetUserActions(db *DB, limit int) ([]UserAction, error) {
    rows, err := db.Query(`
        SELECT id, user_id, username, action, details, ip, created_at 
        FROM user_actions 
        ORDER BY created_at DESC 
        LIMIT ?`, limit)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var actions []UserAction
    for rows.Next() {
        var a UserAction
        if err := rows.Scan(&a.ID, &a.UserID, &a.Username, &a.Action, 
                           &a.Details, &a.IP, &a.CreatedAt); err != nil {
            return nil, err
        }
        actions = append(actions, a)
    }
    return actions, nil
}

// GetUserActionsByUserID возвращает действия конкретного пользователя
func GetUserActionsByUserID(db *DB, userID int64, limit int) ([]UserAction, error) {
    rows, err := db.Query(`
        SELECT id, user_id, username, action, details, ip, created_at 
        FROM user_actions 
        WHERE user_id = ?
        ORDER BY created_at DESC 
        LIMIT ?`, userID, limit)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var actions []UserAction
    for rows.Next() {
        var a UserAction
        if err := rows.Scan(&a.ID, &a.UserID, &a.Username, &a.Action, 
                           &a.Details, &a.IP, &a.CreatedAt); err != nil {
            return nil, err
        }
        actions = append(actions, a)
    }
    return actions, nil
}