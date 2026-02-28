package models

import (
    "database/sql"
    "time"
)

type Domain struct {
    ID           int64
    Name         string
    UserID       int64
    OwnerName    string // Добавлено
    SOAEmail     string
    SOAPrimaryNS string
    SOARefresh   int
    SOARetry     int
    SOAExpire    int
    SOAMinimum   int
    Serial       int
    CreatedAt    time.Time
}

type DomainCreateOptions struct {
    Name         string
    UserID       int64
    SOAEmail     string
    SOAPrimaryNS string
    SOARefresh   int
    SOARetry     int
    SOAExpire    int
    SOAMinimum   int
    CreateNS     bool
    CreateA      bool
    ServerIP     string
}

func CreateDomain(db *DB, opts *DomainCreateOptions) (int64, error) {
    if opts.SOARefresh == 0 {
        opts.SOARefresh = 7200
    }
    if opts.SOARetry == 0 {
        opts.SOARetry = 3600
    }
    if opts.SOAExpire == 0 {
        opts.SOAExpire = 1209600
    }
    if opts.SOAMinimum == 0 {
        opts.SOAMinimum = 3600
    }

    query := `INSERT INTO domains (
        name, user_id, soa_email, soa_primary_ns,
        soa_refresh, soa_retry, soa_expire, soa_minimum,
        serial, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`
    
    result, err := db.Exec(query,
        opts.Name,
        opts.UserID,
        opts.SOAEmail,
        opts.SOAPrimaryNS,
        opts.SOARefresh,
        opts.SOARetry,
        opts.SOAExpire,
        opts.SOAMinimum,
        time.Now(),
    )
    if err != nil {
        return 0, err
    }

    return result.LastInsertId()
}

func GetDomainsByUserID(db *DB, userID int64) ([]Domain, error) {
    rows, err := db.Query(`
        SELECT id, name, user_id, soa_email, soa_primary_ns,
               soa_refresh, soa_retry, soa_expire, soa_minimum,
               serial, created_at
        FROM domains
        WHERE user_id = ?
        ORDER BY name`, userID)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var domains []Domain
    for rows.Next() {
        var d Domain
        if err := rows.Scan(
            &d.ID, &d.Name, &d.UserID, &d.SOAEmail, &d.SOAPrimaryNS,
            &d.SOARefresh, &d.SOARetry, &d.SOAExpire, &d.SOAMinimum,
            &d.Serial, &d.CreatedAt,
        ); err != nil {
            return nil, err
        }
        d.OwnerName = "" // для обычного пользователя не заполняем
        domains = append(domains, d)
    }
    return domains, nil
}

func GetAllDomains(db *DB) ([]Domain, error) {
    rows, err := db.Query(`
        SELECT d.id, d.name, d.user_id, d.soa_email, d.soa_primary_ns,
               d.soa_refresh, d.soa_retry, d.soa_expire, d.soa_minimum,
               d.serial, d.created_at, u.username
        FROM domains d
        JOIN users u ON d.user_id = u.id
        ORDER BY d.created_at DESC`)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var domains []Domain
    for rows.Next() {
        var d Domain
        var username string
        if err := rows.Scan(
            &d.ID, &d.Name, &d.UserID, &d.SOAEmail, &d.SOAPrimaryNS,
            &d.SOARefresh, &d.SOARetry, &d.SOAExpire, &d.SOAMinimum,
            &d.Serial, &d.CreatedAt, &username,
        ); err != nil {
            return nil, err
        }
        d.OwnerName = username
        domains = append(domains, d)
    }
    return domains, nil
}

func GetDomainByID(db *DB, id int64) (*Domain, error) {
    var d Domain
    query := `SELECT id, name, user_id, soa_email, soa_primary_ns,
                     soa_refresh, soa_retry, soa_expire, soa_minimum,
                     serial, created_at
              FROM domains WHERE id = ?`

    err := db.QueryRow(query, id).Scan(
        &d.ID, &d.Name, &d.UserID, &d.SOAEmail, &d.SOAPrimaryNS,
        &d.SOARefresh, &d.SOARetry, &d.SOAExpire, &d.SOAMinimum,
        &d.Serial, &d.CreatedAt,
    )

    if err == sql.ErrNoRows {
        return nil, nil
    }
    if err != nil {
        return nil, err
    }

    // Можно подгрузить имя владельца отдельным запросом, но пока оставим пустым
    return &d, nil
}

func DomainExists(db *DB, name string) (bool, error) {
    var count int
    err := db.QueryRow("SELECT COUNT(*) FROM domains WHERE name = ?", name).Scan(&count)
    if err != nil {
        return false, err
    }
    return count > 0, nil
}

func DeleteDomain(db *DB, id int64) error {
    _, err := db.Exec("DELETE FROM domains WHERE id = ?", id)
    return err
}

func IncrementDomainSerial(db *DB, domainID int64) error {
    _, err := db.Exec("UPDATE domains SET serial = serial + 1 WHERE id = ?", domainID)
    return err
}

func CanAccessDomain(db *DB, userID int64, userRole string, domainID int64) (bool, error) {
    if userRole == "admin" {
        return true, nil
    }
    var count int
    err := db.QueryRow("SELECT COUNT(*) FROM domains WHERE id = ? AND user_id = ?", domainID, userID).Scan(&count)
    if err != nil {
        return false, err
    }
    return count > 0, nil
}