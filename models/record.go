package models

import (
    "database/sql"
)

type Record struct {
    ID       int64
    DomainID int64
    Type     string
    Name     string
    Content  string
    Priority int
    TTL      int
}

func GetRecordsByDomainID(db *DB, domainID int64) ([]Record, error) {
    rows, err := db.Query(`
        SELECT id, domain_id, type, name, content, priority, ttl 
        FROM records 
        WHERE domain_id = ? 
        ORDER BY 
            CASE type 
                WHEN 'SOA' THEN 1
                WHEN 'NS' THEN 2
                ELSE 3
            END, name
    `, domainID)
    
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var records []Record
    for rows.Next() {
        var r Record
        if err := rows.Scan(&r.ID, &r.DomainID, &r.Type, &r.Name, &r.Content, &r.Priority, &r.TTL); err != nil {
            return nil, err
        }
        records = append(records, r)
    }
    return records, nil
}

func GetRecordByID(db *DB, id int64) (*Record, error) {
    var r Record
    query := `SELECT id, domain_id, type, name, content, priority, ttl 
              FROM records WHERE id = ?`
    
    err := db.QueryRow(query, id).Scan(
        &r.ID, &r.DomainID, &r.Type, &r.Name, &r.Content, &r.Priority, &r.TTL,
    )
    
    if err == sql.ErrNoRows {
        return nil, nil
    }
    if err != nil {
        return nil, err
    }
    
    return &r, nil
}

func CreateRecord(db *DB, record *Record) error {
    query := `INSERT INTO records (domain_id, type, name, content, priority, ttl) 
              VALUES (?, ?, ?, ?, ?, ?)`
    
    result, err := db.Exec(query, record.DomainID, record.Type, record.Name, 
                          record.Content, record.Priority, record.TTL)
    if err != nil {
        return err
    }
    
    id, err := result.LastInsertId()
    if err != nil {
        return err
    }
    
    record.ID = id
    return nil
}

func UpdateRecord(db *DB, record *Record) error {
    query := `UPDATE records SET type = ?, name = ?, content = ?, priority = ?, ttl = ? 
              WHERE id = ?`
    
    _, err := db.Exec(query, record.Type, record.Name, record.Content, 
                     record.Priority, record.TTL, record.ID)
    return err
}

func DeleteRecord(db *DB, id int64) error {
    _, err := db.Exec("DELETE FROM records WHERE id = ?", id)
    return err
}

func CountNSRecords(db *DB, domainID int64) (int, error) {
    var count int
    err := db.QueryRow(
        "SELECT COUNT(*) FROM records WHERE domain_id = ? AND type = 'NS'", 
        domainID,
    ).Scan(&count)
    
    return count, err
}