package services

import (
    "time"

    "dns-manager/models"
)

func LogUserAction(db *models.DB, userID int64, username, action, details, ip string) error {
    log := &models.UserAction{
        UserID:    userID,
        Username:  username,
        Action:    action,
        Details:   details,
        IP:        ip,
        CreatedAt: time.Now(),
    }
    
    return models.CreateUserAction(db, log)
}

func LogUserActionWithDB(db *models.DB, userID int64, username, action, details, ip string) {
    go LogUserAction(db, userID, username, action, details, ip) // Асинхронно
}
