package DB

import (
	"APP/models"

	"gorm.io/gorm"
)

var Db *gorm.DB
var UserList []models.User
