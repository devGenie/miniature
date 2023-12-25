package miniature

import (
	"log"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	_ "github.com/mattn/go-sqlite3"
)

type DatabaseObject struct {
	DBConn *gorm.DB
}

type User struct {
	ID       uint   `gorm:"primaryKey"`
	Username string `gorm:"unique"`
	Password string
}

func (dbObj *DatabaseObject) Init() (err error) {
	dbObj.DBConn, err = gorm.Open(sqlite.Open("miniature.db"), &gorm.Config{})
	if err != nil {
		return err
	}

	err = dbObj.DBConn.AutoMigrate(&User{})
	if err != nil {
		log.Fatal("Error adding user to database")
		return err
	}
	return nil
}

func (dbObj *DatabaseObject) AddUser(user *User) (err error) {
	result := dbObj.DBConn.Create(user)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func (dbObj *DatabaseObject) GetUserByUsername(username string) (*User, error) {
	var user User
	result := dbObj.DBConn.First(user, username)
	if result.Error != nil {
		return nil, result.Error
	}
	return &user, nil
}
