package miniature

import (
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
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
	dbObj.DBConn, err = gorm.Open(sqlite.Open("/etc/miniature/miniature.db"), &gorm.Config{})
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
	hashedPassword, err := hashPassword(user.Password)
	if err != nil {
		return err
	}
	user.Password = hashedPassword
	result := dbObj.DBConn.Create(user)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func (dbObj *DatabaseObject) GetUser(username, password string) (*User, error) {
	var user User
	result := dbObj.DBConn.First(&user, "username = ?", username)
	if result.Error != nil {
		return nil, result.Error
	}

	err := checkPassword(password, user.Password)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hashedPassword), nil
}

func checkPassword(password string, hashedPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}
