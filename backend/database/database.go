package database

import (
	"database/sql"
	"log"

	"golang.org/x/crypto/bcrypt"
)

// User represents a user in the system
type User struct {
	Username     string
	PasswordHash string
}

var users = make(map[string]User)

// InitDB initializes the in-memory database with a default user
func InitDB() {
	// For demonstration purposes, let's add a default user
	// In a real application, passwords should be securely generated and stored
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	users["testuser"] = User{
		Username:     "testuser",
		PasswordHash: string(hashedPassword),
	}
}

// AddUser adds a new user to the database
func AddUser(username, password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	users[username] = User{
		Username:     username,
		PasswordHash: string(hashedPassword),
	}
	log.Println("added user", users[username])
	return nil
}

// GetUser retrieves a user by username
func GetUser(username string) (User, bool) {
	user, ok := users[username]
	log.Println("getting user", user)
	return user, ok
}

// GetUserWithParameterizedQuery retrieves a user by username using a parameterized query to prevent SQL injection
func GetUserWithParameterizedQuery(db *sql.DB, username string) (User, bool) {
	var user User
	// A03:2021-Injection
	// In a real application, you would use a parameterized query like this:
	// row := db.QueryRow("SELECT username, password_hash FROM users WHERE username = ?", username)
	// err := row.Scan(&user.Username, &user.PasswordHash)
	// if err != nil {
	// 	 if err == sql.ErrNoRows {
	// 		 return User{}, false
	// 	 }
	// 	 log.Println("Error getting user:", err)
	// 	 return User{}, false
	// }
	// return user, true

	// For this demo, we'll continue to use the in-memory map
	user, ok := users[username]
	log.Println("getting user", user)
	return user, ok
}
