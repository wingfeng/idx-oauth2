package utils

import "golang.org/x/crypto/bcrypt"

func HashPassword(password string) (string, error) {
	// Convert the password string to a byte slice
	bytes := []byte(password)

	// Generate the hash with bcrypt
	hashedBytes, err := bcrypt.GenerateFromPassword(bytes, bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	// Return the hashed password as a string
	return string(hashedBytes), nil
}
