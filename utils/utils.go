package utils

import (
	"math/rand"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword generates a bcrypt hash for the given password.
// This function takes a password string as input, and returns the hashed password string and possible errors.
// The purpose of hashing the password is to securely store it, making it difficult for attackers to obtain the plaintext password.
func HashPassword(password string) (string, error) {
	// Convert the password string to a byte slice for subsequent hashing operations.
	bytes := []byte(password)

	// Generate the hash with bcrypt.
	// bcrypt is a secure password hashing algorithm designed to be slow and resource-intensive, thus resisting brute force attacks.
	// Here, we use the default cost setting provided by bcrypt for balancing security and performance.
	// If an error occurs during the hashing process, an empty string and the error are returned.
	hashedBytes, err := bcrypt.GenerateFromPassword(bytes, bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	// Return the hashed password as a string.
	// Storing the hashed password instead of the plaintext password greatly enhances system security.
	return string(hashedBytes), nil
}

// GenerateRandomString generates a random string of a given length consisting of letters and digits.
func GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+=-"
	result := make([]byte, length)
	//rand.Seed(time.Now().UnixNano())

	for i := 0; i < length; i++ {
		result[i] = charset[rand.Intn(len(charset))]
	}

	return string(result)
}
