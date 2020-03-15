package mailers

import (
	"log"
	"net/smtp"
)

func sendVerificationEmail(user *User) {
	// Set up authentication information.
	auth := smtp.PlainAuth(
		"",
		"hello@globalcv.io",
		"password",
		"mail.example.com",
	)
	// Connect to the server, authenticate, set the sender and recipient,
	// and send the email all in one step.
	err := smtp.SendMail(
		"mail.example.com:25",
		auth,
		"hello@globalcv.io",
		[]string{user.Email},
		[]byte("This is the email body."),
	)
	if err != nil {
		log.Fatal(err)
	}
}
