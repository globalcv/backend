package main

import (
	"context"
	"log"
	"os"
	"os/signal"

	"globalcv/globalcv"
)

func main() {
	a, err := globalcv.New(globalcv.Options{
		Addr:   os.Getenv("addr"),
		DBhost: os.Getenv("dbhost"),
		DBname: os.Getenv("dbname"),
		DBuser: os.Getenv("dbuser"),
		DBpass: os.Getenv("dbpass"),
		DBssl:  os.Getenv("dbssl"),
		Debug:  true,
	})
	if err != nil {
		log.Fatalf("Error initializing API: %v", err)
	}
	// Gracefully defer close connection to database
	defer func() {
		if err := a.Options.DB.Close(); err != nil {
			a.Options.Logger.Fatalf("Error closing connection to database: %v", err)
		}
	}()

	// Handle server interrupts
	done := make(chan bool)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	go func() {
		<-quit
		a.Options.Logger.Println("Server is shutting down...")

		ctx, cancel := context.WithTimeout(context.Background(), a.Options.Server.WriteTimeout)
		defer cancel()

		a.Options.Server.SetKeepAlivesEnabled(false)
		if err := a.Options.Server.Shutdown(ctx); err != nil {
			a.Options.Logger.Fatalf("Could not gracefully shutdown the server: %v", err)
		}
		close(done)
	}()

	// Start the server
	if err = a.Run(); err != nil {
		a.Options.Logger.Fatalf("Error starting resume server: %v", err)
	}

	<-done
}
