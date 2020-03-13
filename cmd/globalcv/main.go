package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"

	"globalcv/globalcv"
)

func main() {
	debug, err := strconv.ParseBool(os.Getenv("debug"))
	if err != nil {
		log.Println("Error getting debug environment variable")
	}
	a, err := globalcv.New(globalcv.Options{
		Addr:   os.Getenv("addr"),
		DBhost: os.Getenv("dbhost"),
		DBname: os.Getenv("dbname"),
		DBuser: os.Getenv("dbuser"),
		DBpass: os.Getenv("dbpass"),
		DBssl:  os.Getenv("dbssl"),
		Debug:  debug,
	})
	if err != nil {
		log.Fatalf("Error initializing API: %v", err)
	}
	// Gracefully defer close connection to database
	defer func() {
		if err := a.DB.Close(); err != nil {
			a.Logger.Fatalf("Error closing connection to database: %v", err)
		}
	}()

	// Handle server interrupts
	done := make(chan bool)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	go func() {
		<-quit
		a.Logger.Println("Server is shutting down...")

		ctx, cancel := context.WithTimeout(context.Background(), a.Server.WriteTimeout)
		defer cancel()

		a.Server.SetKeepAlivesEnabled(false)
		if err := a.Server.Shutdown(ctx); err != nil {
			a.Logger.Fatalf("Could not gracefully shutdown the server: %v", err)
		}
		close(done)
	}()

	// Start the server
	if err = a.Run(); err != nil {
		a.Logger.Fatalf("Error running resume server: %v", err)
	}

	<-done
}
