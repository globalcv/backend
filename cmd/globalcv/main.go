package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"time"

	"globalcv/globalcv"
)

func main() {
	// Get debug env var
	debug, err := strconv.ParseBool(os.Getenv("debug"))
	if err != nil {
		log.Println("Error getting debug environment variable")
	}

	// Create new globalcv API
	a, err := globalcv.New(globalcv.Options{
		Addr:   os.Getenv("addr"),
		DBhost: os.Getenv("dbhost"),
		DBport: os.Getenv("dbport"),
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
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	go func() {
		<-quit

		fmt.Println()
		a.Logger.Println("globalcv API is shutting down...")

		ctx, cancel := context.WithTimeout(context.Background(), a.Server.WriteTimeout)
		defer cancel()

		a.Server.SetKeepAlivesEnabled(false)
		if err := a.Server.Shutdown(ctx); err != nil {
			a.Logger.Fatalf("Could not gracefully shutdown the server: %v", err)
		}

		select {
		case <-time.After(a.Server.WriteTimeout):
			a.Logger.Println("not all connections to server were gracefully closed")
			os.Exit(1)
		case <-ctx.Done():
			a.Logger.Println("globalcv API successfully shutdown")
			os.Exit(0)
		}
	}()

	// Start the server
	if err = a.Run(); err != nil {
		a.Logger.Fatalf("Error running globalcv API: %v", err)
	}
}
