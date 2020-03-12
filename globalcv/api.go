package globalcv

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/jwtauth"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/natefinch/lumberjack"
	"golang.org/x/net/http2"
)

const (
	// JWT iss & aud
	jwtIss = "resume-backend"
	jwtAud = "resume-frontend"
	// argon params
	argonTime    = 1
	argonThreads = 4
	argonMemory  = 64 * 1024
	argonKeyLen  = 32
	argonSaltLen = 16
)

func New(options ...Options) (*API, error) {
	var opts Options
	if len(options) > 0 {
		opts = options[0]
	}

	// Handle nil parameters
	if opts.Addr == "" {
		opts.Addr = "127.0.0.1:8000"
	}
	if opts.Logger == nil {
		opts.Logger = log.New(os.Stdout, "[resume-api] ", log.LstdFlags)
		if !opts.Debug {
			opts.Logger.SetOutput(&lumberjack.Logger{
				Filename:   "/var/log/resume.log",
				MaxSize:    500, // megabytes
				MaxBackups: 3,
				MaxAge:     28, //days
				Compress:   true,
			})
		}
	}
	if opts.DBname == "" || opts.DBpass == "" || opts.DBuser == "" || opts.DBhost == "" {
		return nil, errors.New("please provide database parameters")
	}

	// Create new API object based on provided parameters
	newAPI := API{Options: opts}

	// Init DB
	if err := newAPI.initDB(); err != nil {
		return nil, err
	}

	// Init Chi Router
	newAPI.InitRoutes()

	// Init Server
	if err := newAPI.initServer(); err != nil {
		return nil, err
	}

	// Set JWT Secret
	newAPI.Options.JWTSecret = os.Getenv("jwt_secret")
	newAPI.Options.JWTTokenAuth = jwtauth.New("HS256", newAPI.Options.JWTSecret, nil)

	// Return the newly initialized API object
	return &newAPI, nil
}

func (a *API) Run() error {
	a.Options.Logger.Println(fmt.Sprintf("Server is listening at: %s", a.Options.Addr))
	return a.Options.Server.ListenAndServe()
}

func (a *API) initServer() error {
	// Best practice to set timeouts to avoid Slowloris attacks.
	a.Options.Server = &http.Server{
		Addr:         a.Options.Addr,
		WriteTimeout: time.Second * 10,
		ReadTimeout:  time.Second * 5,
		IdleTimeout:  time.Second * 10,
		Handler:      a.Options.Router,
	}
	// Enable HTTP/2
	if err := http2.ConfigureServer(a.Options.Server, &http2.Server{}); err != nil {
		return err
	}
	return nil
}

func (a *API) initDB() error {
	// Database parameters
	dbURI := fmt.Sprintf("host=%s user=%s dbname=%s password=%s sslmode=%s", a.Options.DBhost,
		a.Options.DBuser, a.Options.DBname, a.Options.DBpass, a.Options.DBssl)

	// Connect to the database
	var err error
	if a.Options.DB, err = gorm.Open("postgres", dbURI); err != nil {
		return err
	}

	// Enable pooling
	// ref: https://github.com/jinzhu/gorm/issues/246
	a.Options.DB.DB().SetMaxIdleConns(0)
	a.Options.DB.DB().SetMaxOpenConns(0)

	// Double-check we can ping the DB after it connects
	if err = a.Options.DB.DB().Ping(); err != nil {
		return err
	}

	// Auto migrate database based on the model structs below
	if a.Options.Debug {
		a.Options.DB.Debug().AutoMigrate(User{}, Resume{})
		return nil
	}

	a.Options.DB.AutoMigrate(User{}, Resume{})
	return nil
}

// logf prints application errors if debug is enabled
func (a *API) logf(format string, args ...interface{}) {
	if a.Options.Debug {
		a.Options.Logger.Printf(format, args...)
	}
}

// jsonResponse builds a map containing the response's status and error message
func jsonResponse(status int, message string) map[string]interface{} {
	return map[string]interface{}{"status": status, "message": message}
}

// respond takes any interface and spits it out in JSON format
// with the necessary response headers
func (a *API) respond(w http.ResponseWriter, data interface{}) {
	// Basic headers
	w.Header().Set("Accept-Charset", "utf-8")
	w.Header().Set("Content-Type", "application/json")
	// Clickjack headers
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("X-Frame-Options", "deny")
	// CORS headers
	//w.Header().Set("Access-Control-Allow-Origin", "http://localhost:8081")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", strings.Join([]string{
		http.MethodHead,
		http.MethodOptions,
		http.MethodGet,
		http.MethodPost,
		http.MethodPatch,
		http.MethodDelete,
	}, ", "))
	w.Header().Set("Access-Control-Allow-Headers",
		"Accept, Content-Type, Content-Length, Accept-Encoding, Authorization")
	w.Header().Set("Vary", "Accept-Encoding, Accept")

	if err := json.NewEncoder(w).Encode(data); err != nil {
		a.Options.Logger.Println(err)
	}
}
