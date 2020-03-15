package globalcv

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ciehanski/go-jwt-middleware"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/natefinch/lumberjack"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
)

const (
	// JWT
	jwtCookie     = "jwt"
	refreshCookie = "refresh"
	jwtIss        = "globalcv-backend"
	jwtAud        = "globalcv-frontend"
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
	if opts.DBname == "" || opts.DBpass == "" || opts.DBuser == "" || opts.DBhost == "" {
		return nil, errors.New("please provide database parameters")
	}

	// Create new API object based on provided parameters
	newAPI := API{Options: opts}

	// Create Logger
	newAPI.Logger = log.New(os.Stdout, "[globalcv-api] ", log.LstdFlags)
	if !opts.Debug {
		newAPI.Logger.SetOutput(&lumberjack.Logger{
			Filename:   "/var/log/globalcv.log",
			MaxSize:    500, // megabytes
			MaxBackups: 3,
			MaxAge:     28, //days
			Compress:   true,
		})
	}

	// Init DB
	if err := newAPI.initDB(); err != nil {
		return nil, err
	}

	// Init Chi Routes
	newAPI.InitRoutes()

	// Init Server
	if err := newAPI.initServer(); err != nil {
		return nil, err
	}

	// Init JWT
	newAPI.JWTMiddleware = jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("jwt_secret")), nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			newAPI.respond(w, http.StatusInternalServerError, err.Error(),
				"JWT error: %v", err)
		},
		SigningMethod:       jwt.SigningMethodHS256,
		Extractor:           jwtmiddleware.FromCookie(jwtCookie),
		EnableAuthOnOptions: true,
		Debug:               newAPI.Options.Debug,
	})

	// Return the newly initialized API object
	return &newAPI, nil
}

func (a *API) Run() error {
	if a.Options.Debug {
		a.Logger.Println(fmt.Sprintf("Server is listening at: %s", a.Options.Addr))
		return a.Server.ListenAndServe()
	} else {
		a.Logger.Println(fmt.Sprintf("Server is listening at: %s", a.Options.Addr))
		return a.Server.ListenAndServeTLS("", "")
	}
}

func (a *API) initServer() error {
	ctx := context.Background()
	// Best practice to set timeouts to avoid Slowloris attacks.
	a.Server = &http.Server{
		Addr:         a.Options.Addr,
		ReadTimeout:  time.Second * 10,
		WriteTimeout: time.Second * 20,
		IdleTimeout:  time.Second * 30,
		Handler:      chi.ServerBaseContext(ctx, a.Router),
	}
	// Enable HTTP/2
	if err := http2.ConfigureServer(a.Server, &http2.Server{}); err != nil {
		return err
	}
	// Get certificate if prod
	if !a.Options.Debug {
		cert := &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			HostPolicy: func(ctx context.Context, host string) error {
				allowedHost := "globalcv.io"
				if host == allowedHost {
					return nil
				}
				return fmt.Errorf("acme/autocert: only %s host is allowed", allowedHost)
			},
			Cache: autocert.DirCache("."),
		}
		a.Server.Addr = ":443"
		a.Server.TLSConfig = &tls.Config{GetCertificate: cert.GetCertificate}
	}
	return nil
}

func (a *API) initDB() error {
	// Database parameters
	dbURI := fmt.Sprintf("host=%s user=%s dbname=%s password=%s sslmode=%s", a.Options.DBhost,
		a.Options.DBuser, a.Options.DBname, a.Options.DBpass, a.Options.DBssl)

	// Connect to the database
	var err error
	if a.DB, err = gorm.Open("postgres", dbURI); err != nil {
		return err
	}

	// Enable pooling
	// ref: https://github.com/jinzhu/gorm/issues/246
	a.DB.DB().SetMaxIdleConns(0)
	a.DB.DB().SetMaxOpenConns(0)

	// Double-check we can ping the DB after it connects
	if err = a.DB.DB().Ping(); err != nil {
		return err
	}

	// Auto migrate database based on the model structs below
	if a.Options.Debug {
		a.DB.Debug().AutoMigrate(User{}, Resume{})
		return nil
	}

	a.DB.AutoMigrate(User{}, Resume{})
	return nil
}

// logf prints application errors if debug is enabled
func (a *API) logf(format string, args ...interface{}) {
	if a.Options.Debug {
		a.Logger.Printf(format, args...)
	}
}

// respond takes any interface and spits it out in JSON format
// with the necessary response headers
func (a *API) respond(w http.ResponseWriter, status int, data interface{}, log string, logArgs ...interface{}) {
	// Log the response
	a.logf(log, logArgs...)
	// Write status header
	w.WriteHeader(status)
	// Basic headers
	w.Header().Set("Accept-Charset", "utf-8")
	w.Header().Set("Content-Type", "application/json")
	// CSP
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; img-src 'self';")
	// Clickjack headers
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("X-Frame-Options", "deny")
	// CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "localhost")
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
	w.Header().Set("Vary", "Accept-Encoding")
	// Encode and send the response
	if err := json.NewEncoder(w).Encode(map[string]interface{}{"status": status, "message": data}); err != nil {
		a.Logger.Println(err)
	}
}
