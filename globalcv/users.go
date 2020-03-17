package globalcv

import (
	"crypto/sha512"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"globalcv/globalcv/auth"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/google/uuid"
)

func (a *API) listUsers(w http.ResponseWriter, r *http.Request) {
	// Only if admin
	var users []User
	if err := a.DB.Select(&users, "SELECT * FROM users ORDER BY id"); err != nil {
		a.err(w, http.StatusInternalServerError, "error communicating with database",
			"Database error while getting all users: %v", err)
		return
	}

	for i := range users { // Sanitize users' passwords
		users[i].Password = ""
	}

	a.respond(w, http.StatusOK, users, "All users retrieved")
}

func (a *API) getUserByID(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "userID")

	var user User
	if err := a.DB.Get(&user, "SELECT * FROM users WHERE id=? LIMIT 1", id); err != nil {
		switch err {
		case sql.ErrNoRows:
			a.err(w, http.StatusNotFound, "user not found", "User %v not found", id)
			return
		default:
			a.err(w, http.StatusInternalServerError, "error communicating with database",
				"Database error while getting %v: %v", user.ID, err)
			return
		}
	}

	user.Password = "" // Sanitize user's password

	if err := validatePermissions(r, &user); err != nil {
		a.err(w, http.StatusUnauthorized, "Unauthorized",
			"Invalid permissions to view user %v: %v", user.ID, err)
		return
	}

	a.respond(w, http.StatusOK, user, "User %v retrieved by ID", user.ID)
}

func (a *API) createUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	select {
	case <-ctx.Done():
		a.logf("request cancelled due to context Done() signal")
		return
	default:
		var user User
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			a.err(w, http.StatusBadRequest, "bad request", "error decoding request: %v", err)
			return
		}

		// Does the user exist?
		if err := a.DB.Get(&user, "SELECT * FROM users WHERE email=? LIMIT 1", user.Email); err != nil {
			switch err {
			case sql.ErrNoRows:
				a.err(w, http.StatusNotFound, "user not found", "User %v not found", user.ID)
				return
			default:
				a.err(w, http.StatusInternalServerError, "error communicating with database",
					"Database error while getting %v: %v", user.ID, err)
				return
			}
		}

		// Generate argon2 hash of the supplied password to store
		hashedPassword, hashErr := auth.HashPassword(user.Password)
		if hashErr != nil {
			a.err(w, http.StatusInternalServerError, "error creating user",
				"Unable to generate random salt for %v's password: %v", user.ID, hashErr)
			return
		}

		// Store hashed password in database, never save the raw password
		user.Password = hashedPassword
		// Force lowercase email in database
		user.Email = strings.ToLower(user.Email)
		// Generate gcvID
		s := sha512.Sum512([]byte(user.Email))
		user.GcvID = base64.StdEncoding.EncodeToString(s[:])
		// Set EmailLogin to true
		user.EmailLogin.Bool = true
		// Set creation time
		user.CreatedAt = time.Now()

		// Create the user
		_, err := a.DB.NamedExec(`INSERT into users (email_login, email, password, avatar, gravatar_id) 
			VALUES (:email_login, :email, :password, :avatar, :gravatar_id)`, user)
		if err != nil {
			a.err(w, http.StatusInternalServerError, "error creating user",
				"Unable to create user %v: %v", user.ID, err)
			return
		}

		// create JWT in header
		if err := a.createJWT(w, &user); err != nil {
			a.err(w, http.StatusInternalServerError, "error creating user",
				"Unable to create JWT for user %v: %v", user.ID, err)
			return
		}

		user.Password = "" // Sanitize user's password

		// Send back response
		resp := map[string]interface{}{}
		resp["user"] = user
		resp["jwt"] = ""
		a.respond(w, http.StatusCreated, user, "User %v created", user.ID)
	}
}

func (a *API) updateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	select {
	case <-ctx.Done():
		a.logf("request cancelled due to context Done() signal")
		return
	default:
		id := chi.URLParam(r, "userID")

		var user User
		if err := a.DB.Get(&user, "SELECT * FROM users WHERE id=? LIMIT 1", id); err != nil {
			switch err {
			case sql.ErrNoRows:
				a.err(w, http.StatusNotFound, "user not found", "User %v not found", id)
				return
			default:
				a.err(w, http.StatusInternalServerError, "error communicating with database",
					"Database error while getting %v: %v", user.ID, err)
				return
			}
		}

		user.Password = "" // Sanitize user's password

		// Validate if the updater is actually the user being updated
		if err := validatePermissions(r, &user); err != nil {
			a.err(w, http.StatusForbidden, "invalid permissions",
				"Unable to validate permissions to modify user %v: %v", user.ID, err)
			return
		}

		// Decode user updates from POST
		var userUpdates User
		if err := json.NewDecoder(r.Body).Decode(&userUpdates); err != nil {
			a.err(w, http.StatusBadRequest, "bad request", "error decoding request: %v", err)
			return
		}

		// Validate the user updates
		if err := a.validateRequestInput(userUpdates); err != nil {
			a.err(w, http.StatusConflict, err.Error(), "Unable to validate user %v: %v", user.ID, err)
			return
		}

		// Only update the fields that were modified
		if _, err := a.DB.NamedExec(`INSERT INTO users (email, password, avatar, gravatar_id) 
			VALUES (:email, :password, :avatar, :gravatar_id)`, &userUpdates); err != nil {
			a.err(w, http.StatusInternalServerError, "error updating user",
				"Unable to update user %v: %v", user.ID, err)
			return
		}

		a.respond(w, http.StatusOK, user, "User %v has been updated", user.ID)
	}
}

func (a *API) deleteUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	select {
	case <-ctx.Done():
		a.logf("request cancelled due to context Done() signal")
		return
	default:
		id := chi.URLParam(r, "userID")

		var user User
		if err := a.DB.Get(&user, "SELECT * FROM users WHERE id=? LIMIT 1", id); err != nil {
			switch err {
			case sql.ErrNoRows:
				a.err(w, http.StatusNotFound, "user not found", "User %v not found", id)
				return
			default:
				a.err(w, http.StatusInternalServerError, "error communicating with database",
					"Database error while getting %v: %v", user.ID, err)
				return
			}
		}

		user.Password = "" // Sanitize user's password

		// Validate if the deleter is actually the user being deleted
		if err := validatePermissions(r, &user); err != nil {
			a.err(w, http.StatusForbidden, "invalid permissions",
				"Unable to validate permissions to delete user %v: %v", user.ID, err)
			return
		}

		// Delete the user
		if _, err := a.DB.Exec("DELETE FROM users WHERE id=?", id); err != nil {
			a.err(w, http.StatusInternalServerError, "error communicating with database",
				"Database error while deleting %v: %v", user.ID, err)
			return
		}

		a.respond(w, http.StatusOK, fmt.Sprintf("User %v successfully deleted", user.ID),
			"User %v has been deleted", user.ID)
	}
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	select {
	case <-ctx.Done():
		a.logf("request cancelled due to context Done() signal")
		return
	default:
		// Decode POST
		var userReq User
		if err := json.NewDecoder(r.Body).Decode(&userReq); err != nil {
			a.err(w, http.StatusBadRequest, "bad request", "error decoding request: %v", err)
			return
		}

		// Does the user exist?
		var user User
		if err := a.DB.Get(&user, "SELECT * FROM users WHERE id=?", userReq.ID); err != nil {
			switch err {
			case sql.ErrNoRows:
				a.err(w, http.StatusNotFound, "user not found", "User %v not found", userReq.ID)
				return
			default:
				a.err(w, http.StatusInternalServerError, "error communicating with database",
					"Database error while getting %v: %v", user.ID, err)
				return
			}
		}

		// Check if user is able to log in via email
		if !user.EmailLogin.Valid {
			a.err(w, http.StatusUnauthorized, "unauthorized to log in via email",
				"User %v is not authorized to log in via email", user.ID)
			return
		}

		// Check password with stored hash
		if ok, err := auth.ComparePasswordHash(user.Password, userReq.Password); !ok {
			a.err(w, http.StatusUnauthorized, "incorrect password",
				"Incorrect password entered for %v", user.ID)
			return
		} else if err != nil {
			a.err(w, http.StatusInternalServerError, "error validating password",
				"Error comparing hash and password for %v: %v", user.ID, err)
			return
		}

		user.Password = "" // Sanitize user's password

		// Create JWT
		if err := a.createJWT(w, &user); err != nil {
			a.err(w, http.StatusInternalServerError, "error creating JWT",
				"Error creating JWTs for %v: %v", user.ID, err)
			return
		}

		// Send back user info in response
		a.respond(w, http.StatusOK, user, "User %v has been logged in", user.ID)
	}
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	authCookie, err := r.Cookie(jwtCookie)
	if err != nil || authCookie == nil {
		a.err(w, http.StatusInternalServerError, "error logging user out", "Unable to get auth cookie: %v", err)
		return
	}
	authCookie.Value = ""
	authCookie.MaxAge = -1
	authCookie.Expires = time.Now().Add(-7 * 24 * time.Hour)
	http.SetCookie(w, authCookie)

	refreshCookie, err := r.Cookie(refreshCookie)
	if err != nil || refreshCookie == nil {
		a.err(w, http.StatusInternalServerError, "error logging user out", "Unable to get refresh cookie: %v", err)
		return
	}
	refreshCookie.Value = ""
	refreshCookie.MaxAge = -1
	refreshCookie.Expires = time.Now().Add(-7 * 24 * time.Hour)
	http.SetCookie(w, refreshCookie)

	a.respond(w, http.StatusOK, "User has been logged out", "User has been logged out")
}

func validatePermissions(r *http.Request, user *User) error {
	// Grab refresh cookie and parse it
	token, err := auth.ParseJWTCookie(r, jwtCookie)
	if err != nil {
		return err
	}
	if int(token.Claims.(jwt.MapClaims)["sub"].(float64)) != user.ID {
		return errors.New("you do not have permissions to modify this resource")
	}
	return nil
}

func (a *API) validateRequestInput(user User) error {
	// TODO: check this email verification
	if err := a.DB.Get(&user, "SELECT * FROM users WHERE email=?", user.Email); err == nil {
		return errors.New("email address already in use")
	}
	validateCap := regexp.MustCompile(`[A-Z]+`)
	validateNum := regexp.MustCompile(`[0-9]+`)
	validateEmail := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}" +
		"[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	validateSymbols := regexp.MustCompile(`[^\w\s]+`)
	switch {
	case !validateEmail.MatchString(user.Email):
		return errors.New("invalid email provided")
	case len(user.Password) < 8:
		return errors.New("password too short")
	case len(user.Password) > 254:
		return errors.New("password too long")
	case !validateSymbols.MatchString(user.Password):
		return errors.New("password must contain a symbol")
	case !validateNum.MatchString(user.Password):
		return errors.New("password must contain a number")
	case !validateCap.MatchString(user.Password):
		return errors.New("password must contain a capital letter")
	default:
		return nil
	}
}

// createToken creates a jwt token with user claims
func (a *API) createJWT(w http.ResponseWriter, user *User) error {
	// Create JWT
	token := jwt.New(jwt.SigningMethodHS256)
	jti := uuid.New()
	// Set token claims
	claims := token.Claims.(jwt.MapClaims)
	claims["jti"] = jti
	claims["iss"] = jwtIss
	claims["aud"] = jwtAud
	claims["sub"] = user.ID
	claims["nbf"] = time.Now().Unix()
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(time.Minute * 15).Unix()
	signedTokenString, err := token.SignedString([]byte(os.Getenv("jwt_secret")))
	if err != nil {
		return fmt.Errorf("error signing JWT: %v", err)
	}

	// Create Refresh JWT
	refreshToken := jwt.New(jwt.SigningMethodHS256)
	refreshJti := uuid.New()
	// Set token claims
	refreshClaims := refreshToken.Claims.(jwt.MapClaims)
	refreshClaims["jti"] = refreshJti
	refreshClaims["iss"] = jwtIss
	refreshClaims["aud"] = jwtAud
	refreshClaims["sub"] = user.ID
	refreshClaims["nbf"] = time.Now().Unix()
	refreshClaims["iat"] = time.Now().Unix()
	refreshSignedTokenString, err := refreshToken.SignedString([]byte(os.Getenv("jwt_secret")))
	if err != nil {
		return fmt.Errorf("error signing refresh token: %v", err)
	}

	// JWT token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     jwtCookie,
		Domain:   a.Options.Domain,
		SameSite: http.SameSiteStrictMode,
		Value:    signedTokenString,
		Path:     "/",
		HttpOnly: true,
		Secure:   !a.Options.Debug,
		Expires:  time.Now().Add(time.Minute * 15),
	})
	// JWT token header
	w.Header().Set("Authorization: bearer", signedTokenString)

	// Refresh cookie
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookie,
		Domain:   a.Options.Domain,
		SameSite: http.SameSiteStrictMode,
		Value:    refreshSignedTokenString,
		Path:     "/",
		HttpOnly: true,
		Secure:   !a.Options.Debug,
	})

	// gcvid cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "gcvid",
		Domain:   a.Options.Domain,
		SameSite: http.SameSiteStrictMode,
		Value:    user.GcvID,
		Path:     "/",
		HttpOnly: true,
		Secure:   !a.Options.Debug,
	})

	a.logf("JWT created for %v", user.ID)
	return nil
}

// whoami gets the locally logged in globalcv user and returns it
// via JSON.
func (a *API) whoami(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	select {
	case <-ctx.Done():
		a.logf("request cancelled due to context Done() signal")
		return
	default:
		gcvidCookie, err := r.Cookie("gcvid")
		if err != nil {
			a.err(w, http.StatusInternalServerError, "error getting current user",
				"Unable to get gcvid cookie: %v", err)
			return
		}

		// Grab refresh cookie and parse it
		refreshTok, err := auth.ParseJWTCookie(r, refreshCookie)
		if err != nil {
			a.err(w, http.StatusUnauthorized, "Error while authorizing",
				"error parsing refresh cookie: %v", err)
			return
		}

		// Does the user exist?
		var user User
		if err := a.DB.Get(&user, "SELECT * FROM users WHERE gcv_id=? LIMIT 1", gcvidCookie.Value); err != nil {
			switch err {
			case sql.ErrNoRows:
				a.err(w, http.StatusNotFound, "user not found", "User %v not found", gcvidCookie.Value)
				return
			default:
				a.err(w, http.StatusInternalServerError, "error communicating with database",
					"Database error while getting %v: %v", user.ID, err)
				return
			}
		}

		// Validate refresh token id == gcvid cookie value
		if user.ID != int(refreshTok.Claims.(jwt.MapClaims)["sub"].(float64)) {
			a.err(w, http.StatusUnauthorized, "Not authorized",
				"Not authorized: gcvCookieUser: %v, refreshTokenUser: %v", user.ID,
				refreshTok.Claims.(jwt.MapClaims)["sub"])
			return
		}

		// Create JWT
		if err := a.createJWT(w, &user); err != nil {
			a.err(w, http.StatusInternalServerError, "error creating JWT",
				"Error creating JWTs for %v: %v", user.GcvID, err)
			return
		}

		a.respond(w, http.StatusOK, user, "Local user retrieved from cookies for user %v", user.GcvID)
	}
}

func (a *API) GitHubCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	select {
	case <-ctx.Done():
		a.logf("request cancelled due to context Done() signal")
		return
	default:
		// Read oauthState from Cookie
		oauthState, err := r.Cookie("github_oauth")
		if err != nil {
			http.Error(w, "cookie not found", http.StatusUnauthorized)
			return
		}

		if r.FormValue("state") != oauthState.Value {
			log.Println("invalid oauth github state")
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		data, err := auth.GetUserDataFromGitHub(r.FormValue("code"))
		if err != nil {
			log.Println(err.Error())
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		// Grab user email + avatar
		fmt.Println(data)

		// Create & authenticate user
	}
}
