package globalcv

import (
	"crypto/sha512"
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
	"github.com/jinzhu/gorm"
)

func (a *API) listUsers(w http.ResponseWriter, r *http.Request) {
	var users []User
	if err := a.DB.Table("users").Find(&users).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			a.respond(w, http.StatusNotFound, "unable to retrieve all users", "Unable to retrieve all users")
			return
		}
		a.respond(w, http.StatusInternalServerError, "error communicating with database",
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
	if err := a.DB.Table("users").Where("id = ?", id).First(&user).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			a.respond(w, http.StatusNotFound, "user not found", "User %v not found", id)
			return
		}
		a.respond(w, http.StatusInternalServerError, "error communicating with database",
			"Database error while getting %v: %v", user.ID, err)
		return
	}

	user.Password = "" // Sanitize user's password

	if err := a.validateIdentity(r, &user); err != nil {
		a.respond(w, http.StatusUnauthorized, "Invalid permissions",
			"Unable to validate permissions to view user %v: %v", user.ID, err)
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
			a.respond(w, http.StatusBadRequest, "bad request", "error decoding request: %v", err)
			return
		}

		// Does the user exist?
		if err := a.DB.Table("users").Where("email = ?", user.Email).First(&user).Error; err != nil {
			if !gorm.IsRecordNotFoundError(err) {
				a.respond(w, http.StatusNotFound, "user already exists", "User %s already exists", user.Email)
				return
			}
			a.respond(w, http.StatusInternalServerError, "error communicating with database",
				"Database error while authenticating %v: %v", user.ID, err)
			return
		}

		// Generate argon2 hash of the supplied password to store
		hashedPassword, hashErr := auth.HashPassword(user.Password)
		if hashErr != nil {
			a.respond(w, http.StatusInternalServerError, "error creating user",
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
		user.EmailLogin = true

		// Create the user
		if err := a.DB.Create(&user).Error; err != nil {
			a.respond(w, http.StatusInternalServerError, "error creating user",
				"Unable to create user %v: %v", user.ID, err)
			return
		}

		// create JWT in header
		if err := a.createJWT(w, &user); err != nil {
			a.respond(w, http.StatusInternalServerError, "error creating user",
				"Unable to create JWT for user %v: %v", user.ID, err)
			return
		}

		user.Password = "" // Sanitize user's password

		// Send back response
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
		if err := a.DB.Table("users").Where("id = ?", id).First(&user).Error; err != nil {
			if gorm.IsRecordNotFoundError(err) {
				a.respond(w, http.StatusNotFound, "user not found", "User %v not found", id)
				return
			}
			a.respond(w, http.StatusInternalServerError, "error communicating with database",
				"Database error while getting %v: %v", user.ID, err)
			return
		}

		user.Password = "" // Sanitize user's password

		// Validate if the updater is actually the user being updated
		if err := a.validateIdentity(r, &user); err != nil {
			a.respond(w, http.StatusForbidden, "invalid permissions",
				"Unable to validate permissions to modify user %v: %v", user.ID, err)
			return
		}

		// Decode user updates from POST
		var userUpdates User
		if err := json.NewDecoder(r.Body).Decode(&userUpdates); err != nil {
			a.respond(w, http.StatusBadRequest, "bad request", "error decoding request: %v", err)
			return
		}

		// Validate the user updates
		if err := a.validateInput(userUpdates); err != nil {
			a.respond(w, http.StatusConflict, err.Error(),
				"Unable to validate user %v: %v", user.ID, err)
			return
		}

		// Only update the fields that were modified
		if err := a.DB.Model(&user).Updates(userUpdates).Error; err != nil {
			a.respond(w, http.StatusInternalServerError, "error updating user",
				"Unable to update user %v: %v", user.ID, err)
			return
		}

		a.respond(w, http.StatusOK, fmt.Sprintf("User %v successfully updated", user.ID),
			"User %v has been updated", user.ID)
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
		if err := a.DB.Table("users").Where("id = ?", id).First(&user).Error; err != nil {
			if gorm.IsRecordNotFoundError(err) {
				a.respond(w, http.StatusNotFound, "user not found", "User %v not found", id)
				return
			}
			a.respond(w, http.StatusInternalServerError, "error communicating with database",
				"Database error while getting %v: %v", user.ID, err)
			return
		}

		user.Password = "" // Sanitize user's password

		// Validate if the deleter is actually the user being deleted
		if err := a.validateIdentity(r, &user); err != nil {
			a.respond(w, http.StatusForbidden, "invalid permissions",
				"Unable to validate permissions to delete user %v: %v", user.ID, err)
			return
		}

		// Delete the user
		if err := a.DB.Table("users").Where("id = ?", id).Delete(&user).Error; err != nil {
			if gorm.IsRecordNotFoundError(err) {
				a.respond(w, http.StatusNotFound, "user not found", "User %v not found", user.ID)
				return
			}
			a.respond(w, http.StatusInternalServerError, "error communicating with database",
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
			a.respond(w, http.StatusBadRequest, "bad request", "error decoding request: %v", err)
			return
		}

		// Does the user exist?
		var user User
		if err := a.DB.Table("users").Where("email = ?", userReq.Email).First(&user).Error; err != nil {
			if gorm.IsRecordNotFoundError(err) {
				a.respond(w, http.StatusNotFound, "user not found", "User %s not found", userReq.Email)
				return
			}
			a.respond(w, http.StatusInternalServerError, "error communicating with database",
				"Database error while authenticating %v: %v", user.ID, err)
			return
		}

		// Check password with stored hash
		if ok, err := auth.ComparePasswordHash(user.Password, userReq.Password); !ok {
			a.respond(w, http.StatusUnauthorized, "incorrect password",
				"Incorrect password entered for %v", user.ID)
			return
		} else if err != nil {
			a.respond(w, http.StatusInternalServerError, "error validating password",
				"Error comparing hash and password for %v: %v", user.ID, err)
			return
		}

		user.Password = "" // Sanitize user's password

		// Create JWT
		if err := a.createJWT(w, &user); err != nil {
			a.respond(w, http.StatusInternalServerError, "error creating JWT",
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
		a.respond(w, http.StatusInternalServerError, "error logging user out", "Unable to get auth cookie: %v", err)
		return
	}
	authCookie.Value = ""
	authCookie.MaxAge = -1
	authCookie.Expires = time.Now().Add(-7 * 24 * time.Hour)
	http.SetCookie(w, authCookie)

	refreshCookie, err := r.Cookie(refreshCookie)
	if err != nil || refreshCookie == nil {
		a.respond(w, http.StatusInternalServerError, "error logging user out", "Unable to get refresh cookie: %v", err)
		return
	}
	refreshCookie.Value = ""
	refreshCookie.MaxAge = -1
	refreshCookie.Expires = time.Now().Add(-7 * 24 * time.Hour)
	http.SetCookie(w, refreshCookie)

	a.respond(w, http.StatusOK, "User has been logged out", "User has been logged out")
}

func (a *API) validateIdentity(r *http.Request, user *User) error {
	// Grab refresh cookie and parse it
	cookie, err := r.Cookie(jwtCookie)
	if err != nil {
		return err
	}
	token, err := jwt.Parse(cookie.Value,
		func(*jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("jwt_secret")), nil
		})
	if err != nil {
		return err
	}
	if token.Claims.(jwt.MapClaims)["sub"] != user.ID {
		return errors.New("you do not have permissions to modify this resource")
	}
	return nil
}

func (a *API) validateInput(user User) error {
	if err := a.DB.Table("users").Where("email = ?", user.Email).First(&user).Error; err == nil {
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
		Domain:   "localhost",
		SameSite: http.SameSiteStrictMode,
		Value:    signedTokenString,
		Path:     "/",
		HttpOnly: true,
		Secure:   !a.Options.Debug,
		Expires:  time.Now().Add(time.Minute * 15),
	})
	// JWT token header
	w.Header().Set("Authorization: BEARER", signedTokenString)

	// Refresh cookie
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookie,
		Domain:   "localhost",
		SameSite: http.SameSiteStrictMode,
		Value:    refreshSignedTokenString,
		Path:     "/",
		HttpOnly: true,
		Secure:   !a.Options.Debug,
	})

	a.logf("JWT created for %v", user.ID)
	return nil
}

func (a *API) refreshToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	select {
	case <-ctx.Done():
		a.logf("request cancelled due to context Done() signal")
		return
	default:
		id := chi.URLParam(r, "userID")

		// Grab refresh cookie and parse it
		refreshTok, err := auth.ParseJWTCookie(r, refreshCookie)
		if err != nil {
			a.respond(w, http.StatusUnauthorized, "Error while authorizing", "error parsing JWT cookie: %v", err)
			return
		}

		// Grab refresh cookie and parse it
		userTok, err := auth.ParseJWTCookie(r, jwtCookie)
		if err != nil {
			a.respond(w, http.StatusUnauthorized, "Error while authorizing", "error parsing JWT cookie: %v", err)
			return
		}

		// Validate user is the same identity that's being requested
		if userTok.Claims.(jwt.MapClaims)["sub"] != refreshTok.Claims.(jwt.MapClaims)["sub"] {
			a.respond(w, http.StatusUnauthorized, "Not authorized",
				"Not authorized: user: %v, refresh: %v", userTok.Claims.(jwt.MapClaims)["sub"],
				refreshTok.Claims.(jwt.MapClaims)["sub"])
			return
		}

		// Everything is valid, create JWT
		token := jwt.New(jwt.SigningMethodHS256)
		jti := uuid.New()
		// Set token claims
		claims := token.Claims.(jwt.MapClaims)
		claims["jti"] = jti
		claims["iss"] = jwtIss
		claims["aud"] = jwtAud
		claims["sub"] = id
		claims["nbf"] = time.Now().Unix()
		claims["iat"] = time.Now().Unix()
		claims["exp"] = time.Now().Add(time.Minute * 15).Unix()
		signedTokenString, err := token.SignedString([]byte(os.Getenv("jwt_secret")))
		if err != nil {
			a.respond(w, http.StatusInternalServerError, "Error refreshing token",
				"Error encoding JWT: %v", err)
			return
		}

		// JWT token cookie
		http.SetCookie(w, &http.Cookie{
			Name:     jwtCookie,
			Domain:   "localhost",
			SameSite: http.SameSiteStrictMode,
			Value:    signedTokenString,
			Path:     "/",
			Expires:  time.Now().Add(time.Minute * 15),
			HttpOnly: true,
			Secure:   !a.Options.Debug,
		})

		a.respond(w, http.StatusOK, "User token has been refreshed", "JWT refreshed for %v", id)
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

		//	// Create user
		//	var user User
		//	if err := a.DB.Table("users").Where("email = ?", data.Email).First(&user).Error; err != nil {
		//		if gorm.IsRecordNotFoundError(err) {
		//			// create user
		//
		//			// Force lowercase email in database
		//			user.Email = strings.ToLower(user.Email)
		//
		//			// Generate gcvID
		//			s := sha512.Sum512([]byte(user.Email))
		//			user.GcvID = base64.StdEncoding.EncodeToString(s[:])
		//
		//			// Set GitHubLogin to true
		//			user.GitHubLogin = true
		//
		//			// Create the user
		//			if err := a.DB.Create(&user).Error; err != nil {
		//				a.logf("Unable to create user %v: %v", user.ID, err)
		//				a.respond(w, jsonResponse(http.StatusInternalServerError, "error creating user"))
		//				return
		//			}
		//
		//			// create JWT
		//			if err := a.createJWT(w, &user); err != nil {
		//				a.logf("Unable to create JWT for user %v: %v", user.ID, err)
		//				a.respond(w, jsonResponse(http.StatusInternalServerError, "error creating user"))
		//				return
		//			}
		//
		//			// Send back response
		//			resp := jsonResponse(http.StatusCreated, fmt.Sprintf("User %v created", user.ID))
		//			resp["user"] = user
		//
		//			a.logf("User %v created", user.ID)
		//			a.respond(w, resp)
		//			return
		//		}
		//		a.logf("Database error while authenticating %v: %v", user.ID, err)
		//		a.respond(w, jsonResponse(http.StatusInternalServerError, "error communicating with database"))
		//		return
		//	}
		//
		//	// log in user
		//
		//	// Check password with stored hash
		//	if ok, err := comparePasswordHash(user.Password, userReq.Password); !ok {
		//		a.logf("Incorrect password entered for %v", user.ID)
		//		a.respond(w, jsonResponse(http.StatusUnauthorized, "incorrect password"))
		//		return
		//	} else if err != nil {
		//		a.logf("Error comparing hash and password for %v: %v", user.ID, err)
		//		a.respond(w, jsonResponse(http.StatusInternalServerError, "error validating password"))
		//		return
		//	}
		//
		//	// Sanitize user's password
		//	user.Password = ""
		//
		//	// Create JWT
		//	if err := a.createJWT(w, &user); err != nil {
		//		a.logf("Error creating JWTs for %v: %v", user.ID, err)
		//		a.respond(w, jsonResponse(http.StatusInternalServerError, "error creating JWT"))
		//		return
		//	}
		//
		//	// Send back user info in response
		//	resp := jsonResponse(http.StatusOK, fmt.Sprintf("User %v authenticated", user.ID))
		//	resp["user"] = user
		//
		//	a.logf("User %v has been logged in", user.ID)
		//	a.respond(w, resp)
		//
	}
}
