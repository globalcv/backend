package globalcv

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	"github.com/google/uuid"
	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/argon2"
)

func (a *API) listUsers(w http.ResponseWriter, r *http.Request) {
	var users []User
	if err := a.Options.DB.Find(&users).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			a.logf("Unable to retrieve all users")
			w.WriteHeader(http.StatusNotFound)
			a.respond(w, jsonResponse(http.StatusNotFound, "unable to retrieve all users"))
			return
		}
		a.logf("Database error while getting all users: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		a.respond(w, jsonResponse(http.StatusInternalServerError, "error communicating with database"))
		return
	}

	// Sanitize users' passwords
	for i := range users {
		users[i].Password = ""
	}

	a.logf("All users retrieved")
	a.respond(w, users)
}

func (a *API) getUserByID(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "userID")

	var user User
	if err := a.Options.DB.Table("users").Where("id = ?", id).First(&user).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			a.logf("User %v not found", id)
			w.WriteHeader(http.StatusNotFound)
			a.respond(w, jsonResponse(http.StatusNotFound, "user not found"))
			return
		}
		a.logf("Database error while getting %s: %v", user.ID, err)
		w.WriteHeader(http.StatusInternalServerError)
		a.respond(w, jsonResponse(http.StatusInternalServerError, "error communicating with database"))
		return
	}

	// Sanitize user's password
	user.Password = ""

	a.logf("User %s retrieved by ID", user.ID)
	a.respond(w, user)
}

func (a *API) createUser(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		a.logf("Bad request: 400")
		w.WriteHeader(http.StatusBadRequest)
		a.respond(w, jsonResponse(http.StatusBadRequest, "bad request"))
		return
	}

	// Generate argon2 hash of the supplied password to store
	hashedPassword, hashErr := hashPassword(user.Password)
	if hashErr != nil {
		a.logf("Unable to generate random salt for %s's password: %v", user.ID, hashErr)
		w.WriteHeader(http.StatusInternalServerError)
		a.respond(w, jsonResponse(http.StatusInternalServerError, "error creating user"))
		return
	}

	// Store hashed password in database, never save the raw password
	user.Password = hashedPassword
	// Force lowercase email in database
	user.Email = strings.ToLower(user.Email)

	// Create the user
	if err := a.Options.DB.Create(&user).Error; err != nil {
		a.logf("Unable to create user %s: %v", user.ID, err)
		w.WriteHeader(http.StatusInternalServerError)
		a.respond(w, jsonResponse(http.StatusInternalServerError, "error creating user"))
		return
	}

	// create JWT in header
	if err := a.createJWT(w, &user); err != nil {
		a.logf("Unable to create JWT for user %s: %v", user.ID, err)
		w.WriteHeader(http.StatusInternalServerError)
		a.respond(w, jsonResponse(http.StatusInternalServerError, "error creating user"))
		return
	}

	// Sanitize user's password
	user.Password = ""

	// Send back response
	resp := jsonResponse(http.StatusCreated, fmt.Sprintf("User %v created", user.ID))
	resp["user"] = user

	a.logf("User %s created", user.ID)
	a.respond(w, resp)
}

func (a *API) updateUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "userID")

	var user User
	if err := a.Options.DB.Table("users").Where("id = ?", id).First(&user).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			a.logf("User %s not found", id)
			w.WriteHeader(http.StatusNotFound)
			a.respond(w, jsonResponse(http.StatusNotFound, "user not found"))
			return
		}
		a.logf("Database error while getting %s: %v", user.ID, err)
		w.WriteHeader(http.StatusInternalServerError)
		a.respond(w, jsonResponse(http.StatusInternalServerError, "error communicating with database"))
		return
	}

	// Sanitize user's password
	user.Password = ""

	// Decode user updates from POST
	var userUpdates User
	if err := json.NewDecoder(r.Body).Decode(&userUpdates); err != nil {
		a.logf("Bad request: 400")
		w.WriteHeader(http.StatusBadRequest)
		a.respond(w, jsonResponse(http.StatusBadRequest, "bad request"))
		return
	}

	// Validate the user updates
	if err := a.validateInput(userUpdates); err != nil {
		a.logf("Unable to validate user %s: %v", user.ID, err)
		w.WriteHeader(http.StatusConflict)
		a.respond(w, jsonResponse(http.StatusConflict, err.Error()))
		return
	}

	// Validate if the updater is actually the user being updated
	if err := a.validateIdentity(r, &user); err != nil {
		a.logf("Unable to validate permissions to modify user %s: %v", user.ID, err)
		w.WriteHeader(http.StatusForbidden)
		a.respond(w, jsonResponse(http.StatusForbidden, "invalid permissions"))
		return
	}

	// Only update the fields that were modified
	if err := a.Options.DB.Model(&user).Updates(userUpdates).Error; err != nil {
		a.logf("Unable to update user %s: %v", user.ID, err)
		w.WriteHeader(http.StatusInternalServerError)
		a.respond(w, jsonResponse(http.StatusInternalServerError, "error updating user"))
		return
	}

	a.logf("User %s has been updated", user.ID)
	a.respond(w, jsonResponse(http.StatusOK, fmt.Sprintf("User %v successfully updated", user.ID)))
}

func (a *API) deleteUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "userID")

	var user User
	if err := a.Options.DB.Table("users").Where("id = ?", id).First(&user).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			a.logf("User %s not found", id)
			w.WriteHeader(http.StatusNotFound)
			a.respond(w, jsonResponse(http.StatusNotFound, "user not found"))
			return
		}
		a.logf("Database error while getting %s: %v", user.ID, err)
		w.WriteHeader(http.StatusInternalServerError)
		a.respond(w, jsonResponse(http.StatusInternalServerError, "error communicating with database"))
		return
	}

	// Sanitize user's password
	user.Password = ""

	// Validate if the deleter is actually the user being deleted
	if err := a.validateIdentity(r, &user); err != nil {
		a.logf("Unable to validate permissions to delete user %s: %v", user.ID, err)
		w.WriteHeader(http.StatusForbidden)
		a.respond(w, jsonResponse(http.StatusForbidden, "invalid permissions"))
		return
	}

	// Delete the user
	if err := a.Options.DB.Table("users").Where("id = ?", id).Delete(&user).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			a.logf("User %s not found", user.ID)
			w.WriteHeader(http.StatusNotFound)
			a.respond(w, jsonResponse(http.StatusNotFound, "user not found"))
			return
		}
		a.logf("Database error while deleting %s: %v", user.ID, err)
		w.WriteHeader(http.StatusInternalServerError)
		a.respond(w, jsonResponse(http.StatusInternalServerError, "error communicating with database"))
		return
	}

	a.logf("User %s has been deleted", user.ID)
	a.respond(w, jsonResponse(http.StatusOK, fmt.Sprintf("User %v successfully deleted", user.ID)))
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	// Decode POST
	var userReq User
	if err := json.NewDecoder(r.Body).Decode(&userReq); err != nil {
		a.logf("Bad request: 400")
		w.WriteHeader(http.StatusBadRequest)
		a.respond(w, jsonResponse(http.StatusBadRequest, "bad request"))
		return
	}

	// Does the user exist?
	var user User
	if err := a.Options.DB.Table("users").Where("email = ?", userReq.Email).First(&user).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			a.logf("User %s not found", userReq.Email)
			w.WriteHeader(http.StatusNotFound)
			a.respond(w, jsonResponse(http.StatusNotFound, "user not found"))
			return
		}
		a.logf("Database error while authenticating %s: %v", user.ID, err)
		w.WriteHeader(http.StatusInternalServerError)
		a.respond(w, jsonResponse(http.StatusInternalServerError, "error communicating with database"))
		return
	}

	// Check password with stored hash
	if ok, err := comparePasswordHash(user.Password, userReq.Password); !ok {
		a.logf("Incorrect password entered for %s", user.ID)
		w.WriteHeader(http.StatusUnauthorized)
		a.respond(w, jsonResponse(http.StatusUnauthorized, "incorrect password"))
		return
	} else if err != nil {
		a.logf("Error comparing hash and password for %s: %v", user.ID, err)
		w.WriteHeader(http.StatusInternalServerError)
		a.respond(w, jsonResponse(http.StatusInternalServerError, "error validating password"))
		return
	}

	// Sanitize user's password
	user.Password = ""

	// Create JWT
	if err := a.createJWT(w, &user); err != nil {
		a.logf("Error creating JWTs for %s: %v", user.ID, err)
		w.WriteHeader(http.StatusInternalServerError)
		a.respond(w, jsonResponse(http.StatusInternalServerError, "error creating JWT"))
		return
	}

	// Send back user info in response
	resp := jsonResponse(http.StatusOK, fmt.Sprintf("User %v authenticated", user.ID))
	resp["user"] = user

	a.logf("User %s has been logged in", user.ID)
	a.respond(w, resp)
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	authCookie, err := r.Cookie("jwt")
	if err != nil {
		a.logf("Unable to get auth cookie: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		a.respond(w, jsonResponse(http.StatusInternalServerError, "error logging user out"))
		return
	} else {
		authCookie.Value = ""
		authCookie.MaxAge = -1
		authCookie.Expires = time.Now().Add(-7 * 24 * time.Hour)
		http.SetCookie(w, authCookie)
	}

	a.logf("User has been logged out")
	a.respond(w, jsonResponse(http.StatusOK, "User has been logged out"))
}

func (a *API) validateIdentity(r *http.Request, user *User) error {
	// Grab user cookie and parse it
	userHeader := jwtauth.TokenFromHeader(r)
	token, err := a.Options.JWTTokenAuth.Decode(userHeader)
	if err != nil {
		return err
	}
	if token.Claims.(jwt.MapClaims)["sub"] != user.ID {
		return errors.New("you do not have permissions to modify this resource")
	}
	return nil
}

func (a *API) validateInput(user User) error {
	if err := a.Options.DB.Table("users").Where("email = ?", user.Email).First(&user).Error; err == nil {
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
	case len(user.Password) > 255:
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
	_, signedTokenString, err := a.Options.JWTTokenAuth.Encode(claims)
	if err != nil {
		return err
	}

	// JWT token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "jwt",
		Domain:   "localhost",
		SameSite: http.SameSiteStrictMode,
		Value:    signedTokenString,
		Path:     "/",
		HttpOnly: false,
		Secure:   !a.Options.Debug,
	})
	// JWT token header
	w.Header().Set("Authorization: BEARER", signedTokenString)

	a.logf("JWT created for %s", user.ID)
	return nil
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}
	passwordHash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	// Base64 encode the salt and hashed password
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(passwordHash)
	// Return a string using the standard encoded hash representation
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version,
		argonMemory, argonTime, argonThreads, b64Salt, b64Hash), nil
}

func comparePasswordHash(expectedPassword, providedPassword string) (bool, error) {
	vals := strings.Split(expectedPassword, "$")
	if len(vals) != 6 {
		return false, errors.New("invalid hash")
	}

	var version int
	_, err := fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return false, err
	}
	if version != argon2.Version {
		return false, errors.New("wrong argon version")
	}

	var mem, iter uint32
	var thread uint8
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &mem, &iter, &thread)
	if err != nil {
		return false, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(vals[4])
	if err != nil {
		return false, err
	}

	actualPasswordHash, err := base64.RawStdEncoding.DecodeString(vals[5])
	if err != nil {
		return false, err
	}

	providedPasswordHash := argon2.IDKey([]byte(providedPassword), salt, iter, mem, thread,
		uint32(len(actualPasswordHash)))
	return subtle.ConstantTimeCompare(actualPasswordHash, providedPasswordHash) == 1, nil
}
