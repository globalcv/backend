package globalcv

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"

	"globalcv/globalcv/auth"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
)

func (a *API) listResumes(w http.ResponseWriter, r *http.Request) {
	// If admin
	var resumes []Resume
	if err := a.DB.Select(&resumes, "SELECT * FROM resumes ORDER BY id"); err != nil {
		a.err(w, http.StatusInternalServerError, "error communicating with database",
			"Database error while getting all resumes: %v", err)
		return
	}

	a.respond(w, http.StatusOK, resumes, "All resumes retrieved")
}

func (a *API) createResume(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	select {
	case <-ctx.Done():
		a.logf("request cancelled due to context Done() signal")
		return
	default:
		var resume Resume
		if err := json.NewDecoder(r.Body).Decode(&resume); err != nil {
			a.err(w, http.StatusBadRequest, "Bad request", "error decoding request: %v", err)
			return
		}

		// Validate if the updater is actually the creator of the resume
		userTok, err := auth.ParseJWTCookie(r, jwtCookie)
		if err != nil {
			a.err(w, http.StatusUnauthorized, "Unauthorized", "error parsing JWT cookie: %v", err)
			return
		}

		// Set resume user to JWT sub
		resume.User = int(userTok.Claims.(jwt.MapClaims)["sub"].(float64))

		// Upload resume file
		if err := uploadResume(&resume); err != nil {
			a.err(w, http.StatusInternalServerError, "error uploaded resume",
				"Unable to create resume %v: %v", resume.ID, err)
			return
		}

		// Create the resume
		if _, err := a.DB.NamedExec(`INSERT into resumes (user, file) VALUES (:user, :file)`, resume); err != nil {
			a.err(w, http.StatusInternalServerError, "error creating resume",
				"Unable to create resume %v: %v", resume.ID, err)
			return
		}

		a.respond(w, http.StatusOK, resume, "Resume %v created", resume.ID)
	}
}

func (a *API) getResume(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "resumeID")

	var resume Resume
	if err := a.DB.Get(&resume, "SELECT * FROM resumes WHERE id=? LIMIT 1", id); err != nil {
		switch err {
		case sql.ErrNoRows:
			a.err(w, http.StatusNotFound, "resume not found", "Resume %v not found", id)
			return
		default:
			a.err(w, http.StatusInternalServerError, "error communicating with database",
				"Database error while getting resume %v: %v", resume.ID, err)
			return
		}
	}

	// Validate if the updater is actually the creator of the resume
	userTok, err := auth.ParseJWTCookie(r, jwtCookie)
	if err != nil {
		a.err(w, http.StatusUnauthorized, "Unauthorized", "error parsing JWT cookie: %v", err)
		return
	}
	if int(userTok.Claims.(jwt.MapClaims)["sub"].(float64)) != resume.User {
		a.err(w, http.StatusUnauthorized, "Unauthorized",
			"Unauthorized: user: %v, refresh: %v", userTok.Claims.(jwt.MapClaims)["sub"], resume.User)
		return
	}

	a.respond(w, http.StatusOK, resume, "Resume %v retrieved by ID", resume.ID)
}

func (a *API) updateResume(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	select {
	case <-ctx.Done():
		a.logf("request cancelled due to context Done() signal")
		return
	default:
		id := chi.URLParam(r, "resumeID")

		var resume Resume
		if err := a.DB.Get(&resume, "SELECT * FROM resumes WHERE id=? LIMIT 1", id); err != nil {
			switch err {
			case sql.ErrNoRows:
				a.err(w, http.StatusNotFound, "resume not found", "Resume %v not found", id)
				return
			default:
				a.err(w, http.StatusInternalServerError, "error communicating with database",
					"Database error while getting resume %v: %v", resume.ID, err)
				return
			}
		}

		// Validate if the updater is actually the creator of the resume
		userTok, err := auth.ParseJWTCookie(r, jwtCookie)
		if err != nil {
			a.err(w, http.StatusUnauthorized, "Unauthorized", "error parsing JWT cookie: %v", err)
			return
		}
		if int(userTok.Claims.(jwt.MapClaims)["sub"].(float64)) != resume.User {
			a.err(w, http.StatusUnauthorized, "Unauthorized",
				"Unauthorized: user: %v, refresh: %v", userTok.Claims.(jwt.MapClaims)["sub"], resume.User)
			return
		}

		// Decode user updates from POST
		var resumeUpdates Resume
		if err := json.NewDecoder(r.Body).Decode(&resumeUpdates); err != nil {
			a.err(w, http.StatusBadRequest, "bad request", "error decoding request: %v", err)
			return
		}

		// Validate the resume updates
		if err := validateResumeInput(resumeUpdates); err != nil {
			return
		}

		// Only update the fields that were modified
		if _, err := a.DB.NamedExec(`INSERT INTO resumes (file) VALUES (:file)`, &resumeUpdates); err != nil {
			a.err(w, http.StatusInternalServerError, "error updating user",
				"Unable to update resume %v: %v", resume.ID, err)
			return
		}

		a.respond(w, http.StatusOK, resume, "Resume %v has been updated", resume.ID)
	}
}

func (a *API) deleteResume(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	select {
	case <-ctx.Done():
		a.logf("request cancelled due to context Done() signal")
		return
	default:
		id := chi.URLParam(r, "resumeID")

		var resume Resume
		if err := a.DB.Get(&resume, "SELECT * FROM resumes WHERE id=? LIMIT 1", id); err != nil {
			switch err {
			case sql.ErrNoRows:
				a.err(w, http.StatusNotFound, "resume not found", "Resume %v not found", id)
				return
			default:
				a.err(w, http.StatusInternalServerError, "error communicating with database",
					"Database error while getting resume %v: %v", resume.ID, err)
				return
			}
		}

		// Validate if the updater is actually the creator of the resume
		userTok, err := auth.ParseJWTCookie(r, jwtCookie)
		if err != nil {
			a.err(w, http.StatusUnauthorized, "Unauthorized", "error parsing JWT cookie: %v", err)
			return
		}
		if int(userTok.Claims.(jwt.MapClaims)["sub"].(float64)) != resume.User {
			a.err(w, http.StatusUnauthorized, "Unauthorized",
				"Unauthorized: user: %v, refresh: %v", userTok.Claims.(jwt.MapClaims)["sub"], resume.User)
			return
		}

		// Delete the resume
		if _, err := a.DB.Exec("DELETE FROM resumes WHERE id=?", id); err != nil {
			a.err(w, http.StatusInternalServerError, "error communicating with database",
				"Database error while deleting resume %v: %v", resume.ID, err)
			return
		}

		a.respond(w, http.StatusOK, fmt.Sprintf("Resume %v successfully deleted", resume.ID),
			"Resume %v has been deleted", resume.ID)
	}
}

func uploadResume(resume *Resume) error {
	// TODO: upload the resume file to S3 and set resume.File to the S3 URL
	resume.File = "s3-bucket.com/img.png"
	return nil
}

func validateResumeInput(resume Resume) error {
	// TODO: ensure file is valid URL format
	return nil
}
