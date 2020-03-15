package globalcv

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/jinzhu/gorm"
)

func (a *API) listResumes(w http.ResponseWriter, r *http.Request) {
	var resumes []Resume
	if err := a.DB.Table("resumes").Find(&resumes).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			a.respond(w, http.StatusNotFound, "unable to retrieve all resumes",
				"Unable to retrieve all resumes")
			return
		}
		a.respond(w, http.StatusInternalServerError, "error communicating with database",
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
			a.respond(w, http.StatusBadRequest, "Bad request",
				"error decoding request: %v", err)
			return
		}

		// Upload resume file
		uploadResume(&resume)

		// Create the resume
		if err := a.DB.Create(&resume).Error; err != nil {
			a.respond(w, http.StatusInternalServerError, "error creating resume",
				"Unable to create resume %v: %v", resume.ID, err)
			return
		}

		a.respond(w, http.StatusOK, resume, "Resume %v created", resume.ID)
	}
}

func (a *API) getResume(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "resumeID")

	var resume Resume
	if err := a.DB.Table("resumes").Where("id = ?", id).First(&resume).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			a.respond(w, http.StatusNotFound, "resume not found",
				"Resume %v not found", id)
			return
		}
		a.respond(w, http.StatusInternalServerError, "error communicating with database",
			"Database error while getting %v: %v", resume.ID, err)
		return
	}

	a.respond(w, http.StatusOK, resume, "Resume %v retrieved by ID", resume.ID)
}

func (a *API) updateResume(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("aaa update"))
}

func (a *API) deleteResume(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("aaa delete"))
}

func uploadResume(resume *Resume) {

}
