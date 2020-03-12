package globalcv

import (
	"net/http"

	"github.com/go-chi/chi"
	"github.com/jinzhu/gorm"
)

func (a *API) listResumes(w http.ResponseWriter, r *http.Request) {
	var resumes []Resume
	if err := a.Options.DB.Find(&resumes).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			a.logf("Unable to retrieve all resumes")
			w.WriteHeader(http.StatusNotFound)
			a.respond(w, jsonResponse(http.StatusNotFound, "unable to retrieve all resumes"))
			return
		}
		a.logf("Database error while getting all resumes: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		a.respond(w, jsonResponse(http.StatusInternalServerError, "error communicating with database"))
		return
	}

	a.logf("All resumes retrieved")
	a.respond(w, resumes)
}

func (a *API) createResume(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("aaa create"))
}

func (a *API) getResume(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "resumeID")

	var resume Resume
	if err := a.Options.DB.Table("resumes").Where("id = ?", id).First(&resume).Error; err != nil {
		if gorm.IsRecordNotFoundError(err) {
			a.logf("Resume %v not found", id)
			w.WriteHeader(http.StatusNotFound)
			a.respond(w, jsonResponse(http.StatusNotFound, "resume not found"))
			return
		}
		a.logf("Database error while getting %s: %v", resume.ID, err)
		w.WriteHeader(http.StatusInternalServerError)
		a.respond(w, jsonResponse(http.StatusInternalServerError, "error communicating with database"))
		return
	}

	a.logf("Resume %s retrieved by ID", resume.ID)
	a.respond(w, resume)
}

func (a *API) updateResume(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("aaa update"))
}

func (a *API) deleteResume(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("aaa delete"))
}
