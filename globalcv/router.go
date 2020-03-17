package globalcv

import (
	"time"

	"globalcv/globalcv/auth"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
)

func (a *API) InitRoutes() {
	// Create new router
	a.Router = chi.NewRouter()
	// Middleware stack
	a.Router.Use(middleware.RequestID)
	a.Router.Use(middleware.RealIP)
	a.Router.Use(middleware.Logger)
	a.Router.Use(middleware.Recoverer)
	// Set a timeout value on the request context (ctx), that will signal
	// through ctx.Done() that the request has timed out and further
	// processing should be stopped.
	a.Router.Use(middleware.Timeout(30 * time.Second))
	// Register Routes
	a.userRoutes()
	a.resumeRoutes()
}

// userRoutes creates RESTful HTTP routes for globalcv users.
func (a *API) userRoutes() {
	a.Router.Route("/users", func(r chi.Router) {
		r.Get("/", a.listUsers)    // GET  /users       - list all users
		r.Get("/whoami", a.whoami) // GET /users/whoami - get local current user and log in
		r.Post("/", a.createUser)  // POST /users       - create a new user
		r.Post("/login", a.login)  // POST /users/login - login an existing user

		r.Group(func(r chi.Router) {
			r.Use(a.Authenticator.Handler)
			r.Post("/logout", a.logout) // POST /users/logout - log out an authenticated user
		})

		r.Route("/{userID:[0-9]+}", func(r chi.Router) {
			r.Get("/", a.getUserByID)    // GET /users/{id}   - get a single user by id
			r.Group(func(r chi.Router) { // Protected routes that require authorization
				r.Use(a.Authenticator.Handler)
				r.Patch("/", a.updateUser)  // PATCH  /users/{id} - update a single user by id
				r.Delete("/", a.deleteUser) // DELETE /users/{id} - delete a single user by id
			})
		})
	})
	// OAuth Routes
	a.Router.Route("/oauth", func(r chi.Router) {
		r.Group(func(r chi.Router) { // GitHub OAuth
			r.Post("/github", auth.GitHubLogin)
			r.Get("/github/callback", a.GitHubCallback)
		})
		r.Group(func(r chi.Router) { // GitLab OAuth
			r.Post("/gitlab", auth.GitLabLogin)
			//r.Get("/gitlab/callback", a.GitLabCallback)
		})
		r.Group(func(r chi.Router) { // LinkedIn OAuth
			r.Post("/linkedin", auth.LinkedInLogin)
			//r.Get("/linkedin/callback", a.LinkedInCallback)
		})
	})
}

// resumeRoutes creates RESTful HTTP routes for globalcv resumes.
func (a *API) resumeRoutes() {
	a.Router.Route("/resumes", func(r chi.Router) {
		r.Get("/", a.listResumes)    // GET  /resumes - list all resumes
		r.Group(func(r chi.Router) { // User needs to be authenticated to create resume
			r.Use(a.Authenticator.Handler)
			r.Post("/", a.createResume) // POST /resumes - create a new resume
		})
		r.Route("/{resumeID:[0-9]+}", func(r chi.Router) {
			r.Group(func(r chi.Router) { // Protected routes that require authorization
				r.Use(a.Authenticator.Handler)
				r.Get("/", a.getResume)       // GET    /resumes/{id} - get a single resume by id
				r.Patch("/", a.updateResume)  // PATCH  /resumes/{id} - update a single resume by id
				r.Delete("/", a.deleteResume) // DELETE /resumes/{id} - delete a single resume by id
			})
		})
	})
}
