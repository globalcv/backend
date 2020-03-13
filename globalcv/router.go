package globalcv

import (
	"time"

	"globalcv/oauth"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
)

func (a *API) InitRoutes() {
	// Create new router
	a.Router = chi.NewRouter()

	// A good base middleware stack
	a.Router.Use(middleware.RequestID)
	a.Router.Use(middleware.RealIP)
	a.Router.Use(middleware.Logger)
	a.Router.Use(middleware.Recoverer)
	a.Router.Use(middleware.DefaultCompress)

	// Set a timeout value on the request context (ctx), that will signal
	// through ctx.Done() that the request has timed out and further
	// processing should be stopped.
	a.Router.Use(middleware.Timeout(30 * time.Second))

	// Register Routes
	a.userRoutes()
	a.resumeRoutes()
}

// userRoutes creates RESTful HTTP routes for users
func (a *API) userRoutes() {
	a.Router.Route("/users", func(r chi.Router) {
		r.Get("/", a.listUsers)   // GET  /users       - list all users
		r.Post("/", a.createUser) // POST /users       - create a new user
		r.Post("/login", a.login) // POST /users/login - login an existing user

		r.Group(func(r chi.Router) {
			r.Use(a.JWTMiddleware.Handler)

			r.Post("/logout", a.logout) // POST /users/logout - log out an authenticated user
		})

		r.Route("/{userID:[0-9]+}", func(r chi.Router) {
			r.Get("/", a.getUserByID)    // GET /users/{id}   - get a single user by id
			r.Group(func(r chi.Router) { // Protected routes that require authorization
				r.Use(a.JWTMiddleware.Handler)

				r.Patch("/", a.updateUser)  // PATCH  /users/{id} - update a single user by id
				r.Delete("/", a.deleteUser) // DELETE /users/{id} - delete a single user by id
			})
		})
	})

	// OAuth Routes
	a.Router.Route("/oauth", func(r chi.Router) {
		// GitHub OAuth
		r.Group(func(r chi.Router) {
			r.Post("/github", oauth.GitHubLogin)
			r.Get("/github/callback", oauth.GitHubCallback)
		})
		// GitLab OAuth
		r.Group(func(r chi.Router) {
			r.Post("/gitlab", oauth.GitlabLogin)
			r.Get("/gitlab/callback", oauth.GitHubCallback)
		})
		// LinkedIn OAuth
		r.Group(func(r chi.Router) {
			r.Post("/linkedin", oauth.LinkedInLogin)
			r.Get("/linkedin/callback", oauth.GitHubCallback)
		})
	})
}

// resumeRoutes creates RESTful HTTP routes for resumes
func (a *API) resumeRoutes() {
	a.Router.Route("/resumes", func(r chi.Router) {
		r.Get("/", a.listResumes)    // GET    /resumes      - list all resumes
		r.Group(func(r chi.Router) { // User needs to be authenticated to create resume
			r.Use(a.JWTMiddleware.Handler)

			r.Post("/", a.createResume) // POST   /resumes      - create a new resume
		})
		r.Route("/{resumeID:[0-9]+}", func(r chi.Router) {
			r.Group(func(r chi.Router) { // Protected routes that require authorization
				r.Use(a.JWTMiddleware.Handler)

				r.Get("/", a.getResume)       // GET    /resumes/{id} - get a single resume by id
				r.Patch("/", a.updateResume)  // PATCH  /resumes/{id} - update a single resume by id
				r.Delete("/", a.deleteResume) // DELETE /resumes/{id} - delete a single resume by id
			})
		})
	})
}
