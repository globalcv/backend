package globalcv

import (
	"net/http"
	"time"

	"globalcv/oauth"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/jwtauth"
)

func (a *API) InitRoutes() {
	// Create new router
	a.Options.Router = chi.NewRouter()

	// A good base middleware stack
	a.Options.Router.Use(middleware.RequestID)
	a.Options.Router.Use(middleware.RealIP)
	a.Options.Router.Use(middleware.Logger)
	a.Options.Router.Use(middleware.Recoverer)
	a.Options.Router.Use(middleware.DefaultCompress)

	// Set a timeout value on the request context (ctx), that will signal
	// through ctx.Done() that the request has timed out and further
	// processing should be stopped.
	a.Options.Router.Use(middleware.Timeout(60 * time.Second))

	// Register Routes
	a.userRoutes()
	a.resumeRoutes()
}

// userRoutes creates RESTful HTTP routes for users
func (a *API) userRoutes() {
	a.Options.Router.Route("/users", func(r chi.Router) {
		r.Get("/", a.listUsers)   // GET  /users       - list all users
		r.Post("/", a.createUser) // POST /users       - create a new user
		r.Post("/login", a.login) // POST /users/login - login an existing user

		r.Route("/{userID:[0-9]+}", func(r chi.Router) {
			r.Get("/", a.getUserByID) // GET /users/{id}   - get a single user by id
			// Protected routes that require authorization
			r.Group(func(r chi.Router) {
				// JWT Auth
				r.Use(jwtauth.Verifier(a.Options.JWTTokenAuth))
				r.Use(a.authenticator)
				r.Patch("/", a.updateUser)  // PATCH  /users/{id} - update a single user by id
				r.Delete("/", a.deleteUser) // DELETE /users/{id} - delete a single user by id
			})
		})
	})

	// OAuth Routes
	a.Options.Router.Route("/oauth", func(r chi.Router) {
		// GitHub OAuth
		r.Group(func(r chi.Router) {
			r.Post("/github", oauth.GitHubLogin)
			r.Get("/github/callback", oauth.GitHubCallback)
		})
	})
}

// resumeRoutes creates RESTful HTTP routes for resumes
func (a *API) resumeRoutes() {
	a.Options.Router.Route("/resumes", func(r chi.Router) {
		r.Get("/", a.listResumes)    // GET    /resumes      - list all resumes
		r.Group(func(r chi.Router) { // User needs to be authenticated to create resume
			// JWT Auth
			r.Use(jwtauth.Verifier(a.Options.JWTTokenAuth))
			r.Use(a.authenticator)
			r.Post("/", a.createResume) // POST   /resumes      - create a new resume
		})

		r.Route("/{resumeID:[0-9]+}", func(r chi.Router) {
			r.Get("/", a.getResume) // GET    /resumes/{id} - get a single resume by id
			// Protected routes that require authorization
			r.Group(func(r chi.Router) {
				// JWT Auth
				r.Use(jwtauth.Verifier(a.Options.JWTTokenAuth))
				r.Use(a.authenticator)
				r.Patch("/", a.updateResume)  // PATCH  /resumes/{id} - update a single resume by id
				r.Delete("/", a.deleteResume) // DELETE /resumes/{id} - delete a single resume by id
			})
		})
	})
}

func (a *API) authenticator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := jwtauth.TokenFromCookie(r)
		if tokenString == "" {
			a.logf("no token in header")
			a.respond(w, jsonResponse(http.StatusUnauthorized, "Unauthorized"))
			return
		}

		token, err := a.Options.JWTTokenAuth.Decode(tokenString)
		if err != nil {
			a.logf("error retrieving token: %v; got: %v", err, tokenString)
			a.respond(w, jsonResponse(http.StatusUnauthorized, "Unauthorized"))
			return
		}

		if token == nil || !token.Valid {
			a.logf("token is invalid")
			a.respond(w, jsonResponse(http.StatusUnauthorized, "Unauthorized"))
			return
		}

		// Token is authenticated, pass it through
		next.ServeHTTP(w, r)
	})
}
