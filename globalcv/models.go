package globalcv

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/ciehanski/go-jwt-middleware"
	"github.com/go-chi/chi"
	"github.com/jmoiron/sqlx"
)

type API struct {
	Options       Options
	Server        *http.Server
	Router        chi.Router
	DB            *sqlx.DB
	Logger        *log.Logger
	Authenticator *jwtmiddleware.JWTMiddleware
}

type Options struct {
	Addr   string
	DBname string
	DBhost string
	DBport string
	DBuser string
	DBpass string
	DBssl  string
	Debug  bool
	Domain string
}

type User struct {
	ID               int            `db:"id" json:"id"`
	GitHubLogin      sql.NullBool   `db:"type:github_login" json:"github_login,omitempty"`
	GitLabLogin      sql.NullBool   `db:"gitlab_login" json:"gitlab_login,omitempty"`
	LinkedInLogin    sql.NullBool   `db:"linkedin_login" json:"linkedin_login,omitempty"`
	EmailLogin       sql.NullBool   `db:"email_login" json:"email_login,omitempty"`
	Email            string         `db:"email" json:"email"`
	EmailConfirmed   sql.NullBool   `db:"email_confirmed" json:"email_confirmed"`
	GcvID            string         `db:"gcv_id" json:"gcv_id"`
	Password         string         `db:"password" json:"password,omitempty"`
	Avatar           sql.NullString `db:"avatar" json:"avatar"`
	GravatarID       sql.NullString `db:"gravatar_id" json:"gravatar_id"`
	ApplicationsSent sql.NullInt32  `db:"applications_sent" json:"applications_sent"`
	PrimaryResume    Resume         `db:"primary_resume" json:"primary_resume"`
	AllResumes       []Resume       `db:"all_resumes" json:"all_resumes"`
	Notifications    []Notification `db:"notifications" json:"notifications"`
	CreatedAt        time.Time      `db:"created_at" json:"created_at"`
	ModifiedAt       time.Time      `db:"modified_at" json:"modified_at"`
	DeletedAt        time.Time      `db:"deleted_at" json:"deleted_at"`
}

type Resume struct {
	ID              int           `db:"id" json:"id"`
	User            int           `db:"user" json:"user"`
	File            string        `db:"file" json:"file"`
	TimesApplied    sql.NullInt32 `db:"times_applied" json:"times_applied"`
	TimesViewed     sql.NullInt32 `db:"times_viewed" json:"times_viewed"`
	TimesDownloaded sql.NullInt32 `db:"times_downloaded" json:"times_downloaded"`
	CreatedAt       time.Time     `db:"created_at" json:"created_at"`
	ModifiedAt      time.Time     `db:"modified_at" json:"modified_at"`
	DeletedAt       time.Time     `db:"deleted_at" json:"deleted_at"`
}

type Notification struct {
	ID         int       `db:"id" json:"id"`
	User       int       `db:"user" json:"user"`
	Message    string    `db:"message" json:"message"`
	CreatedAt  time.Time `db:"created_at" json:"created_at"`
	ModifiedAt time.Time `db:"modified_at" json:"modified_at"`
	DeletedAt  time.Time `db:"deleted_at" json:"deleted_at"`
}
