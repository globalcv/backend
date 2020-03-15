package globalcv

import (
	"log"
	"net/http"

	"github.com/ciehanski/go-jwt-middleware"
	"github.com/go-chi/chi"
	"github.com/jinzhu/gorm"
)

type API struct {
	Options       Options
	Server        *http.Server
	Router        chi.Router
	DB            *gorm.DB
	Logger        *log.Logger
	JWTMiddleware *jwtmiddleware.JWTMiddleware
}

type Options struct {
	Addr   string
	DBname string
	DBhost string
	DBuser string
	DBpass string
	DBssl  string
	Debug  bool
}

type User struct {
	gorm.Model
	GitHubLogin      bool     `gorm:"type:boolean" json:"github_login,omitempty"`
	GitLabLogin      bool     `gorm:"type:boolean" json:"gitlab_login,omitempty"`
	LinkedInLogin    bool     `gorm:"type:boolean" json:"linkedin_login,omitempty"`
	EmailLogin       bool     `gorm:"type:boolean" json:"email_login,omitempty"`
	Email            string   `gorm:"type:varchar(255);not null;unique;unique_index:idx_user_by_email" json:"email"`
	EmailConfirmed   bool     `gorm:"type:boolean;not null" json:"email_confirmed"`
	GcvID            string   `gorm:"type:varchar(255);not null;unique;unique_index:idx_user_by_gcvid" json:"gcv_id"`
	Password         string   `gorm:"type:varchar(255);not null" json:"password,omitempty"`
	Avatar           string   `gorm:"type:varchar(255)" json:"avatar"`
	GravatarID       string   `gorm:"type:varchar(255)" json:"gravatar_id"`
	ApplicationsSent int      `gorm:"type:int" json:"applications_sent"`
	PrimaryResume    Resume   `gorm:"foreignkey:User" json:"primary_resume"`
	AllResumes       []Resume `gorm:"foreignkey:User" json:"all_resumes"`
}

type Resume struct {
	gorm.Model
	User            uint   `gorm:"type:int;not null;index:idx_resume_by_user" json:"user"`
	File            string `gorm:"type:varchar(255);not null" json:"file"`
	TimesApplied    int    `gorm:"type:int" json:"times_applied"`
	TimesViewed     int    `gorm:"type:int" json:"times_viewed"`
	TimesDownloaded int    `gorm:"type:int" json:"times_downloaded"`
}
