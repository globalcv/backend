package globalcv

import (
	"log"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	"github.com/jinzhu/gorm"
)

type API struct {
	Options Options
}

type Options struct {
	Addr         string
	Server       *http.Server
	Router       chi.Router
	DB           *gorm.DB
	Logger       *log.Logger
	DBname       string
	DBhost       string
	DBuser       string
	DBpass       string
	DBssl        string
	JWTSecret    string
	JWTTokenAuth *jwtauth.JWTAuth
	Debug        bool
}

type User struct {
	gorm.Model
	Email          string   `gorm:"type:varchar(255);not null;unique;unique_index:idx_user_by_email" json:"email"`
	EmailConfirmed bool     `gorm:"type:boolean" json:"email_confirmed"`
	Password       string   `gorm:"type:varchar(255);not null" json:"password,omitempty"`
	Avatar         string   `gorm:"type:varchar(255);not null" json:"avatar"`
	PrimaryResume  Resume   `gorm:"foreignkey:User" json:"primary_resume"`
	AllResumes     []Resume `gorm:"foreignkey:User" json:"all_resumes"`
}

type Resume struct {
	gorm.Model
	User uint   `gorm:"type:int;not null;index:idx_resume_by_user" json:"user"`
	File string `gorm:"type:varchar(255);not null" json:"file"`
}
