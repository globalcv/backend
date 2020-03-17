package globalcv

import (
	"fmt"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

func (a *API) createUserTable() error {
	schema := `
		-- Table: public.users

		-- DROP TABLE public.users;
		
		CREATE TABLE public.users
		(
			id integer NOT NULL DEFAULT nextval('users_id_seq'::regclass),
			github_login boolean,
			gitlab_login boolean,
			linkedin_login boolean,
			email_login boolean,
			email character varying(255) COLLATE pg_catalog."default" NOT NULL,
			email_confirmed boolean,
			gcv_id character varying(255) COLLATE pg_catalog."default" NOT NULL,
			password character varying(255) COLLATE pg_catalog."default" NOT NULL,
			avatar character varying(255) COLLATE pg_catalog."default",
			gravatar_id character varying(255) COLLATE pg_catalog."default",
			applications_sent integer,
			created_at timestamp with time zone,
			updated_at timestamp with time zone,
			deleted_at timestamp with time zone,
			CONSTRAINT users_pkey PRIMARY KEY (id),
			CONSTRAINT users_email_key UNIQUE (email),
			CONSTRAINT users_gcv_id_key UNIQUE (gcv_id)
		)
		WITH (
			OIDS = FALSE
		)
		TABLESPACE pg_default;
		
		ALTER TABLE public.users
			OWNER to globalcv;
		-- Index: idx_user_by_email
		
		-- DROP INDEX public.idx_user_by_email;
		
		CREATE UNIQUE INDEX idx_user_by_email
			ON public.users USING btree
			(email COLLATE pg_catalog."default" ASC NULLS LAST)
			TABLESPACE pg_default;
		-- Index: idx_user_by_gcvid
		
		-- DROP INDEX public.idx_user_by_gcvid;
		
		CREATE UNIQUE INDEX idx_user_by_gcvid
			ON public.users USING btree
			(gcv_id COLLATE pg_catalog."default" ASC NULLS LAST)
			TABLESPACE pg_default;
		-- Index: idx_users_deleted_at
		
		-- DROP INDEX public.idx_users_deleted_at;
		
		CREATE INDEX idx_users_deleted_at
			ON public.users USING btree
			(deleted_at ASC NULLS LAST)
			TABLESPACE pg_default;`

	_, err := a.DB.Exec(schema)
	if err != nil {
		return err
	}
	return nil
}

func (a *API) createResumeTable() error {
	schema := `
		-- Table: public.resumes

		-- DROP TABLE public.resumes;
		
		CREATE TABLE IF NOT EXISTS public.resumes
		(
			id integer NOT NULL DEFAULT nextval('resumes_id_seq'::regclass),
			"user" integer NOT NULL,
			file character varying(255) COLLATE pg_catalog."default" NOT NULL,
			times_applied integer,
			times_viewed integer,
			times_downloaded integer,
			created_at timestamp with time zone,
			updated_at timestamp with time zone,
			deleted_at timestamp with time zone,
			CONSTRAINT resumes_pkey PRIMARY KEY (id)
		)
		WITH (
			OIDS = FALSE
		)
		TABLESPACE pg_default;
		
		ALTER TABLE public.resumes
			OWNER to globalcv;
		-- Index: idx_resume_by_user
		
		-- DROP INDEX public.idx_resume_by_user;
		
		CREATE INDEX idx_resume_by_user
			ON public.resumes USING btree
			("user" ASC NULLS LAST)
			TABLESPACE pg_default;
		-- Index: idx_resumes_deleted_at
		
		-- DROP INDEX public.idx_resumes_deleted_at;
		
		CREATE INDEX idx_resumes_deleted_at
			ON public.resumes USING btree
			(deleted_at ASC NULLS LAST)
			TABLESPACE pg_default;`

	_, err := a.DB.Exec(schema)
	if err != nil {
		return err
	}
	return nil
}

func (a *API) createNotificationTable() error {
	schema := `
		-- Table: public.notifications

		-- DROP TABLE public.notifications;
		
		CREATE TABLE IF NOT EXISTS public.notifications
		(
			id integer NOT NULL DEFAULT nextval('notifications_id_seq'::regclass),
			"user" integer NOT NULL,
			message character varying(255) COLLATE pg_catalog."default" NOT NULL,
			created_at timestamp with time zone,
			updated_at timestamp with time zone,
			deleted_at timestamp with time zone,
			CONSTRAINT notifications_pkey PRIMARY KEY (id)
		)
		WITH (
			OIDS = FALSE
		)
		TABLESPACE pg_default;
		
		ALTER TABLE public.notifications
			OWNER to globalcv;
		-- Index: idx_notification_by_user
		
		-- DROP INDEX public.idx_notification_by_user;
		
		CREATE INDEX idx_notification_by_user
			ON public.notifications USING btree
			("user" ASC NULLS LAST)
			TABLESPACE pg_default;
		-- Index: idx_notifications_deleted_at
		
		-- DROP INDEX public.idx_notifications_deleted_at;
		
		CREATE INDEX idx_notifications_deleted_at
			ON public.notifications USING btree
			(deleted_at ASC NULLS LAST)
			TABLESPACE pg_default;`

	_, err := a.DB.Exec(schema)
	if err != nil {
		return err
	}
	return nil
}

func (a *API) initDB() error {
	var err error
	t := "host=%s port=%s user=%s password=%s dbname=%s sslmode=disable"
	conn := fmt.Sprintf(t, a.Options.DBhost, a.Options.DBport, a.Options.DBuser, a.Options.DBpass, a.Options.DBname)
	a.DB, err = sqlx.Connect("postgres", conn)
	if err != nil {
		return fmt.Errorf("database initialization error: %v", err)
	}

	// Enable pooling
	// ref: https://github.com/jinzhu/gorm/issues/246
	//a.DB.SetMaxIdleConns(0)
	//a.DB.SetMaxOpenConns(0)

	// Create tables
	if err := a.createUserTable(); err != nil {
		return err
	}
	if err := a.createResumeTable(); err != nil {
		return err
	}
	if err := a.createNotificationTable(); err != nil {
		return err
	}
	return nil
}
