# github.com/globalcv/backend

globalcv Backend Routes

## Routes

<details>
<summary>`/oauth/*/github`</summary>

- [RequestID]()
- [RealIP]()
- [Logger]()
- [Recoverer]()
- [DefaultCompress]()
- [Timeout.func1]()
- **/oauth/***
	- **/github**
		- _POST_
			- [GitHubLogin]()

</details>
<details>
<summary>`/oauth/*/github/callback`</summary>

- [RequestID]()
- [RealIP]()
- [Logger]()
- [Recoverer]()
- [DefaultCompress]()
- [Timeout.func1]()
- **/oauth/***
	- **/github/callback**
		- _GET_
			- [(*API).GitHubCallback-fm]()

</details>
<details>
<summary>`/oauth/*/gitlab`</summary>

- [RequestID]()
- [RealIP]()
- [Logger]()
- [Recoverer]()
- [DefaultCompress]()
- [Timeout.func1]()
- **/oauth/***
	- **/gitlab**
		- _POST_
			- [GitLabLogin]()

</details>
<details>
<summary>`/oauth/*/linkedin`</summary>

- [RequestID]()
- [RealIP]()
- [Logger]()
- [Recoverer]()
- [DefaultCompress]()
- [Timeout.func1]()
- **/oauth/***
	- **/linkedin**
		- _POST_
			- [LinkedInLogin]()

</details>
<details>
<summary>`/resumes/*`</summary>

- [RequestID]()
- [RealIP]()
- [Logger]()
- [Recoverer]()
- [DefaultCompress]()
- [Timeout.func1]()
- **/resumes/***
	- **/**
		- _GET_
			- [(*API).listResumes-fm]()
		- _POST_
			- [github.com/ciehanski/go-jwt-middleware.(*JWTMiddleware).Handler-fm]()
			- [(*API).createResume-fm]()

</details>
<details>
<summary>`/resumes/*/{resumeID:[0-9]+}/*`</summary>

- [RequestID]()
- [RealIP]()
- [Logger]()
- [Recoverer]()
- [DefaultCompress]()
- [Timeout.func1]()
- **/resumes/***
	- **/{resumeID:[0-9]+}/***
		- **/**
			- _DELETE_
				- [github.com/ciehanski/go-jwt-middleware.(*JWTMiddleware).Handler-fm]()
				- [(*API).deleteResume-fm]()
			- _GET_
				- [github.com/ciehanski/go-jwt-middleware.(*JWTMiddleware).Handler-fm]()
				- [(*API).getResume-fm]()
			- _PATCH_
				- [github.com/ciehanski/go-jwt-middleware.(*JWTMiddleware).Handler-fm]()
				- [(*API).updateResume-fm]()

</details>
<details>
<summary>`/users/*`</summary>

- [RequestID]()
- [RealIP]()
- [Logger]()
- [Recoverer]()
- [DefaultCompress]()
- [Timeout.func1]()
- **/users/***
	- **/**
		- _GET_
			- [(*API).listUsers-fm]()
		- _POST_
			- [(*API).createUser-fm]()

</details>
<details>
<summary>`/users/*/login`</summary>

- [RequestID]()
- [RealIP]()
- [Logger]()
- [Recoverer]()
- [DefaultCompress]()
- [Timeout.func1]()
- **/users/***
	- **/login**
		- _POST_
			- [(*API).login-fm]()

</details>
<details>
<summary>`/users/*/logout`</summary>

- [RequestID]()
- [RealIP]()
- [Logger]()
- [Recoverer]()
- [DefaultCompress]()
- [Timeout.func1]()
- **/users/***
	- **/logout**
		- _POST_
			- [github.com/ciehanski/go-jwt-middleware.(*JWTMiddleware).Handler-fm]()
			- [(*API).logout-fm]()

</details>
<details>
<summary>`/users/*/{userID:[0-9]+}/*`</summary>

- [RequestID]()
- [RealIP]()
- [Logger]()
- [Recoverer]()
- [DefaultCompress]()
- [Timeout.func1]()
- **/users/***
	- **/{userID:[0-9]+}/***
		- **/**
			- _DELETE_
				- [github.com/ciehanski/go-jwt-middleware.(*JWTMiddleware).Handler-fm]()
				- [(*API).deleteUser-fm]()
			- _GET_
				- [(*API).getUserByID-fm]()
			- _PATCH_
				- [github.com/ciehanski/go-jwt-middleware.(*JWTMiddleware).Handler-fm]()
				- [(*API).updateUser-fm]()

</details>

Total # of routes: 10
