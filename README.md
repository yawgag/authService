## About Project
This project provides a gRPC-based authentication and authorization service.  
It supports user registration, login, session management, token refresh, and role-based access control.

Key features:
- JWT-based authentication (access and refresh tokens)
- Role system with default and custom roles separation
- Secure password change and account management
- Token expiration and session tracking
- Admin functions for user and role management
- Pagination support for user listing
- Public RSA key exposure for token verification

> This service is designed to be used as part of a microservices architecture.


---------
## Table of Contents
- [Setup Instructions](#setup-instructions)
- [Methods](#methods)
  - [Register](#register)
  - [Login](#login)
  - [Logout](#logout)
  - [ChangePassword](#changepassword)
  - [ChangeEmail](#changeemail)
  - [UserDeleteAccount](#userdeleteaccount)
  - [UserLogoutAllSessions](#userlogoutallsessions)
  - [NewRole](#newrole)
  - [ChangeUserRole](#changeuserrole)
  - [AdminDeleteAccount](#admindeleteaccount)
  - [AdminLogoutUserSessions](#adminlogoutusersessions)
  - [UpdateTokens](#updatetokens)
  - [GetPublicRSAKey](#getpublicrsakey)
  - [GetUserData](#getuserdata)
  - [GetUsersList](#getuserslist)
- [Tokens](#tokens)
  - [Refresh token](#refresh-token)
  - [Access token](#access-token)
---------

## Setup Instructions

To run the authentication service using the provided `docker-compose.yml`, you need to prepare the following:

### Required environment variables for `auth-service`

You must provide these environment variables to configure the service correctly:

- `SERVER_ADDRESS` — the address and port where the gRPC server will listen. Example: `:50051`

- `DB_URL` — PostgreSQL connection string in the format: 
`postgres://<user>:<password>@<host>:<port>/<database>`  

- `PRIVATE_KEY` — Base64 encoded RSA private key used for signing JWT tokens.

- `PUBLIC_KEY` — Base64 encoded RSA public key used to verify JWT tokens.

### Database initialization

- The PostgreSQL database is initialized with the schema from `./docker/init.sql`.  

### Ports

- The gRPC auth service will be exposed on port `50051` (configurable via `SERVER_ADDRESS`).  
- The PostgreSQL service is exposed on port `5433` (mapped to container’s 5432).

### Running the services

Run the following command to build and start the services:

```bash
docker-compose up --build
```



## Methods
- `Register`
Returns **access and refresh tokens**.
This adds a new user to the database with the default role **"user"**.
                    
Variable  | Note
------------- | -------------
Email  | no validation, unique for users
Login  | no validation, unique for users
Password  | no validation 

- `Login` 
Returns **access and refresh tokens**.
                    
Variable  | Note
------------- | -------------
Login  | -
Password  | -

- `Logout` 
Deletes the user session that it takes from the refresh token.
                    
Variable  | Note
------------- | -------------
RefreshToken  | in the request metadata

- `ChangePassword` 
Change user password.
                    
Variable  | Note
------------- | -------------
AccessToken  | in the request metadata
oldPassword  | old user password
newPassword  | new user password

- `ChangeEmail` 
Change user email.
                    
Variable  | Note
------------- | -------------
AccessToken  | in the request metadata
Password  | old user password
newEmail  | new user password

- `UserDeleteAccount` 
Delete user account and all user sessions. An access token is required to identify the user.
                    
Variable  | Note
------------- | -------------
AccessToken  | in the request metadata
Password  | user password

- `UserLogoutAllSessions` 
Returns number of deleted sessions.
Delete all user sessions.
                    
Variable  | Note
------------- | -------------
AccessToken  | in the request metadata

- `NewRole` 
Add new users role to database.
Require **refresh token with admin role**.
> all roles are stored in lowercase letters. ROLE, role and rOlE is equal.
                    
Variable  | Note
------------- | -------------
RefreshToken  | in the request metadata
roleName  | new role name

- `ChangeUserRole` 
Change user role.
Require **refresh token with admin or moderator role**.
                    
Variable  | Note
------------- | -------------
RefreshToken  | in the request metadata
login  | -
roleName  | new user role

- `AdminDeleteAccount` 
Delete user account. An login requre to identify the user.
Require **refresh token with admin role**.
                    
Variable  | Note
------------- | -------------
RefreshToken  | in the request metadata
login  | -

- `AdminLogoutUserSessions` 
Delete all user sessions. An login requre to identify the user.
Require **refresh token with admin role**.
                    
Variable  | Note
------------- | -------------
RefreshToken  | in the request metadata
login  | -

- `UpdateTokens` 
Internal function to update user access token. 
                    
Variable  | Note
------------- | -------------
RefreshToken  | in the request metadata

- `GetPublicRSAKey`
Internal function to get public RSA key to decode jwt tokens. 
                    
Variable  | Note
------------- | -------------
--  | --

- `GetUserData` 
Returns all user info: uid, login, email, role.
                    
Variable  | Note
------------- | -------------
login  | -

- `GetUsersList` 
Uses pagination to return a page from the user database. 
                    
Variable  | Note
------------- | -------------
pageLimit | Number of users in response page
pageNumber | number of returned page. Starts from 1.
---------
## Tokens
### Refresh token
Used to update the access token.
It is stored in metadata as string with name **"refresh-token"**.
> The user's session is stored in the database for 30 days, after which it becomes invalid.

Inside token:
                    
Variable  | Note
------------- | -------------
sessionId  | UUID
exp  | UNIX time format
### Access token
Used to identify the user
It is stored in metadata as string with name **"authorization"** with **"Bearer "** prefix.
> It is valid for 15 minutes, after which it requires updating.

Inside token: 
                    
Variable  | Note
------------- | -------------
uid  | UUID
userRole  | String. Role name
exp | UNIX time format
