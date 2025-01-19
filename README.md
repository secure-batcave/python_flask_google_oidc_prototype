# PROTOTYPE: User Account Creation/Authentication with Google and Python Flask

This is a prototype Flask OAuth2.0/OpenID Connect (OIDC) Client/App.

## Install

Install the required dependencies:

    cd <project_directory>
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt

## Config

Create your own Google OAuth Client at <https://console.cloud.google.com/apis/credentials>, make sure to add `http://127.0.0.1:<port>/auth` into Authorized redirect URIs, where `<port>` is the port number you want to run the app on.

Create environment variables for FLASK_SECRET_KEY, USER_FOLDER_PATH, GOOGLE_CLIENT_ID, and GOOGLE_CLIENT_SECRET, see `config.py`.

## Run

Start server with:

    python3 app.py

Then visit:

    http://127.0.0.1:5000/

## Flow

1. User clicks login.
2. User redirected to Google for authentication. App provides a redirect URL (app_domain/auth) for Google to use to redirect the user on successful authentication.
3. User accepts giving permission for App to access public information of User's gmail account.
4. Google redirects the user using the redirect URL. Google also appends an Authorization Code at the end of the URL.
5. App uses the Authorization Code to retrieve ID Token (OIDC) and/or Access Token (OAuth2.0) from Google's server.
6. App retrieves Google's keys and validates the ID Token with the keys, then extracts the User's Email Address from the validated token.
7. If the User's Email Address exists in user database, provide the filepath to the User's personal folder.
8. If the User's Email Address does not exist in the user database, create a personal folder for them in database and provide the filepath.
