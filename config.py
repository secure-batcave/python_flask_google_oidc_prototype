import os

# Instructions to set environment variables:
# 1. Create a new file called '.env' in the root directory of the project
# 2. Add the following lines to the file:
#    FLASK_SECRET_KEY=<your_secret_key>
#    USER_FOLDER_PATH=<your_user_folder_path>
#    GOOGLE_CLIENT_ID=<your_client_id>
#    GOOGLE_CLIENT_SECRET=<your_client_secret>
# 3. Replace <your_secret_key>, <your_user_folder_path>, <your_client_id>, and <your_client_secret> with your actual values
# 4. Run the application

# Flask Secret Key
SECRET_KEY = os.getenv('FLASK_SECRET_KEY', os.urandom(24))

# User Folder Path
USER_FOLDER_PATH = os.getenv('USER_FOLDER_PATH', 'user_folders')

# Create your own Google OAuth Client ID and Secret at https://console.cloud.google.com/apis/credentials
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
    raise ValueError("Google OAuth credentials are not set.")


# Use Proxy Fix for reverse proxy setups (if hosting behind Nginx, etc.)
USE_PROXY_FIX = False
PROXY_FIX_SETTINGS = {
    'X_FORWARDED_FOR': 1,
    'X_FORWARDED_HOST': 1,
    'X_FORWARDED_PROTO': 1,
    'X_FORWARDED_PORT': 1
}
# X_FORWARDED_FOR: 1 uses the first value in the X-Forwarded-For header as the client's IP
# X_FORWARDED_HOST: 1 trusts the X-Forwarded-Host header for the original host
# X_FORWARDED_PROTO: 1 trusts the X-Forwarded-Proto header to determine HTTP or HTTPS
# X_FORWARDED_PORT: 1 trusts the X-Forwarded-Port header for the original port


# Cookie Security Settings
##########################

# Cookies require HTTPS, only enable if HTTPS is configured
# Protects against MITM attacks
#SESSION_COOKIE_SECURE = True

# Prevent JavaScript running in the browser from accessing the session cookie
# Protects against XSS attacks
SESSION_COOKIE_HTTPONLY = True

# Controls whether the session cookie is sent with cross-site requests
# Protects against CSRF attacks
SESSION_COOKIE_SAMESITE = 'Lax'

# Rate Limit Settings
##########################

# Default rate limit for all routes
DEFAULT_RATE_LIMIT = "100 per minute"

# Rate limit for login route
LOGIN_RATE_LIMIT = "10 per minute"

# Rate limit for auth route
AUTH_RATE_LIMIT = "10 per minute"