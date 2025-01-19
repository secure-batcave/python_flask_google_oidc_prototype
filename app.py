import os, hashlib

from flask import Flask, url_for, session, render_template, redirect, flash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from authlib.integrations.flask_client import OAuth
from authlib.jose import jwt, JsonWebKey
from authlib.jose.errors import JoseError
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.config.from_object('config')


# Fix for reverse proxy setups (if hosting behind Nginx, etc.)
# Disabled by default
if app.config.get('USE_PROXY_FIX'):
    proxy_settings = app.config.get('PROXY_FIX_SETTINGS', {})
    app.wsgi_app = ProxyFix(app.wsgi_app, **proxy_settings)


# Initialize Flask-Limiter
# Implement storage backend for production use
limiter = Limiter(
    get_remote_address,  # Use client's IP as the identifier
    app=app,             # Attach to your Flask app
    default_limits=[app.config['DEFAULT_RATE_LIMIT']],  # Default rate limit from config
)


# Content Security Policy (CSP)
# Protects against XSS attacks
# Disable if your app relies on:
# Third-party libraries other than Google APIs.
# Inline styles (e.g., dynamically generated CSS).
# External APIs for AJAX requests or WebSocket connections.
@app.after_request
def set_csp(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://apis.google.com; "
    )
    return response


# Google OAuth Configuration
CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'
oauth = OAuth(app)

oauth.register(
    name='google',
    server_metadata_url=CONF_URL,
    client_kwargs={'scope': 'openid email'}
)


# A simple in-memory datastore for demonstration purposes
# Replace with database or persistent storage in production
user_datastore = {}

def validate_token(token):
    try:
        jwks_url = oauth.google.load_server_metadata().get('jwks_uri')
        jwks = JsonWebKey.import_key_set(oauth.google.get(jwks_url).json())
        claims = jwt.decode(token['id_token'], jwks)
        # Add leeway to avoid token time validation issues
        claims.validate(leeway=300)  # 300 seconds = 5 minutes

        if claims.get('aud') != app.config['GOOGLE_CLIENT_ID']:
            raise JoseError("Invalid token audience.")

        return claims
    except JoseError as e:
        app.logger.error(f"Token validation failed: {e}")
        raise e

def get_user_folder(email):
    folder_name = hashlib.sha256(email.encode()).hexdigest()
    folder_path = os.path.join(app.config['USER_FOLDER_PATH'], folder_name)
    os.makedirs(folder_path, exist_ok=True)
    return folder_path

def update_user_file(folder_path, email):
    file_path = os.path.join(folder_path, 'user_data.txt')
    count = 1
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r') as file:
                for line in file:
                    if "You have logged in" in line:
                        count = int(line.split()[-2]) + 1
                        break
        except (IndexError, ValueError):
            count = 1
    with open(file_path, 'w') as file:
        file.write(f"Hello world, {email}\n")
        file.write(f"You have logged in {count} times.\n")
    return file_path


# Flask Routes
@app.route('/')
def homepage():
    user_id = session.get('user_id')
    if not user_id:
        return render_template('home.html', user=None, message='')
    user = user_datastore.get(user_id)
    message = user.get('message', '') if user else ''
    return render_template('home.html', user=user, message=message)

@app.route('/login')
@limiter.limit(app.config['LOGIN_RATE_LIMIT'])  # Login rate limit from config
def login():
    redirect_uri = url_for('auth', _external=True)
    return oauth.google.authorize_redirect(
        redirect_uri,
        prompt="select_account"  # Force account selection
    )

@app.route('/auth')
@limiter.limit(app.config['AUTH_RATE_LIMIT'])  # Auth rate limit from config
def auth():
    try:
        token = oauth.google.authorize_access_token()
        claims = validate_token(token)
        email = claims['email']
        folder_path = get_user_folder(email)

        # User file manipulation for testing
        user_file = update_user_file(folder_path, email)
        with open(user_file, 'r') as file:
            message = file.read()
        
        # Store user in datastore and session
        user_id = hashlib.sha256(email.encode()).hexdigest()
        user_datastore[user_id] = {'email': email, 'message': message}
        session['user_id'] = user_id
        
        return redirect('/')
    except (JoseError, KeyError):
        flash('Authentication failed. Please try again.')
        return redirect('/login')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect('/')


if __name__ == "__main__":
    app.run(debug=True, port=5000, host="0.0.0.0")