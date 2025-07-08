from flask import Flask, request, redirect, url_for, session, render_template
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
# Ensure you have a strong, secret key for session management
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db' # SQLite database file
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Database Model ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# --- Database Initialization (for development/first run) ---
@app.before_request
def create_tables():
    with app.app_context():
        db.create_all() # Creates tables if they don't exist

        # Add a default user if none exists (for easy testing)
        if not User.query.filter_by(username='testuser').first():
            new_user = User(username='testuser')
            new_user.set_password('password123') # VERY IMPORTANT: Change this for production!
            db.session.add(new_user)
            db.session.commit()
            print("Added default user: 'aonehospitalitys@gmail.com' with password 'mansoor786'")

# --- Routes ---

@app.route('/')
def index():
    # If the user is logged in, redirect to dashboard, otherwise to login
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session['username'] = user.username # Store username in session
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid username or password. Please try again.'
            # Re-render the login page with an error message
            return render_template('login.html', error=error)
    else:
        # If already logged in, redirect to dashboard
        if 'username' in session:
            return redirect(url_for('dashboard'))
        # Otherwise, serve the empty login form
        return render_template('login.html', error=error)

@app.route('/dashboard')
def dashboard():
    # Check if user is logged in
    if 'username' in session:
        # Pass the username to the dashboard template
        return render_template('dashboard.html', username=session['username'])
    else:
        # If not logged in, redirect to login page
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('username', None) # Remove username from session
    return redirect(url_for('login')) # Redirect to login page

if __name__ == '__main__':
    # For production, set debug=False and use a production-ready WSGI server like Gunicorn or uWSGI
    app.run(debug=True)
