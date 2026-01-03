from flask import Flask, render_template, redirect, url_for
from flask_login import LoginManager, current_user
from models import db, init_db, AdminAccount, UserAccount
from routes import api
from datetime import timedelta

app = Flask(__name__)

# =============================================
# CONFIGURATION
# =============================================

# PostgreSQL Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:admin123@localhost:5432/flask_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
}

# Secret key for session management
app.secret_key = "12345678"  # Change this to a random secret key in production

# Session configuration
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# =============================================
# FLASK-LOGIN SETUP
# =============================================

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_page'
login_manager.login_message = 'Please log in to access this page.'

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login"""
    if user_id.startswith('admin_'):
        admin_id = int(user_id.split('_')[1])
        return AdminAccount.query.get(admin_id)
    elif user_id.startswith('user_'):
        user_id = int(user_id.split('_')[1])
        return UserAccount.query.get(user_id)
    return None

# =============================================
# DATABASE INITIALIZATION
# =============================================

# Initialize database
init_db(app)

# Register API blueprint
app.register_blueprint(api)

# =============================================
# MAIN ROUTES
# =============================================

@app.route('/')
def index():
    """Redirect to appropriate page based on authentication"""
    if current_user.is_authenticated:
        if isinstance(current_user, AdminAccount):
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    return redirect(url_for('login_page'))

# =============================================
# LOGIN ROUTES
# =============================================

@app.route('/IMS')
@app.route('/system-login')
def login_page():
    """Display login page"""
    # If already logged in, redirect to appropriate dashboard
    if current_user.is_authenticated:
        if isinstance(current_user, AdminAccount):
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    
    return render_template('system-login.html')

# =============================================
# DASHBOARD ROUTES
# =============================================

@app.route('/admin-dashboard')
def admin_dashboard():
    """Admin dashboard - only accessible by admin accounts"""
    if not current_user.is_authenticated:
        return redirect(url_for('login_page'))
    
    if not isinstance(current_user, AdminAccount):
        return redirect(url_for('login_page'))
    
    return render_template('admin.html', user=current_user)

@app.route('/user-dashboard')
def user_dashboard():
    """User dashboard - accessible by user accounts based on their role"""
    if not current_user.is_authenticated:
        return redirect(url_for('login_page'))
    
    if not isinstance(current_user, UserAccount):
        return redirect(url_for('login_page'))
    
    role = current_user.role
    
    # Route to appropriate dashboard based on role
    if role == 'Business Office':
        return render_template('business-office.html', user=current_user)
    elif role == 'Laboratory':
        return render_template('laboratory.html', user=current_user)
    elif role == 'Pharmacy':
        return render_template('pharmacy.html', user=current_user)
    elif role == 'Nurse':
        return render_template('nurse.html', user=current_user)
    elif role == 'Head of Hospital':
        return render_template('user-head.html', user=current_user)
    else:
        return redirect(url_for('login_page'))

# =============================================
# PUBLIC WEBSITE ROUTES (Optional)
# =============================================

@app.route('/website')
def website():
    """Public website"""
    return render_template('website.html')

@app.route('/website/login')
def website_login():
    """Website login page"""
    return render_template('website-login.html')

@app.route('/website/user-portal')
def website_user():
    """Website user portal"""
    return render_template('user-portal.html')

# =============================================
# ERROR HANDLERS
# =============================================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    db.session.rollback()
    return render_template('500.html'), 500

# =============================================
# CONTEXT PROCESSORS
# =============================================
@app.context_processor
def inject_user():
    """Make current_user available in all templates"""
    return dict(current_user=current_user)

@app.context_processor
def inject_user_info():
    """Inject user information for templates"""
    user_info = {
        'full_name': 'Guest',
        'username': '',
        'role': ''
    }
    
    if current_user.is_authenticated:
        user_info['full_name'] = current_user.full_name
        user_info['username'] = current_user.username
        if isinstance(current_user, AdminAccount):
            user_info['role'] = 'Admin'
        elif isinstance(current_user, UserAccount):
            user_info['role'] = current_user.role
    
    return dict(user_info=user_info)
# =============================================
# RUN APPLICATION
# =============================================

if __name__ == '__main__':
    print("\n📍 Access Points:")
    print("   • Management System → http://127.0.0.1:5000/IMS")
    print("   • Public Website   → http://127.0.0.1:5000/website")
    
    
    app.run(debug=True, host='0.0.0.0', port=5000)