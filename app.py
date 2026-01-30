from flask import Flask, render_template, redirect, url_for, session
from flask_login import LoginManager, current_user
from models import db, init_db, AdminAccount, UserAccount, WebsiteUser
from routes import api
from datetime import timedelta

app = Flask(__name__)


# CONFIGURATION
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


# FLASK-LOGIN SETUP (IMS ONLY)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_page'
login_manager.login_message = 'Please log in to access this page.'

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login - IMS ONLY"""
    # Only handle IMS users (Admin and Staff)
    if user_id.startswith('admin_'):
        admin_id = int(user_id.split('_')[1])
        return db.session.get(AdminAccount, admin_id)
    elif user_id.startswith('user_'):
        uid = int(user_id.split('_')[1])
        return db.session.get(UserAccount, uid)
    return None


# CUSTOM WEBSITE USER AUTHENTICATION HELPER
def get_website_user():
    """Get current website user from manual session"""
    website_user_id = session.get('website_user_id')
    if website_user_id:
        return db.session.get(WebsiteUser, website_user_id)
    return None

def is_website_user_authenticated():
    """Check if website user is authenticated"""
    return session.get('website_user_id') is not None


# DATABASE INITIALIZATION
init_db(app)
app.register_blueprint(api)


# MAIN ROUTES
@app.route('/')
def index():
    """Redirect to appropriate page based on authentication"""
    # Check IMS authentication (Flask-Login)
    if current_user.is_authenticated:
        if isinstance(current_user, AdminAccount):
            return redirect(url_for('admin_dashboard'))
        elif isinstance(current_user, UserAccount):
            return redirect(url_for('user_dashboard'))
    
    # Check Website authentication (Manual Session)
    if is_website_user_authenticated():
        return redirect(url_for('website_user'))
    
    # Default: redirect to IMS login
    return redirect(url_for('login_page'))


# ============================================
# IMS AUTHENTICATION ROUTES (Flask-Login)
# ============================================

@app.route('/IMS')
@app.route('/system-login')
def login_page():
    """Display IMS login page"""
    # If already logged in via IMS, redirect to dashboard
    if current_user.is_authenticated:
        if isinstance(current_user, AdminAccount):
            return redirect(url_for('admin_dashboard'))
        elif isinstance(current_user, UserAccount):
            return redirect(url_for('user_dashboard'))
    
    return render_template('system-login.html')


# ============================================
# IMS DASHBOARD ROUTES
# ============================================

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
    role_templates = {
        'Business Office': 'business-office.html',
        'Laboratory': 'laboratory.html',
        'Front Desk': 'front-desk.html',
        'Doctor': 'doctor.html',
        'Pharmacy': 'pharmacy.html',
        'Nurse': 'nurse.html',
        'Head of Hospital': 'user-head.html'
    }
    
    template = role_templates.get(role)
    if template:
        return render_template(template, user=current_user)
    else:
        return redirect(url_for('login_page'))


# ============================================
# WEBSITE AUTHENTICATION ROUTES (Manual Session)
# ============================================

@app.route('/website')
def website():
    """Public website - accessible to everyone"""
    return render_template('website.html')


@app.route('/website/login')
def website_login():
    """Website login page"""
    # If already logged in as website user, redirect to portal
    if is_website_user_authenticated():
        return redirect(url_for('website_user'))
    
    return render_template('website-login.html')


@app.route('/website/user-portal')
def website_user():
    """Website user portal - requires website authentication"""
    if not is_website_user_authenticated():
        return redirect(url_for('website_login'))
    
    user = get_website_user()
    if not user:
        # Session exists but user not found - clear session
        session.pop('website_user_id', None)
        return redirect(url_for('website_login'))
    
    return render_template('user-portal.html', user=user)


# ============================================
# ERROR HANDLERS
# ============================================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    db.session.rollback()
    return render_template('500.html'), 500


# ============================================
# CONTEXT PROCESSORS
# ============================================

@app.context_processor
def inject_user():
    """Make current_user (IMS) and website_user available in all templates"""
    return dict(
        current_user=current_user,
        website_user=get_website_user(),
        is_website_authenticated=is_website_user_authenticated()
    )


@app.context_processor
def inject_user_info():
    """Inject user information for templates"""
    user_info = {
        'full_name': 'Guest',
        'username': '',
        'role': '',
        'auth_type': None
    }
    
    # Check IMS authentication (Flask-Login)
    if current_user.is_authenticated:
        user_info['full_name'] = current_user.full_name
        user_info['username'] = current_user.username
        user_info['auth_type'] = 'ims'
        
        if isinstance(current_user, AdminAccount):
            user_info['role'] = 'Admin'
        elif isinstance(current_user, UserAccount):
            user_info['role'] = current_user.role
    
    # Check Website authentication (Manual Session)
    elif is_website_user_authenticated():
        user = get_website_user()
        if user:
            user_info['full_name'] = user.full_name
            user_info['username'] = user.username
            user_info['role'] = 'Website User'
            user_info['auth_type'] = 'website'
    
    return dict(user_info=user_info)


# RUN APPLICATION
if __name__ == '__main__':
    print("\n" + "="*60)
    print("🏥 HOSPITAL MANAGEMENT SYSTEM")
    print("="*60)
    print("\n📍 Access Points:")
    print("   • IMS (Management)  → http://127.0.0.1:5000/IMS")
    print("   • Public Website    → http://127.0.0.1:5000/website")
    print("\n🔐 Default Admin Login (IMS):")
    print("   Username: admin")
    print("   Password: admin123")
    
    app.run(debug=True, host='0.0.0.0', port=5000)