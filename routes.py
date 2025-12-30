from flask import Blueprint, request, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user
from models import db, AdminAccount, UserAccount, AuditLog, Employee, Patient
from datetime import datetime
from sqlalchemy import or_, and_, func

api = Blueprint('api', __name__, url_prefix='/api')

# =============================================
# UTILITY FUNCTIONS
# =============================================

def get_client_ip():
    """Get client IP address"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr or '127.0.0.1'

def log_audit(action, entity, details, user_obj=None):
    """Create audit log entry"""
    if user_obj is None:
        user_obj = current_user
    
    if not user_obj or not hasattr(user_obj, 'username'):
        return
    
    user_type = 'admin' if isinstance(user_obj, AdminAccount) else 'user'
    
    log = AuditLog(
        user_type=user_type,
        user_id=user_obj.id,
        username=user_obj.username,
        full_name=user_obj.full_name,
        action=action,
        entity=entity,
        details=details,
        ip_address=get_client_ip()
    )
    db.session.add(log)
    db.session.commit()

def requires_admin(f):
    """Decorator to require admin authentication"""
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not isinstance(current_user, AdminAccount):
            return jsonify({'status': 'error', 'message': 'Admin access required'}), 403
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# =============================================
# AUTHENTICATION ROUTES
# =============================================

@api.route('/login', methods=['POST'])
def login():
    """Handle login request"""
    data = request.get_json()
    
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    role = data.get('role', '').strip()
    
    if not username or not password or not role:
        return jsonify({
            'status': 'error',
            'message': 'Username, password, and role are required'
        }), 400
    
    user = None
    user_type = None
    
    # Check if it's an admin login (Head of Hospital can be admin or user)
    if role == 'Head of Hospital':
        # Check admin accounts first
        admin = AdminAccount.query.filter_by(username=username, is_active=True).first()
        
        if admin and admin.check_password(password):
            user = admin
            user_type = 'admin'
        else:
            # Also check user accounts for Head of Hospital role
            user_account = UserAccount.query.filter_by(
                username=username, 
                role='Head of Hospital',
                is_active=True
            ).first()
            
            if user_account and user_account.check_password(password):
                user = user_account
                user_type = 'user'
    else:
        # For other roles, check user accounts only
        user_account = UserAccount.query.filter_by(
            username=username,
            role=role,
            is_active=True
        ).first()
        
        if user_account and user_account.check_password(password):
            user = user_account
            user_type = 'user'
    
    if user:
        # Log the user in
        login_user(user, remember=True)
        
        # Store session data
        session['user_type'] = user_type
        session['user_role'] = role
        session['full_name'] = user.full_name
        session.permanent = True
        
        # Log the login action
        log_audit('LOGIN', 'System', f'User logged into {role} dashboard', user)
        
        # Determine redirect URL
        if user_type == 'admin':
            redirect_url = '/admin-dashboard'
        else:
            redirect_url = '/user-dashboard'
        
        return jsonify({
            'status': 'success',
            'message': 'Login successful',
            'user_type': user_type,
            'role': role,
            'full_name': user.full_name,
            'redirect': redirect_url
        }), 200
    else:
        return jsonify({
            'status': 'error',
            'message': 'Invalid username, password, or role'
        }), 401

@api.route('/logout', methods=['POST'])
@login_required
def logout():
    """Handle logout request"""
    # Log the logout action before logging out
    log_audit('LOGOUT', 'System', f'User logged out from {session.get("user_role", "Unknown")} dashboard')
    
    # Clear session
    session.clear()
    
    # Logout user
    logout_user()
    
    return jsonify({
        'status': 'success',
        'message': 'Logged out successfully',
        'redirect': '/IMS'
    }), 200

@api.route('/check-session')
def check_session():
    """Check if user is logged in"""
    if current_user.is_authenticated:
        return jsonify({
            'authenticated': True,
            'user_type': session.get('user_type'),
            'role': session.get('user_role'),
            'full_name': session.get('full_name')
        }), 200
    else:
        return jsonify({
            'authenticated': False
        }), 200

# =============================================
# ADMIN ACCOUNT ROUTES
# =============================================

@api.route('/admin/list', methods=['GET'])
@login_required
@requires_admin
def list_admins():
    """Get all admin accounts"""
    admins = AdminAccount.query.order_by(AdminAccount.id).all()
    return jsonify({
        'status': 'success',
        'data': [admin.to_dict() for admin in admins]
    }), 200

@api.route('/admin/create', methods=['POST'])
@login_required
@requires_admin
def create_admin():
    """Create new admin account"""
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    full_name = data.get('full_name', '').strip()
    
    if not username or not password or not full_name:
        return jsonify({'status': 'error', 'message': 'All fields are required'}), 400
    
    if len(password) < 6:
        return jsonify({'status': 'error', 'message': 'Password must be at least 6 characters'}), 400
    
    # Check if username exists
    if AdminAccount.query.filter_by(username=username).first():
        return jsonify({'status': 'error', 'message': 'Username already exists'}), 400
    
    # Create new admin
    admin = AdminAccount(
        username=username,
        full_name=full_name,
        role='Head of Hospital'
    )
    admin.set_password(password)
    
    db.session.add(admin)
    db.session.commit()
    
    log_audit('CREATE', 'Admin Account', f'Created admin account: {full_name}')
    
    return jsonify({
        'status': 'success',
        'message': 'Admin account created successfully',
        'data': admin.to_dict()
    }), 201

@api.route('/admin/update/<int:admin_id>', methods=['PUT'])
@login_required
@requires_admin
def update_admin(admin_id):
    """Update admin account"""
    admin = AdminAccount.query.get_or_404(admin_id)
    data = request.get_json()
    
    username = data.get('username', '').strip()
    full_name = data.get('full_name', '').strip()
    
    if not username or not full_name:
        return jsonify({'status': 'error', 'message': 'All fields are required'}), 400
    
    # Check if username is taken by another admin
    existing = AdminAccount.query.filter_by(username=username).first()
    if existing and existing.id != admin_id:
        return jsonify({'status': 'error', 'message': 'Username already exists'}), 400
    
    admin.username = username
    admin.full_name = full_name
    
    db.session.commit()
    
    log_audit('UPDATE', 'Admin Account', f'Updated admin account: {full_name}')
    
    return jsonify({
        'status': 'success',
        'message': 'Admin account updated successfully',
        'data': admin.to_dict()
    }), 200

@api.route('/admin/change-password', methods=['POST'])
@login_required
@requires_admin
def change_admin_password():
    """Change admin password"""
    data = request.get_json()
    
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')
    
    if not current_password or not new_password:
        return jsonify({'status': 'error', 'message': 'All fields are required'}), 400
    
    if len(new_password) < 6:
        return jsonify({'status': 'error', 'message': 'Password must be at least 6 characters'}), 400
    
    if not current_user.check_password(current_password):
        return jsonify({'status': 'error', 'message': 'Current password is incorrect'}), 400
    
    current_user.set_password(new_password)
    db.session.commit()
    
    log_audit('UPDATE', 'Admin Account', 'Changed admin password')
    
    return jsonify({
        'status': 'success',
        'message': 'Password updated successfully'
    }), 200

@api.route('/admin/delete/<int:admin_id>', methods=['DELETE'])
@login_required
@requires_admin
def delete_admin(admin_id):
    """Delete admin account"""
    if admin_id == 1:
        return jsonify({'status': 'error', 'message': 'Cannot delete default admin account'}), 400
    
    if admin_id == current_user.id:
        return jsonify({'status': 'error', 'message': 'Cannot delete your own account'}), 400
    
    admin = AdminAccount.query.get_or_404(admin_id)
    full_name = admin.full_name
    
    db.session.delete(admin)
    db.session.commit()
    
    log_audit('DELETE', 'Admin Account', f'Deleted admin account: {full_name}')
    
    return jsonify({
        'status': 'success',
        'message': 'Admin account deleted successfully'
    }), 200

@api.route('/current-user', methods=['GET'])
@login_required
def get_current_user():
    """Get current logged-in user information"""
    return jsonify({
        'status': 'success',
        'username': current_user.username,
        'full_name': current_user.full_name,
        'role': current_user.role if hasattr(current_user, 'role') else 'Admin'
    }), 200
    
# =============================================
# USER ACCOUNT ROUTES
# =============================================

@api.route('/user-account/list', methods=['GET'])
@login_required
@requires_admin
def list_user_accounts():
    """Get all user accounts"""
    users = UserAccount.query.order_by(UserAccount.id).all()
    return jsonify({
        'status': 'success',
        'data': [user.to_dict() for user in users]
    }), 200

@api.route('/user-account/create', methods=['POST'])
@login_required
@requires_admin
def create_user_account():
    """Create new user account"""
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    full_name = data.get('full_name', '').strip()
    role = data.get('role', '').strip()
    
    if not username or not password or not full_name or not role:
        return jsonify({'status': 'error', 'message': 'All fields are required'}), 400
    
    if len(password) < 6:
        return jsonify({'status': 'error', 'message': 'Password must be at least 6 characters'}), 400
    
    # Check if username exists
    if UserAccount.query.filter_by(username=username).first():
        return jsonify({'status': 'error', 'message': 'Username already exists'}), 400
    
    # Create new user account
    user = UserAccount(
        username=username,
        full_name=full_name,
        role=role,
        created_by=current_user.id
    )
    user.set_password(password)
    
    db.session.add(user)
    db.session.commit()
    
    log_audit('CREATE', 'User Account', f'Created user account: {full_name} ({role})')
    
    return jsonify({
        'status': 'success',
        'message': 'User account created successfully',
        'data': user.to_dict()
    }), 201

@api.route('/user-account/update/<int:user_id>', methods=['PUT'])
@login_required
@requires_admin
def update_user_account(user_id):
    """Update user account"""
    user = UserAccount.query.get_or_404(user_id)
    data = request.get_json()
    
    username = data.get('username', '').strip()
    full_name = data.get('full_name', '').strip()
    role = data.get('role', '').strip()
    
    if not username or not full_name or not role:
        return jsonify({'status': 'error', 'message': 'All fields are required'}), 400
    
    # Check if username is taken
    existing = UserAccount.query.filter_by(username=username).first()
    if existing and existing.id != user_id:
        return jsonify({'status': 'error', 'message': 'Username already exists'}), 400
    
    user.username = username
    user.full_name = full_name
    user.role = role
    
    db.session.commit()
    
    log_audit('UPDATE', 'User Account', f'Updated user account: {full_name}')
    
    return jsonify({
        'status': 'success',
        'message': 'User account updated successfully',
        'data': user.to_dict()
    }), 200

@api.route('/user-account/reset-password/<int:user_id>', methods=['POST'])
@login_required
@requires_admin
def reset_user_password(user_id):
    """Reset user password"""
    user = UserAccount.query.get_or_404(user_id)
    data = request.get_json()
    
    new_password = data.get('new_password', '').strip()
    
    if not new_password:
        return jsonify({'status': 'error', 'message': 'New password is required'}), 400
    
    if len(new_password) < 6:
        return jsonify({'status': 'error', 'message': 'Password must be at least 6 characters'}), 400
    
    user.set_password(new_password)
    db.session.commit()
    
    log_audit('UPDATE', 'User Account', f'Reset password for: {user.full_name}')
    
    return jsonify({
        'status': 'success',
        'message': 'Password reset successfully'
    }), 200

@api.route('/user-account/delete/<int:user_id>', methods=['DELETE'])
@login_required
@requires_admin
def delete_user_account(user_id):
    """Delete user account"""
    user = UserAccount.query.get_or_404(user_id)
    full_name = user.full_name
    
    db.session.delete(user)
    db.session.commit()
    
    log_audit('DELETE', 'User Account', f'Deleted user account: {full_name}')
    
    return jsonify({
        'status': 'success',
        'message': 'User account deleted successfully'
    }), 200

# =============================================
# EMPLOYEE ROUTES
# =============================================

@api.route('/employee/list', methods=['GET'])
@login_required
def list_employees():
    """Get all employees"""
    employees = Employee.query.order_by(Employee.id).all()
    return jsonify({
        'status': 'success',
        'data': [emp.to_dict() for emp in employees]
    }), 200

@api.route('/employee/create', methods=['POST'])
@login_required
@requires_admin
def create_employee():
    """Create new employee"""
    data = request.get_json()
    
    name = data.get('name', '').strip()
    email = data.get('email', '').strip()
    department = data.get('department', '').strip()
    role = data.get('role', '').strip()
    
    if not name or not email or not department or not role:
        return jsonify({'status': 'error', 'message': 'All fields are required'}), 400
    
    # Check if email exists
    if Employee.query.filter_by(email=email).first():
        return jsonify({'status': 'error', 'message': 'Email already exists'}), 400
    
    # Generate employee ID
    count = Employee.query.count() + 1
    emp_id = f'#EMP{str(count).zfill(3)}'
    
    employee = Employee(
        emp_id=emp_id,
        name=name,
        email=email,
        department=department,
        role=role,
        created_by=current_user.id
    )
    
    db.session.add(employee)
    db.session.commit()
    
    log_audit('CREATE', 'Employee', f'Created employee: {name}')
    
    return jsonify({
        'status': 'success',
        'message': 'Employee created successfully',
        'data': employee.to_dict()
    }), 201

# =============================================
# PATIENT ROUTES
# =============================================

@api.route('/patient/list', methods=['GET'])
@login_required
def list_patients():
    """Get all patients"""
    patients = Patient.query.order_by(Patient.id.desc()).all()
    return jsonify({
        'status': 'success',
        'data': [patient.to_dict() for patient in patients]
    }), 200

# =============================================
# AUDIT LOG ROUTES
# =============================================

@api.route('/audit-logs', methods=['GET'])
@login_required
@requires_admin
def get_audit_logs():
    """Get audit logs with filters"""
    # Get query parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    action_filter = request.args.get('action', None)
    date_filter = request.args.get('date', None)
    search = request.args.get('search', None)
    
    # Build query
    query = AuditLog.query
    
    if action_filter:
        query = query.filter(AuditLog.action == action_filter.upper())
    
    if date_filter:
        try:
            date_obj = datetime.strptime(date_filter, '%Y-%m-%d')
            query = query.filter(func.date(AuditLog.timestamp) == date_obj.date())
        except ValueError:
            pass
    
    if search:
        query = query.filter(
            or_(
                AuditLog.username.ilike(f'%{search}%'),
                AuditLog.full_name.ilike(f'%{search}%'),
                AuditLog.details.ilike(f'%{search}%')
            )
        )
    
    query = query.order_by(AuditLog.timestamp.desc())
    
    # Paginate
    logs = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'status': 'success',
        'data': [log.to_dict() for log in logs.items],
        'pagination': {
            'page': logs.page,
            'per_page': logs.per_page,
            'total': logs.total,
            'pages': logs.pages
        }
    }), 200

# =============================================
# DASHBOARD STATS
# =============================================

@api.route('/stats/dashboard', methods=['GET'])
@login_required
@requires_admin
def get_dashboard_stats():
    """Get dashboard statistics"""
    total_employees = Employee.query.filter_by(status='Active').count()
    total_patients = Patient.query.filter_by(status='Active').count()
    total_admins = AdminAccount.query.filter_by(is_active=True).count()
    total_users = UserAccount.query.filter_by(is_active=True).count()
    
    # Recent activity (last 10 logs)
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
    
    return jsonify({
        'status': 'success',
        'data': {
            'total_employees': total_employees,
            'total_patients': total_patients,
            'total_admins': total_admins,
            'total_users': total_users,
            'recent_activity': [log.to_dict() for log in recent_logs]
        }
    }), 200