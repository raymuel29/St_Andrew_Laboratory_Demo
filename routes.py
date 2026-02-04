from flask import Blueprint, request, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user
from models import db, AdminAccount, UserAccount, AuditLog, Employee, Patient, InventoryProduct, InventoryTransaction, PharmacySale, PharmacySaleItem, WebsiteUser, Appointment, Message, HospitalService, ServiceUsageRecord, ServicePriceHistory, PatientAdmission
from datetime import datetime, timedelta
from decimal import Decimal
from sqlalchemy import or_, and_, func

api = Blueprint('api', __name__, url_prefix='/api')


# UTILITY FUNCTIONS
def get_client_ip():
    """Get client IP address"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr or '127.0.0.1'


def log_audit(action, entity, details):
    """Log audit trail - IMS ONLY (Admin & Staff users)"""
    try:
        # Only log if user is authenticated via Flask-Login (IMS users only)
        if not current_user.is_authenticated:
            return  # Don't log if not IMS user
        
        # Determine user_type based on current_user type
        if isinstance(current_user, AdminAccount):
            user_type = 'admin'
        elif isinstance(current_user, UserAccount):
            user_type = 'user'
        else:
            return  # Don't log if not Admin or UserAccount
        
        audit_log = AuditLog(
            user_type=user_type,
            user_id=current_user.id,
            username=current_user.username,
            full_name=current_user.full_name,
            action=action,  # CREATE, UPDATE, DELETE, LOGIN, LOGOUT
            entity=entity,  # Patient, Admin Account, User Account, System, etc.
            details=details,
            ip_address=get_client_ip()
        )
        db.session.add(audit_log)
        db.session.commit()
    except Exception as e:
        print(f"Error logging audit: {str(e)}")
        db.session.rollback()


def requires_admin(f):
    """Decorator to require admin authentication"""
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not isinstance(current_user, AdminAccount):
            return jsonify({'status': 'error', 'message': 'Admin access required'}), 403
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function


def requires_website_user(f):
    """Decorator to require website user authentication"""
    def decorated_function(*args, **kwargs):
        website_user_id = session.get('website_user_id')
        if not website_user_id:
            return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
        
        user = db.session.get(WebsiteUser, website_user_id)
        if not user:
            session.pop('website_user_id', None)
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
        
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function


# AUTHENTICATION ROUTES
@api.route('/login', methods=['POST'])
def login():
    """Handle IMS login request (Admin & Staff)"""
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
    
    # Check if it's an admin login
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
        # Log the user in using Flask-Login
        login_user(user, remember=True)
        
        # Store session data
        session['user_type'] = user_type
        session['user_role'] = role
        session['full_name'] = user.full_name
        session.permanent = True
        
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
    """Handle IMS logout request"""
    # Clear session
    session.clear()
    
    # Logout user via Flask-Login
    logout_user()
    
    return jsonify({
        'status': 'success',
        'message': 'Logged out successfully',
        'redirect': '/IMS'
    }), 200


@api.route('/check-session')
def check_session():
    """Check if user is logged in (IMS)"""
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


# ADMIN ACCOUNT ROUTES
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


# USER ACCOUNT ROUTES
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


# EMPLOYEE ROUTES
@api.route('/employee/list', methods=['GET'])
@login_required
def list_employees():
    """Get all active employees, supports ?search= and ?department="""
    try:
        search     = request.args.get('search', '').strip().lower()
        department = request.args.get('department', '').strip()

        query = Employee.query.filter_by(status='Active')

        if department:
            query = query.filter(Employee.department == department)

        if search:
            query = query.filter(
                or_(
                    Employee.name.ilike(f'%{search}%'),
                    Employee.email.ilike(f'%{search}%'),
                    Employee.department.ilike(f'%{search}%'),
                    Employee.gender.ilike(f'%{search}%')
                )
            )

        employees = query.order_by(Employee.name.asc()).all()

        return jsonify({
            'status': 'success',
            'data': [emp.to_dict() for emp in employees]
        }), 200

    except Exception as e:
        print(f"Error listing employees: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch employees'
        }), 500


@api.route('/employee/create', methods=['POST'])
@login_required
@requires_admin
def create_employee():
    """Create new employee"""
    try:
        data = request.get_json()

        name           = data.get('name', '').strip()
        gender         = data.get('gender', '').strip()
        email          = data.get('email', '').strip().lower()
        contact_number = data.get('contact_number', '').strip()  # ADD THIS
        address        = data.get('address', '').strip()         # ADD THIS
        department     = data.get('department', '').strip()

        # ── validation ──────────────────────────────────
        if not name or not gender or not email or not department:
            return jsonify({
                'status': 'error',
                'message': 'All required fields must be filled (Name, Gender, Email, Department)'
            }), 400

        if gender not in ('Male', 'Female'):
            return jsonify({
                'status': 'error',
                'message': 'Gender must be Male or Female'
            }), 400

        if Employee.query.filter_by(email=email).first():
            return jsonify({
                'status': 'error',
                'message': 'An employee with this email already exists'
            }), 400

        # ── create record ───────────────────────────────
        employee = Employee(
            name=name,
            gender=gender,
            email=email,
            contact_number=contact_number if contact_number else None,  # ADD THIS
            address=address if address else None,                       # ADD THIS
            department=department,
            status='Active',
            created_by=current_user.id
        )

        db.session.add(employee)
        db.session.commit()

        log_audit('CREATE', 'Employee', f'Created employee: {name} ({department})')

        return jsonify({
            'status': 'success',
            'message': 'Employee added successfully',
            'data': employee.to_dict()
        }), 201

    except Exception as e:
        db.session.rollback()
        print(f"Error creating employee: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to create employee. Please try again.'
        }), 500


@api.route('/employee/update/<int:employee_id>', methods=['PUT'])
@login_required
@requires_admin
def update_employee(employee_id):
    """Update employee details"""
    try:
        employee = Employee.query.get_or_404(employee_id)
        data = request.get_json()

        name           = data.get('name', '').strip()
        gender         = data.get('gender', '').strip()
        email          = data.get('email', '').strip().lower()
        contact_number = data.get('contact_number', '').strip()  # ADD THIS
        address        = data.get('address', '').strip()         # ADD THIS
        department     = data.get('department', '').strip()

        # ── validation ──────────────────────────────────
        if not name or not gender or not email or not department:
            return jsonify({
                'status': 'error',
                'message': 'All required fields must be filled'
            }), 400

        if gender not in ('Male', 'Female'):
            return jsonify({
                'status': 'error',
                'message': 'Gender must be Male or Female'
            }), 400

        # duplicate email check (ignore self)
        existing = Employee.query.filter_by(email=email).first()
        if existing and existing.id != employee_id:
            return jsonify({
                'status': 'error',
                'message': 'An employee with this email already exists'
            }), 400

        # ── apply changes ───────────────────────────────
        employee.name           = name
        employee.gender         = gender
        employee.email          = email
        employee.contact_number = contact_number if contact_number else None  # ADD THIS
        employee.address        = address if address else None                # ADD THIS
        employee.department     = department

        db.session.commit()

        log_audit('UPDATE', 'Employee', f'Updated employee: {name}')

        return jsonify({
            'status': 'success',
            'message': 'Employee updated successfully',
            'data': employee.to_dict()
        }), 200

    except Exception as e:
        db.session.rollback()
        print(f"Error updating employee: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to update employee'
        }), 500


@api.route('/employee/delete/<int:employee_id>', methods=['DELETE'])
@login_required
@requires_admin
def delete_employee(employee_id):
    """Soft-delete employee by setting status to Inactive"""
    try:
        employee = Employee.query.get_or_404(employee_id)
        emp_name = employee.name

        employee.status = 'Inactive'
        db.session.commit()

        log_audit('DELETE', 'Employee', f'Deleted employee: {emp_name}')

        return jsonify({
            'status': 'success',
            'message': 'Employee deleted successfully'
        }), 200

    except Exception as e:
        db.session.rollback()
        print(f"Error deleting employee: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to delete employee'
        }), 500



# PATIENT ROUTES
@api.route('/patient/register', methods=['POST'])
@login_required
def register_patient():
    """Register a new patient"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['firstName', 'lastName', 'dob', 'gender', 'mobile', 'address', 'city',
                          'emergencyName', 'emergencyRelation', 'emergencyPhone']
        
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    'status': 'error',
                    'message': f'{field} is required'
                }), 400
        
        # Generate patient ID
        # Format: PT-YYYY-XXXXX (e.g., PT-2025-00001)
        from datetime import datetime
        year = datetime.now().year
        count = Patient.query.filter(Patient.patient_id.like(f'PT-{year}-%')).count() + 1
        patient_id = f'PT-{year}-{str(count).zfill(5)}'
        
        # Convert date string to date object
        try:
            dob = datetime.strptime(data['dob'], '%Y-%m-%d').date()
        except ValueError:
            return jsonify({
                'status': 'error',
                'message': 'Invalid date format for date of birth'
            }), 400
        
        # Create new patient
        patient = Patient(
            patient_id=patient_id,
            first_name=data['firstName'].strip(),
            middle_name=data.get('middleName', '').strip() if data.get('middleName') else None,
            last_name=data['lastName'].strip(),
            date_of_birth=dob,
            gender=data['gender'],
            blood_type=data.get('bloodType'),  # NEW
            civil_status=data.get('civilStatus'),
            email=data.get('email', '').strip() if data.get('email') else None,
            mobile=data['mobile'].strip(),
            address=data['address'].strip(),
            city=data['city'].strip(),
            province=data.get('province', '').strip() if data.get('province') else None,
            emergency_contact_name=data['emergencyName'].strip(),
            emergency_contact_relationship=data['emergencyRelation'].strip(),
            emergency_contact_phone=data['emergencyPhone'].strip(),
            emergency_contact_email=data.get('emergencyEmail', '').strip() if data.get('emergencyEmail') else None,  # NEW
            allergies=data.get('allergies', '').strip() if data.get('allergies') else None,  # NEW
            chronic_conditions=data.get('conditions', '').strip() if data.get('conditions') else None,  # NEW
            current_medications=data.get('medications', '').strip() if data.get('medications') else None,  # NEW
            insurance_provider=data.get('insuranceProvider'),
            policy_number=data.get('policyNumber', '').strip() if data.get('policyNumber') else None,
            created_by=current_user.id
        )
        
        db.session.add(patient)
        db.session.commit()
        
        # Log the action
        full_name = f"{patient.first_name} {patient.last_name}"
        log_audit('CREATE', 'Patient', f'Registered new patient: {full_name} ({patient_id})')
        
        return jsonify({
            'status': 'success',
            'message': 'Patient registered successfully',
            'data': patient.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"Error registering patient: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to register patient. Please try again.'
        }), 500


@api.route('/patient/list', methods=['GET'])
@login_required
def list_patients():
    """Get all patients"""
    try:
        patients = Patient.query.order_by(Patient.registration_date.desc()).all()
        return jsonify({
            'status': 'success',
            'data': [patient.to_dict() for patient in patients]
        }), 200
    except Exception as e:
        print(f"Error fetching patients: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch patients'
        }), 500


@api.route('/patient/<int:patient_id>', methods=['GET'])
@login_required
def get_patient(patient_id):
    """Get single patient details"""
    try:
        patient = Patient.query.get_or_404(patient_id)
        return jsonify({
            'status': 'success',
            'data': patient.to_dict()
        }), 200
    except Exception as e:
        print(f"Error fetching patient: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Patient not found'
        }), 404


@api.route('/patient/update/<int:patient_id>', methods=['PUT'])
@login_required
def update_patient(patient_id):
    """Update patient information"""
    try:
        patient = Patient.query.get_or_404(patient_id)
        data = request.get_json()
        
        # Update fields
        patient.first_name = data.get('firstName', patient.first_name).strip()
        patient.middle_name = data.get('middleName', '').strip() if data.get('middleName') else None
        patient.last_name = data.get('lastName', patient.last_name).strip()
        
        if data.get('dob'):
            from datetime import datetime
            patient.date_of_birth = datetime.strptime(data['dob'], '%Y-%m-%d').date()
        
        patient.gender = data.get('gender', patient.gender)
        patient.blood_type = data.get('bloodType', patient.blood_type)  # NEW
        patient.civil_status = data.get('civilStatus', patient.civil_status)
        patient.email = data.get('email', '').strip() if data.get('email') else None
        patient.mobile = data.get('mobile', patient.mobile).strip()
        patient.address = data.get('address', patient.address).strip()
        patient.city = data.get('city', patient.city).strip()
        patient.province = data.get('province', '').strip() if data.get('province') else None
        patient.emergency_contact_name = data.get('emergencyName', patient.emergency_contact_name).strip()
        patient.emergency_contact_relationship = data.get('emergencyRelation', patient.emergency_contact_relationship).strip()
        patient.emergency_contact_phone = data.get('emergencyPhone', patient.emergency_contact_phone).strip()
        patient.emergency_contact_email = data.get('emergencyEmail', '').strip() if data.get('emergencyEmail') else None  # NEW
        patient.allergies = data.get('allergies', '').strip() if data.get('allergies') else None  # NEW
        patient.chronic_conditions = data.get('conditions', '').strip() if data.get('conditions') else None  # NEW
        patient.current_medications = data.get('medications', '').strip() if data.get('medications') else None  # NEW
        patient.insurance_provider = data.get('insuranceProvider', patient.insurance_provider)
        patient.policy_number = data.get('policyNumber', '').strip() if data.get('policyNumber') else None
        
        db.session.commit()
        
        # Log the action
        full_name = f"{patient.first_name} {patient.last_name}"
        log_audit('UPDATE', 'Patient', f'Updated patient: {full_name} ({patient.patient_id})')
        
        return jsonify({
            'status': 'success',
            'message': 'Patient updated successfully',
            'data': patient.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error updating patient: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to update patient'
        }), 500


@api.route('/patient/delete/<int:patient_id>', methods=['DELETE'])
@login_required
@requires_admin
def delete_patient(patient_id):
    """Delete patient (admin only)"""
    try:
        patient = Patient.query.get_or_404(patient_id)
        full_name = f"{patient.first_name} {patient.last_name}"
        patient_id_num = patient.patient_id
        
        db.session.delete(patient)
        db.session.commit()
        
        log_audit('DELETE', 'Patient', f'Deleted patient: {full_name} ({patient_id_num})')
        
        return jsonify({
            'status': 'success',
            'message': 'Patient deleted successfully'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting patient: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to delete patient'
        }), 500



# FRONT DESK ROUTES (IMS ONLY)
@api.route('/frontdesk/employees/all-doctors', methods=['GET'])
@login_required
def frontdesk_get_all_doctors():
    """Get all active doctors for front desk admission form"""
    try:
        employees = Employee.query.filter_by(
            status='Active'
        ).order_by(Employee.department.asc(), Employee.name.asc()).all()
        
        employee_list = [
            {
                'id': emp.id,
                'name': emp.name,
                'email': emp.email,
                'department': emp.department
            }
            for emp in employees
        ]
        
        return jsonify({
            'status': 'success',
            'data': employee_list
        }), 200
        
    except Exception as e:
        print(f"Error fetching all doctors: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch doctors'
        }), 500


@api.route('/frontdesk/services/rooms', methods=['GET'])
@login_required
def frontdesk_get_rooms():
    """Get all room types for front desk admission form"""
    try:
        rooms = (
            HospitalService.query
            .filter_by(category='Room', status='Active')
            .order_by(HospitalService.price.asc())
            .all()
        )

        data = [
            {
                'id': r.id,
                'service_name': r.service_name,
                'price': float(r.price),
                'description': r.description,
                'is_available': r.is_available,
                'quantity_available': r.quantity_available
            }
            for r in rooms
        ]

        return jsonify({
            'status': 'success',
            'data': data
        }), 200

    except Exception as e:
        print(f"Error fetching rooms: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch rooms'
        }), 500


@api.route('/frontdesk/services/professional-fees', methods=['GET'])
@login_required
def frontdesk_get_professional_fees():
    """Get all professional fees for front desk"""
    try:
        services = (
            HospitalService.query
            .filter_by(category='Professional Fee', status='Active')
            .order_by(HospitalService.service_name.asc())
            .all()
        )

        data = [
            {
                'id': s.id,
                'service_name': s.service_name,
                'price': float(s.price),
                'description': s.description
            }
            for s in services
        ]

        return jsonify({
            'status': 'success',
            'data': data
        }), 200

    except Exception as e:
        print(f"Error fetching professional fees: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch services'
        }), 500


@api.route('/frontdesk/appointments', methods=['GET'])
@login_required
def frontdesk_get_appointments():
    """Get all appointments for front desk"""
    try:
        from models import Appointment
        
        # Get all appointments
        appointments = Appointment.query.order_by(
            Appointment.appointment_date.desc(),
            Appointment.appointment_time.desc()
        ).all()
        
        return jsonify({
            'status': 'success',
            'data': [apt.to_dict() for apt in appointments]
        }), 200
        
    except Exception as e:
        print(f"Error fetching appointments: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch appointments'
        }), 500


@api.route('/frontdesk/appointment/accept/<int:appointment_id>', methods=['POST'])
@login_required
def frontdesk_accept_appointment(appointment_id):
    """Accept appointment - change status to Waiting to Approved"""
    try:
        from models import Appointment
        
        appointment = Appointment.query.get_or_404(appointment_id)
        
        # Only accept if status is Pending
        if appointment.status != 'Pending':
            return jsonify({
                'status': 'error',
                'message': 'Only pending appointments can be accepted'
            }), 400
        
        # Update status to Waiting to Approved
        appointment.status = 'Waiting to Approved'
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Appointment accepted successfully',
            'data': appointment.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error accepting appointment: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to accept appointment'
        }), 500


@api.route('/frontdesk/appointment/reject/<int:appointment_id>', methods=['POST'])
@login_required
def frontdesk_reject_appointment(appointment_id):
    """Reject appointment"""
    try:
        from models import Appointment
        
        appointment = Appointment.query.get_or_404(appointment_id)
        
        # Only reject if status is Pending
        if appointment.status != 'Pending':
            return jsonify({
                'status': 'error',
                'message': 'Only pending appointments can be rejected'
            }), 400
        
        # Update status to Rejected
        appointment.status = 'Rejected'
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Appointment rejected successfully',
            'data': appointment.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error rejecting appointment: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to reject appointment'
        }), 500


@api.route('/frontdesk/appointment/<int:appointment_id>', methods=['GET'])
@login_required
def frontdesk_get_appointment(appointment_id):
    """Get single appointment details"""
    try:
        from models import Appointment
        
        appointment = Appointment.query.get_or_404(appointment_id)
        
        return jsonify({
            'status': 'success',
            'data': appointment.to_dict()
        }), 200
        
    except Exception as e:
        print(f"Error fetching appointment: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch appointment'
        }), 500


@api.route('/frontdesk/admission/create', methods=['POST'])
@login_required
def create_patient_admission():
    """Create new patient admission - with patient verification"""
    try:
        from models import PatientAdmission
        
        data = request.get_json()
        
        # Validate required fields
        patient_name = data.get('patient_name', '').strip()
        gender = data.get('gender', '').strip()
        doctor_name = data.get('doctor_name', '').strip()
        room_type = data.get('room_type', '').strip()
        deposit_amount = data.get('deposit_amount', 0)
        
        if not all([patient_name, gender, doctor_name, room_type]):
            return jsonify({
                'status': 'error',
                'message': 'All fields are required'
            }), 400
        
        # VERIFY PATIENT EXISTS IN DATABASE
        patient = Patient.query.filter(
            func.lower(
                func.concat(
                    Patient.first_name, ' ',
                    func.coalesce(func.concat(Patient.middle_name, ' '), ''),
                    Patient.last_name
                )
            ) == func.lower(patient_name)
        ).first()
        
        if not patient:
            return jsonify({
                'status': 'error',
                'message': 'Patient not found in database. Please register the patient first before admission.'
            }), 404
        
        # Optional: Verify gender matches
        if patient.gender != gender:
            return jsonify({
                'status': 'error',
                'message': f'Gender mismatch: Patient {patient_name} is registered as {patient.gender}'
            }), 400
        
        # Check if patient already has an active admission
        existing_admission = PatientAdmission.query.filter_by(
            patient_name=patient_name,
            status='Admitted'
        ).first()
        
        if existing_admission:
            return jsonify({
                'status': 'error',
                'message': 'Patient already has an active admission'
            }), 400
        
        # Create admission record with verified patient data
        admission = PatientAdmission(
            patient_name=patient_name,
            gender=patient.gender,  # Use verified gender from database
            doctor_name=doctor_name,
            room_type=room_type,
            deposit_amount=float(deposit_amount),
            status='Admitted',
            admitted_by=current_user.id
        )
        
        db.session.add(admission)
        db.session.commit()
        
        # Log audit with patient ID
        log_audit('CREATE', 'Patient Admission', 
                  f'Admitted patient: {patient_name} (ID: {patient.patient_id})')
        
        return jsonify({
            'status': 'success',
            'message': f'Patient {patient_name} admitted successfully!',
            'data': admission.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"Error creating admission: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': 'Failed to admit patient. Please try again.'
        }), 500


@api.route('/frontdesk/admission/list', methods=['GET'])
@login_required
def list_patient_admissions():
    """Get all patient admissions"""
    try:
        from models import PatientAdmission
        
        # Get query parameters
        status = request.args.get('status', 'Admitted')  # Changed default from 'Active' to 'Admitted'
        search = request.args.get('search', '').strip()
        
        # Build query
        query = PatientAdmission.query
        
        if status != 'All':
            query = query.filter_by(status=status)
        
        if search:
            from sqlalchemy import or_
            query = query.filter(
                or_(
                    PatientAdmission.patient_name.ilike(f'%{search}%'),
                    PatientAdmission.doctor_name.ilike(f'%{search}%')
                )
            )
        
        # Order by most recent first
        admissions = query.order_by(PatientAdmission.admission_date.desc()).all()
        
        return jsonify({
            'status': 'success',
            'data': [admission.to_dict() for admission in admissions]
        }), 200
        
    except Exception as e:
        print(f"Error fetching admissions: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch admissions'
        }), 500


@api.route('/patient/search', methods=['GET'])
@login_required
def search_patients_for_admission():
    """Search patients by name - for admission form autocomplete"""
    try:
        search_term = request.args.get('q', '').strip()
        
        if len(search_term) < 2:
            return jsonify({
                'status': 'success',
                'data': []
            }), 200
        
        # Search for patients matching the search term
        patients = Patient.query.filter(
            or_(
                Patient.first_name.ilike(f'%{search_term}%'),
                Patient.last_name.ilike(f'%{search_term}%'),
                func.concat(
                    Patient.first_name, ' ',
                    func.coalesce(func.concat(Patient.middle_name, ' '), ''),
                    Patient.last_name
                ).ilike(f'%{search_term}%')
            )
        ).filter_by(status='Active').limit(10).all()
        
        results = [
            {
                'id': p.id,
                'patient_id': p.patient_id,
                'full_name': f"{p.first_name} {p.middle_name + ' ' if p.middle_name else ''}{p.last_name}",
                'gender': p.gender,
                'blood_type': p.blood_type,
                'mobile': p.mobile
            }
            for p in patients
        ]
        
        return jsonify({
            'status': 'success',
            'data': results
        }), 200
        
    except Exception as e:
        print(f"Error searching patients: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to search patients'
        }), 500


@api.route('/frontdesk/admission/<int:admission_id>', methods=['GET'])
@login_required
def get_patient_admission(admission_id):
    """Get single admission details"""
    try:
        from models import PatientAdmission
        
        admission = PatientAdmission.query.get_or_404(admission_id)
        
        return jsonify({
            'status': 'success',
            'data': admission.to_dict()
        }), 200
        
    except Exception as e:
        print(f"Error fetching admission: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch admission details'
        }), 500


@api.route('/frontdesk/admission/discharge/<int:admission_id>', methods=['POST'])
@login_required
def discharge_patient_admission(admission_id):
    """Discharge a patient"""
    try:
        from models import PatientAdmission
        
        admission = PatientAdmission.query.get_or_404(admission_id)
        
        if admission.status == 'Discharged':
            return jsonify({
                'status': 'error',
                'message': 'Patient is already discharged'
            }), 400
        
        # Update admission record
        admission.status = 'Discharged'
        
        db.session.commit()
        
        # Log audit
        log_audit('UPDATE', 'Patient Admission', f'Discharged patient: {admission.patient_name}')
        
        return jsonify({
            'status': 'success',
            'message': 'Patient discharged successfully',
            'data': admission.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error discharging patient: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to discharge patient'
        }), 500


@api.route('/patient/check-exists', methods=['GET'])
@login_required
def check_patient_exists():
    """Check if patient exists by full name - for admission verification"""
    try:
        patient_name = request.args.get('name', '').strip()
        
        if not patient_name:
            return jsonify({
                'status': 'error',
                'message': 'Patient name is required',
                'exists': False
            }), 400
        
        # Search for patient by full name
        # Try exact match first
        patient = Patient.query.filter(
            func.concat(
                Patient.first_name, ' ',
                func.coalesce(func.concat(Patient.middle_name, ' '), ''),
                Patient.last_name
            ) == patient_name
        ).first()
        
        if patient:
            return jsonify({
                'status': 'success',
                'exists': True,
                'data': {
                    'id': patient.id,
                    'patient_id': patient.patient_id,
                    'full_name': f"{patient.first_name} {patient.middle_name + ' ' if patient.middle_name else ''}{patient.last_name}",
                    'gender': patient.gender,
                    'blood_type': patient.blood_type,
                    'mobile': patient.mobile
                }
            }), 200
        
        # Try case-insensitive search if exact match fails
        patient = Patient.query.filter(
            func.lower(
                func.concat(
                    Patient.first_name, ' ',
                    func.coalesce(func.concat(Patient.middle_name, ' '), ''),
                    Patient.last_name
                )
            ) == func.lower(patient_name)
        ).first()
        
        if patient:
            return jsonify({
                'status': 'success',
                'exists': True,
                'data': {
                    'id': patient.id,
                    'patient_id': patient.patient_id,
                    'full_name': f"{patient.first_name} {patient.middle_name + ' ' if patient.middle_name else ''}{patient.last_name}",
                    'gender': patient.gender,
                    'blood_type': patient.blood_type,
                    'mobile': patient.mobile
                }
            }), 200
        
        # Patient not found
        return jsonify({
            'status': 'success',
            'exists': False,
            'message': 'Patient not found in database'
        }), 200
        
    except Exception as e:
        print(f"Error checking patient existence: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': 'Failed to check patient',
            'exists': False
        }), 500



# AUDIT LOG ROUTES
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
    
    # Filter by action (if provided)
    if action_filter and action_filter != 'All Actions':
        query = query.filter(AuditLog.action == action_filter.upper())
    
    # Filter by date (if provided)
    if date_filter:
        try:
            date_obj = datetime.strptime(date_filter, '%Y-%m-%d')
            query = query.filter(func.date(AuditLog.timestamp) == date_obj.date())
        except ValueError:
            pass
    
    # Search filter (username, full_name, or details)
    if search:
        search_pattern = f'%{search}%'
        query = query.filter(
            or_(
                AuditLog.username.ilike(search_pattern),
                AuditLog.full_name.ilike(search_pattern),
                AuditLog.details.ilike(search_pattern),
                AuditLog.entity.ilike(search_pattern)
            )
        )
    
    # Order by most recent first
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



# DASHBOARD STATS
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


# INVENTORY ROUTES
@api.route('/inventory/list', methods=['GET'])
@login_required
def list_inventory():
    """Get all inventory products"""
    try:
        # Get query parameters for filtering
        category = request.args.get('category', None)
        status = request.args.get('status', 'Active')
        search = request.args.get('search', None)
        
        # Build query
        query = InventoryProduct.query
        
        if category and category != 'All Categories':
            query = query.filter_by(category=category)
        
        if status:
            query = query.filter_by(status=status)
        
        if search:
            query = query.filter(
                or_(
                    InventoryProduct.product_name.ilike(f'%{search}%')
                )
            )
        
        products = query.order_by(InventoryProduct.product_name).all()
        
        return jsonify({
            'status': 'success',
            'data': [product.to_dict() for product in products]
        }), 200
        
    except Exception as e:
        print(f"Error fetching inventory: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch inventory products'
        }), 500

@api.route('/inventory/create', methods=['POST'])
@login_required
def create_inventory_product():
    """Create new inventory product"""
    try:
        data = request.get_json()
        
        # Validate required fields
        product_name = data.get('product_name', '').strip()
        category = data.get('category', '').strip()
        current_stock = data.get('current_stock', 0)
        reorder_level = data.get('reorder_level', 50)
        cost_price = data.get('cost_price', 0)
        selling_price = data.get('selling_price', 0)
        
        if not product_name or not category:
            return jsonify({
                'status': 'error',
                'message': 'Product name and category are required'
            }), 400
        
        if cost_price <= 0 or selling_price <= 0:
            return jsonify({
                'status': 'error',
                'message': 'Cost price and selling price must be greater than 0'
            }), 400
        
        # Check if product already exists
        existing = InventoryProduct.query.filter_by(
            product_name=product_name,
            category=category
        ).first()
        
        if existing:
            return jsonify({
                'status': 'error',
                'message': 'Product with this name already exists in this category'
            }), 400
        
        # Create new product
        product = InventoryProduct(
            product_name=product_name,
            category=category,
            current_stock=int(current_stock),
            reorder_level=int(reorder_level),
            cost_price=float(cost_price),
            selling_price=float(selling_price),
            created_by=current_user.id
        )
        
        db.session.add(product)
        db.session.commit()
        
        # Log initial stock if any
        if int(current_stock) > 0:
            transaction = InventoryTransaction(
                product_id=product.id,
                transaction_type='INITIAL_STOCK',
                quantity=int(current_stock),
                previous_stock=0,
                new_stock=int(current_stock),
                notes='Initial stock entry',
                performed_by=current_user.id
            )
            db.session.add(transaction)
            db.session.commit()
        
        # Log audit
        log_audit('CREATE', 'Inventory', f'Added product: {product_name}')
        
        return jsonify({
            'status': 'success',
            'message': 'Product added successfully',
            'data': product.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"Error creating inventory product: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to create product. Please try again.'
        }), 500

@api.route('/inventory/update/<int:product_id>', methods=['PUT'])
@login_required
def update_inventory_product(product_id):
    """Update inventory product"""
    try:
        product = InventoryProduct.query.get_or_404(product_id)
        data = request.get_json()
        
        # Update fields
        product.product_name = data.get('product_name', product.product_name).strip()
        product.category = data.get('category', product.category).strip()
        product.reorder_level = int(data.get('reorder_level', product.reorder_level))
        product.cost_price = float(data.get('cost_price', product.cost_price))
        product.selling_price = float(data.get('selling_price', product.selling_price))
        product.updated_by = current_user.id
        
        db.session.commit()
        
        # Log audit
        log_audit('UPDATE', 'Inventory', f'Updated product: {product.product_name}')
        
        return jsonify({
            'status': 'success',
            'message': 'Product updated successfully',
            'data': product.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error updating inventory product: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to update product'
        }), 500

@api.route('/inventory/restock/<int:product_id>', methods=['POST'])
@login_required
def restock_product(product_id):
    """Restock inventory product"""
    try:
        product = InventoryProduct.query.get_or_404(product_id)
        data = request.get_json()
        
        quantity = int(data.get('quantity', 0))
        notes = data.get('notes', '').strip()
        
        if quantity <= 0:
            return jsonify({
                'status': 'error',
                'message': 'Quantity must be greater than 0'
            }), 400
        
        # Record previous stock
        previous_stock = product.current_stock
        
        # Update stock
        product.current_stock += quantity
        product.updated_by = current_user.id
        
        # Create transaction record
        transaction = InventoryTransaction(
            product_id=product.id,
            transaction_type='RESTOCK',
            quantity=quantity,
            previous_stock=previous_stock,
            new_stock=product.current_stock,
            notes=notes or f'Restocked {quantity} units',
            performed_by=current_user.id
        )
        
        db.session.add(transaction)
        db.session.commit()
        
        # Log audit
        log_audit('UPDATE', 'Inventory', f'Restocked {product.product_name}: +{quantity} units')
        
        return jsonify({
            'status': 'success',
            'message': f'Successfully restocked {quantity} units',
            'data': product.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error restocking product: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to restock product'
        }), 500

@api.route('/inventory/adjust/<int:product_id>', methods=['POST'])
@login_required
def adjust_inventory(product_id):
    """Adjust inventory stock (add or remove)"""
    try:
        product = InventoryProduct.query.get_or_404(product_id)
        data = request.get_json()
        
        adjustment = int(data.get('adjustment', 0))
        notes = data.get('notes', '').strip()
        
        if adjustment == 0:
            return jsonify({
                'status': 'error',
                'message': 'Adjustment cannot be zero'
            }), 400
        
        # Record previous stock
        previous_stock = product.current_stock
        
        # Calculate new stock
        new_stock = product.current_stock + adjustment
        
        if new_stock < 0:
            return jsonify({
                'status': 'error',
                'message': 'Adjustment would result in negative stock'
            }), 400
        
        # Update stock
        product.current_stock = new_stock
        product.updated_by = current_user.id
        
        # Create transaction record
        transaction = InventoryTransaction(
            product_id=product.id,
            transaction_type='ADJUSTMENT',
            quantity=abs(adjustment),
            previous_stock=previous_stock,
            new_stock=new_stock,
            notes=notes or f'Stock adjustment: {adjustment:+d} units',
            performed_by=current_user.id
        )
        
        db.session.add(transaction)
        db.session.commit()
        
        # Log audit
        log_audit('UPDATE', 'Inventory', f'Adjusted {product.product_name}: {adjustment:+d} units')
        
        return jsonify({
            'status': 'success',
            'message': 'Stock adjusted successfully',
            'data': product.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error adjusting inventory: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to adjust stock'
        }), 500

@api.route('/inventory/delete/<int:product_id>', methods=['DELETE'])
@login_required
def delete_inventory_product(product_id):
    """Delete inventory product (soft delete - mark as inactive)"""
    try:
        product = InventoryProduct.query.get_or_404(product_id)
        product_name = product.product_name
        
        # Soft delete - mark as inactive
        product.status = 'Inactive'
        product.updated_by = current_user.id
        
        db.session.commit()
        
        # Log audit
        log_audit('DELETE', 'Inventory', f'Deleted product: {product_name}')
        
        return jsonify({
            'status': 'success',
            'message': 'Product deleted successfully'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting inventory product: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to delete product'
        }), 500

@api.route('/inventory/transactions/<int:product_id>', methods=['GET'])
@login_required
def get_product_transactions(product_id):
    """Get transaction history for a product"""
    try:
        transactions = InventoryTransaction.query.filter_by(
            product_id=product_id
        ).order_by(InventoryTransaction.transaction_date.desc()).limit(50).all()
        
        return jsonify({
            'status': 'success',
            'data': [trans.to_dict() for trans in transactions]
        }), 200
        
    except Exception as e:
        print(f"Error fetching transactions: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch transaction history'
        }), 500

@api.route('/inventory/categories', methods=['GET'])
@login_required
def get_inventory_categories():
    """Get list of all categories"""
    try:
        categories = db.session.query(InventoryProduct.category).distinct().all()
        category_list = [cat[0] for cat in categories]
        
        return jsonify({
            'status': 'success',
            'data': category_list
        }), 200
        
    except Exception as e:
        print(f"Error fetching categories: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch categories'
        }), 500

@api.route('/inventory/stats', methods=['GET'])
@login_required
def get_inventory_stats():
    """Get inventory statistics"""
    try:
        total_products = InventoryProduct.query.filter_by(status='Active').count()
        
        low_stock = InventoryProduct.query.filter(
            and_(
                InventoryProduct.status == 'Active',
                InventoryProduct.current_stock < InventoryProduct.reorder_level
            )
        ).count()
        
        out_of_stock = InventoryProduct.query.filter(
            and_(
                InventoryProduct.status == 'Active',
                InventoryProduct.current_stock <= 0
            )
        ).count()
        
        # Calculate total inventory value
        products = InventoryProduct.query.filter_by(status='Active').all()
        total_value = sum(float(p.cost_price) * p.current_stock for p in products)
        
        return jsonify({
            'status': 'success',
            'data': {
                'total_products': total_products,
                'low_stock_count': low_stock,
                'out_of_stock_count': out_of_stock,
                'total_inventory_value': round(total_value, 2)
            }
        }), 200
        
    except Exception as e:
        print(f"Error fetching inventory stats: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch inventory statistics'
        }), 500


# PHARMACY ROUTES
@api.route('/pharmacy/medicines', methods=['GET'])
@login_required
def get_pharmacy_medicines():
    """Get medicines from inventory for pharmacy POS"""
    try:
        products = InventoryProduct.query.filter_by(status='Active').all()

        category_mapping = {
            'medicines': 'medicines',
            'medical supplies': 'supplies',
            'vitamins': 'vitamins',
            'supplements': 'supplements',
            'personal care': 'personal_care'
        }

        medicines = []
        for product in products:
            # normalize category from DB
            raw_category = (product.category or '').strip().lower()

            mapped_category = category_mapping.get(
                raw_category,
                'medicines'  # safe fallback
            )

            medicine = {
                'id': product.id,
                'name': product.product_name,
                'generic': product.product_name,
                'price': float(product.selling_price),
                'cost': float(product.cost_price),
                'stock': product.current_stock,
                'reorderLevel': product.reorder_level,
                'category': mapped_category,
                'barcode': f'BAR{str(product.id).zfill(10)}',
                'status': 'LOW STOCK' if product.current_stock <= product.reorder_level else ''
            }

            medicines.append(medicine)

        return jsonify({
            'status': 'success',
            'data': medicines
        }), 200

    except Exception as e:
        print(f"Error fetching pharmacy inventory: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch inventory products'
        }), 500

@api.route('/inventory/decrease/<int:product_id>', methods=['POST'])
@login_required
def decrease_inventory(product_id):
    """Decrease inventory stock (e.g., when selling a product)"""
    try:
        product = InventoryProduct.query.get_or_404(product_id)
        data = request.get_json()

        quantity = int(data.get('quantity', 0))
        notes = data.get('notes', '').strip()

        if quantity <= 0:
            return jsonify({
                'status': 'error',
                'message': 'Quantity must be greater than 0'
            }), 400

        if product.current_stock < quantity:
            return jsonify({
                'status': 'error',
                'message': f'Insufficient stock. Current stock: {product.current_stock}'
            }), 400

        previous_stock = product.current_stock
        product.current_stock -= quantity
        product.updated_by = current_user.id

        # Create transaction record
        transaction = InventoryTransaction(
            product_id=product.id,
            transaction_type='DECREASE',
            quantity=quantity,
            previous_stock=previous_stock,
            new_stock=product.current_stock,
            notes=notes or f'Decreased stock by {quantity} units',
            performed_by=current_user.id
        )
        db.session.add(transaction)
        db.session.commit()

        # Log audit
        log_audit('UPDATE', 'Inventory', f'Decreased {product.product_name} by {quantity} units')

        return jsonify({
            'status': 'success',
            'message': f'Stock decreased by {quantity} units',
            'data': product.to_dict()
        }), 200

    except Exception as e:
        db.session.rollback()
        print(f"Error decreasing inventory: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to decrease stock'
        }), 500

@api.route('/pharmacy/complete-sale', methods=['POST'])
@login_required
def complete_pharmacy_sale():
    """Complete a pharmacy sale transaction"""
    try:
        data = request.get_json()
        
        # Validate required fields
        items = data.get('items', [])
        if not items:
            return jsonify({
                'status': 'error',
                'message': 'No items in cart'
            }), 400
        
        # Generate receipt number
        receipt_number = f"RCP{int(datetime.now().timestamp() * 1000)}"
        
        # Calculate totals
        subtotal = float(data.get('subtotal', 0))
        discount_percentage = float(data.get('discount_percentage', 0))
        discount_amount = float(data.get('discount_amount', 0))
        tax_amount = float(data.get('tax_amount', 0))
        total_amount = float(data.get('total_amount', 0))
        amount_received = float(data.get('amount_received', 0))
        change_amount = float(data.get('change_amount', 0))
        
        # Calculate total cost and profit
        total_cost = 0
        sale_items = []
        
        # Process each item
        for item in items:
            product = InventoryProduct.query.get(item['id'])
            if not product:
                return jsonify({
                    'status': 'error',
                    'message': f"Product {item['name']} not found"
                }), 404
            
            quantity = int(item['quantity'])
            
            # Check stock
            if product.current_stock < quantity:
                return jsonify({
                    'status': 'error',
                    'message': f"Insufficient stock for {product.product_name}"
                }), 400
            
            # Calculate item totals
            unit_price = float(product.selling_price)
            unit_cost = float(product.cost_price)
            item_total = unit_price * quantity
            item_cost_total = unit_cost * quantity
            item_profit = item_total - item_cost_total
            
            total_cost += item_cost_total
            
            # Create sale item
            sale_item = {
                'product_id': product.id,
                'product_name': product.product_name,
                'quantity': quantity,
                'unit_price': unit_price,
                'unit_cost': unit_cost,
                'item_total': item_total,
                'item_cost_total': item_cost_total,
                'item_profit': item_profit
            }
            sale_items.append(sale_item)
            
            # Update inventory stock
            previous_stock = product.current_stock
            product.current_stock -= quantity
            product.updated_by = current_user.id
            
            # Create inventory transaction
            inventory_transaction = InventoryTransaction(
                product_id=product.id,
                transaction_type='SALE',
                quantity=quantity,
                previous_stock=previous_stock,
                new_stock=product.current_stock,
                notes=f'Sold via POS - Receipt: {receipt_number}',
                performed_by=current_user.id
            )
            db.session.add(inventory_transaction)
        
        # Calculate total profit
        total_profit = total_amount - total_cost
        
        # Create pharmacy sale
        sale = PharmacySale(
            receipt_number=receipt_number,
            payment_method=data.get('payment_method', 'cash'),
            subtotal=subtotal,
            discount_percentage=discount_percentage,
            discount_amount=discount_amount,
            tax_amount=tax_amount,
            total_amount=total_amount,
            amount_received=amount_received,
            change_amount=change_amount,
            total_cost=total_cost,
            total_profit=total_profit,
            user_id=current_user.id,
            user_name=current_user.full_name
        )
        
        db.session.add(sale)
        db.session.flush()  # Get the sale ID
        
        # Add sale items
        for sale_item_data in sale_items:
            sale_item = PharmacySaleItem(
                sale_id=sale.id,
                **sale_item_data
            )
            db.session.add(sale_item)
        
        db.session.commit()
        
        # Log audit
        log_audit('CREATE', 'Pharmacy Sale', f'Completed sale: {receipt_number} - Total: ₱{total_amount:.2f}')
        
        return jsonify({
            'status': 'success',
            'message': 'Sale completed successfully',
            'data': sale.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"Error completing sale: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': 'Failed to complete sale. Please try again.'
        }), 500

@api.route('/pharmacy/sales/reports', methods=['GET'])
@login_required
def get_pharmacy_sales_reports():
    """Get pharmacy sales reports filtered by date and user"""
    try:
        # Get query parameters
        period = request.args.get('period', 'today')  # today, week, month, year
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        # Base query - filter by current user only
        query = PharmacySale.query.filter_by(user_id=current_user.id)
        
        # Apply date filters
        now = datetime.now()
        
        if period == 'today':
            start = datetime(now.year, now.month, now.day, 0, 0, 0)
            end = datetime(now.year, now.month, now.day, 23, 59, 59)
            query = query.filter(PharmacySale.sale_date >= start, PharmacySale.sale_date <= end)
            
        elif period == 'week':
            # Get start of week (Monday)
            start = now - timedelta(days=now.weekday())
            start = datetime(start.year, start.month, start.day, 0, 0, 0)
            end = now
            query = query.filter(PharmacySale.sale_date >= start, PharmacySale.sale_date <= end)
            
        elif period == 'month':
            start = datetime(now.year, now.month, 1, 0, 0, 0)
            end = now
            query = query.filter(PharmacySale.sale_date >= start, PharmacySale.sale_date <= end)
            
        elif period == 'year':
            start = datetime(now.year, 1, 1, 0, 0, 0)
            end = now
            query = query.filter(PharmacySale.sale_date >= start, PharmacySale.sale_date <= end)
            
        elif period == 'custom' and start_date and end_date:
            start = datetime.strptime(start_date, '%Y-%m-%d')
            end = datetime.strptime(end_date, '%Y-%m-%d')
            end = datetime(end.year, end.month, end.day, 23, 59, 59)
            query = query.filter(PharmacySale.sale_date >= start, PharmacySale.sale_date <= end)
        
        # Get all sales for period
        sales = query.order_by(PharmacySale.sale_date.desc()).all()
        
        # Calculate summary statistics
        total_sales = sum(float(sale.total_amount) for sale in sales)
        total_profit = sum(float(sale.total_profit) for sale in sales)
        total_transactions = len(sales)
        total_items_sold = sum(
            sum(item.quantity for item in sale.items)
            for sale in sales
        )
        
        # Get top selling products
        product_stats = {}
        for sale in sales:
            for item in sale.items:
                if item.product_id not in product_stats:
                    product_stats[item.product_id] = {
                        'name': item.product_name,
                        'quantity': 0,
                        'revenue': 0
                    }
                product_stats[item.product_id]['quantity'] += item.quantity
                product_stats[item.product_id]['revenue'] += float(item.item_total)
        
        # Sort and get top 10
        top_selling = sorted(
            product_stats.values(),
            key=lambda x: x['quantity'],
            reverse=True
        )[:10]
        
        return jsonify({
            'status': 'success',
            'data': {
                'summary': {
                    'total_sales': round(total_sales, 2),
                    'total_profit': round(total_profit, 2),
                    'total_transactions': total_transactions,
                    'total_items_sold': total_items_sold
                },
                'top_selling': top_selling,
                'transactions': [sale.to_dict() for sale in sales[:20]]  # Last 20 transactions
            }
        }), 200
        
    except Exception as e:
        print(f"Error fetching sales reports: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch sales reports'
        }), 500

@api.route('/pharmacy/sales/<int:sale_id>', methods=['GET'])
@login_required
def get_pharmacy_sale_details(sale_id):
    """Get details of a specific sale"""
    try:
        sale = PharmacySale.query.get_or_404(sale_id)
        
        # Check if user has permission to view this sale
        if sale.user_id != current_user.id and not isinstance(current_user, AdminAccount):
            return jsonify({
                'status': 'error',
                'message': 'Unauthorized access'
            }), 403
        
        return jsonify({
            'status': 'success',
            'data': sale.to_dict()
        }), 200
        
    except Exception as e:
        print(f"Error fetching sale details: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch sale details'
        }), 500




# SERVICE MANAGEMENT ROUTES
@api.route('/services/list', methods=['GET'])
@login_required
def list_services():
    """Get all hospital services"""
    try:
        # Get query parameters for filtering
        category = request.args.get('category', None)
        status = request.args.get('status', 'Active')
        
        # Build query
        query = HospitalService.query
        
        if category and category != 'All Categories':
            query = query.filter_by(category=category)
        
        if status:
            query = query.filter_by(status=status)
        
        # Order by category and name
        services = query.order_by(
            HospitalService.category,
            HospitalService.service_name
        ).all()
        
        return jsonify({
            'status': 'success',
            'data': [service.to_dict() for service in services],
            'count': len(services)
        }), 200
        
    except Exception as e:
        print(f"Error fetching services: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch services'
        }), 500


@api.route('/services/get/<int:service_id>', methods=['GET'])
@login_required
def get_service(service_id):
    """Get a specific service by ID"""
    try:
        service = HospitalService.query.get(service_id)
        
        if not service:
            return jsonify({
                'status': 'error',
                'message': 'Service not found'
            }), 404
        
        return jsonify({
            'status': 'success',
            'data': service.to_dict()
        }), 200
        
    except Exception as e:
        print(f"Error fetching service: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch service'
        }), 500


@api.route('/services/create', methods=['POST'])
@login_required
def create_service():
    """Create a new hospital service"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['service_name', 'category', 'price']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({
                    'status': 'error',
                    'message': f'{field} is required'
                }), 400
        
        # Check if service already exists
        existing_service = HospitalService.query.filter_by(
            service_name=data['service_name']
        ).first()
        
        if existing_service:
            return jsonify({
                'status': 'error',
                'message': 'A service with this name already exists'
            }), 400
        
        # Create new service
        service = HospitalService(
            service_name=data['service_name'],
            category=data['category'],
            price=Decimal(str(data['price'])),
            description=data.get('description', ''),
            quantity_available=data.get('quantity_available', None),
            is_available=data.get('is_available', True),
            status='Active',
            created_by=current_user.id
        )
        
        db.session.add(service)
        db.session.commit()
        
        # Log audit
        log_audit('CREATE', 'Hospital Service', f'Created service: {service.service_name}')
        
        return jsonify({
            'status': 'success',
            'message': 'Service created successfully',
            'data': service.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"Error creating service: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to create service. Please try again.'
        }), 500


@api.route('/services/update/<int:service_id>', methods=['PUT'])
@login_required
def update_service(service_id):
    """Update an existing service"""
    try:
        service = HospitalService.query.get(service_id)
        
        if not service:
            return jsonify({
                'status': 'error',
                'message': 'Service not found'
            }), 404
        
        data = request.get_json()
        
        # Track price change
        old_price = service.price
        new_price = Decimal(str(data.get('price', service.price)))
        
        if old_price != new_price:
            # Create price history record
            change_percentage = ((new_price - old_price) / old_price) * 100
            
            price_history = ServicePriceHistory(
                service_id=service.id,
                old_price=old_price,
                new_price=new_price,
                change_percentage=change_percentage,
                reason=data.get('price_change_reason', 'Price update'),
                changed_by=current_user.id
            )
            
            db.session.add(price_history)
            
            # Update service price fields
            service.previous_price = old_price
            service.price_last_updated = datetime.utcnow()
        
        # Update service fields
        if 'service_name' in data:
            service.service_name = data['service_name']
        if 'category' in data:
            service.category = data['category']
        if 'price' in data:
            service.price = new_price
        if 'description' in data:
            service.description = data['description']
        if 'quantity_available' in data:
            service.quantity_available = data['quantity_available']
        if 'is_available' in data:
            service.is_available = data['is_available']
        if 'status' in data:
            service.status = data['status']
        
        service.updated_by = current_user.id
        
        db.session.commit()
        
        # Log audit
        log_audit('UPDATE', 'Hospital Service', f'Updated service: {service.service_name}')
        
        return jsonify({
            'status': 'success',
            'message': 'Service updated successfully',
            'data': service.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error updating service: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to update service. Please try again.'
        }), 500


@api.route('/services/delete/<int:service_id>', methods=['DELETE'])
@login_required
def delete_service(service_id):
    """Delete a service (soft delete by setting status to Inactive)"""
    try:
        service = HospitalService.query.get(service_id)
        
        if not service:
            return jsonify({
                'status': 'error',
                'message': 'Service not found'
            }), 404
        
        service_name = service.service_name
        
        # Soft delete - set status to Inactive instead of deleting
        service.status = 'Inactive'
        service.updated_by = current_user.id
        
        db.session.commit()
        
        # Log audit
        log_audit('DELETE', 'Hospital Service', f'Deleted service: {service_name}')
        
        return jsonify({
            'status': 'success',
            'message': 'Service deleted successfully'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting service: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to delete service. Please try again.'
        }), 500


@api.route('/services/stats', methods=['GET'])
@login_required
def get_service_stats():
    """Get service statistics"""
    try:
        # Count by category
        total_services = HospitalService.query.filter_by(status='Active').count()
        
        room_services = HospitalService.query.filter_by(
            category='Room',
            status='Active'
        ).count()
        
        diagnostic_services = HospitalService.query.filter_by(
            category='Diagnostic',
            status='Active'
        ).count()
        
        # Calculate average price
        active_services = HospitalService.query.filter_by(status='Active').all()
        if active_services:
            avg_price = sum(float(s.price) for s in active_services) / len(active_services)
        else:
            avg_price = 0
        
        return jsonify({
            'status': 'success',
            'data': {
                'total_services': total_services,
                'room_services': room_services,
                'diagnostic_services': diagnostic_services,
                'average_price': round(avg_price, 2)
            }
        }), 200
        
    except Exception as e:
        print(f"Error fetching service stats: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch service statistics'
        }), 500


@api.route('/services/categories', methods=['GET'])
@login_required
def get_service_categories():
    """Get all service categories"""
    try:
        # Predefined categories
        categories = [
            'Room',
            'Diagnostic',
            'Procedure',
            'Professional Fee',
            'Medication',
            'Other'
        ]
        
        return jsonify({
            'status': 'success',
            'data': categories
        }), 200
        
    except Exception as e:
        print(f"Error fetching categories: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch categories'
        }), 500


@api.route('/services/by-category', methods=['GET'])
@login_required
def get_services_by_category():
    """Get services grouped by category"""
    try:
        services = HospitalService.query.filter_by(status='Active').order_by(
            HospitalService.category,
            HospitalService.service_name
        ).all()
        
        # Group by category
        grouped = {}
        for service in services:
            if service.category not in grouped:
                grouped[service.category] = []
            grouped[service.category].append(service.to_dict())
        
        return jsonify({
            'status': 'success',
            'data': grouped
        }), 200
        
    except Exception as e:
        print(f"Error fetching services by category: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch services'
        }), 500


# ================================
# SERVICE USAGE ROUTES
# ================================

@api.route('/services/usage/create', methods=['POST'])
@login_required
def create_service_usage():
    """Record service usage"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['service_id', 'quantity']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'status': 'error',
                    'message': f'{field} is required'
                }), 400
        
        # Get service
        service = HospitalService.query.get(data['service_id'])
        
        if not service:
            return jsonify({
                'status': 'error',
                'message': 'Service not found'
            }), 404
        
        # Create usage record
        quantity = int(data['quantity'])
        unit_price = service.price
        total_price = unit_price * quantity
        
        usage_record = ServiceUsageRecord(
            service_id=service.id,
            patient_id=data.get('patient_id'),
            patient_name=data.get('patient_name'),
            quantity=quantity,
            unit_price=unit_price,
            total_price=total_price,
            notes=data.get('notes', ''),
            recorded_by=current_user.id
        )
        
        db.session.add(usage_record)
        db.session.commit()
        
        # Log audit
        log_audit('CREATE', 'Service Usage', f'Recorded usage of: {service.service_name}')
        
        return jsonify({
            'status': 'success',
            'message': 'Service usage recorded successfully',
            'data': usage_record.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"Error creating service usage: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to record service usage. Please try again.'
        }), 500


@api.route('/services/usage/list', methods=['GET'])
@login_required
def list_service_usage():
    """Get service usage records"""
    try:
        # Get query parameters
        service_id = request.args.get('service_id', type=int)
        patient_id = request.args.get('patient_id', type=int)
        billing_status = request.args.get('billing_status')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        # Build query
        query = ServiceUsageRecord.query
        
        if service_id:
            query = query.filter_by(service_id=service_id)
        
        if patient_id:
            query = query.filter_by(patient_id=patient_id)
        
        if billing_status:
            query = query.filter_by(billing_status=billing_status)
        
        if start_date:
            query = query.filter(ServiceUsageRecord.usage_date >= start_date)
        
        if end_date:
            query = query.filter(ServiceUsageRecord.usage_date <= end_date)
        
        # Order by date descending
        usage_records = query.order_by(
            ServiceUsageRecord.usage_date.desc()
        ).all()
        
        return jsonify({
            'status': 'success',
            'data': [record.to_dict() for record in usage_records],
            'count': len(usage_records)
        }), 200
        
    except Exception as e:
        print(f"Error fetching service usage: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch service usage records'
        }), 500


@api.route('/services/price-history/<int:service_id>', methods=['GET'])
@login_required
def get_price_history(service_id):
    """Get price change history for a service"""
    try:
        service = HospitalService.query.get(service_id)
        
        if not service:
            return jsonify({
                'status': 'error',
                'message': 'Service not found'
            }), 404
        
        price_history = ServicePriceHistory.query.filter_by(
            service_id=service_id
        ).order_by(
            ServicePriceHistory.change_date.desc()
        ).all()
        
        return jsonify({
            'status': 'success',
            'data': [record.to_dict() for record in price_history]
        }), 200
        
    except Exception as e:
        print(f"Error fetching price history: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch price history'
        }), 500




# ============================================
# UPDATED WEBSITE AUTHENTICATION ROUTES
# ============================================

@api.route('/signup', methods=['POST'])
def website_signup():
    """Create website user account - Updated to handle separate name fields"""
    try:
        data = request.get_json()
        
        # Get separate name fields
        first_name = data.get('firstName', '').strip()
        middle_name = data.get('middleName', '').strip()
        last_name = data.get('lastName', '').strip()
        username = data.get('username', '').strip().lower()
        phone = data.get('phone', '').strip()
        password = data.get('password', '').strip()
        
        # Validate required fields (firstName and lastName are required, middleName is optional)
        if not first_name or not last_name or not username or not phone or not password:
            return jsonify({
                'status': 'error',
                'message': 'First name, last name, username, phone, and password are required'
            }), 400
        
        # Validate password length
        if len(password) < 6:
            return jsonify({
                'status': 'error',
                'message': 'Password must be at least 6 characters long'
            }), 400
        
        # Validate username length
        if len(username) < 3:
            return jsonify({
                'status': 'error',
                'message': 'Username must be at least 3 characters long'
            }), 400
        
        # Validate phone number
        if len(phone) < 10:
            return jsonify({
                'status': 'error',
                'message': 'Please enter a valid phone number'
            }), 400
        
        # Check if username already exists
        existing_user = WebsiteUser.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({
                'status': 'error',
                'message': 'This username is already taken'
            }), 400
        
        # Check if phone already exists
        existing_phone = WebsiteUser.query.filter_by(phone=phone).first()
        if existing_phone:
            return jsonify({
                'status': 'error',
                'message': 'This phone number is already registered'
            }), 400
        
        # Construct full_name from separate fields
        # Format: "FirstName MiddleName LastName" or "FirstName LastName" if no middle name
        if middle_name:
            full_name = f"{first_name} {middle_name} {last_name}"
        else:
            full_name = f"{first_name} {last_name}"
        
        # Create new user
        new_user = WebsiteUser(
            full_name=full_name,
            username=username,
            phone=phone
        )
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': f'Welcome {first_name}! Your account has been created successfully. You can now log in.'
        }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"Signup error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': 'An error occurred while creating your account. Please try again.'
        }), 500


@api.route('/website-login', methods=['POST'])
def website_login():
    """Website user login - uses manual session (NOT Flask-Login)"""
    try:
        data = request.get_json()
        
        username = data.get('username', '').strip().lower()
        password = data.get('password', '').strip()
        
        if not username or not password:
            return jsonify({
                'status': 'error',
                'message': 'Username and password are required'
            }), 400
        
        # Find user in database
        user = WebsiteUser.query.filter_by(username=username).first()
        
        # Check if user exists and password matches
        if not user or not user.check_password(password):
            return jsonify({
                'status': 'error',
                'message': 'Invalid username or password'
            }), 401
        
        if not user.is_active:
            return jsonify({
                'status': 'error',
                'message': 'Your account has been deactivated. Please contact support.'
            }), 403
        
        # Update last login time
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        # Grant access via MANUAL SESSION (NOT Flask-Login)
        session['website_user_id'] = user.id
        session['website_user_name'] = user.full_name
        session['website_username'] = user.username
        session.permanent = True
        
        return jsonify({
            'status': 'success',
            'message': f'Welcome back, {user.full_name.split()[0]}!',  # Use first name for greeting
            'redirect': '/website/user-portal',
            'user': {
                'name': user.full_name,
                'username': user.username
            }
        }), 200
        
    except Exception as e:
        print(f"Login error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': 'An error occurred during login. Please try again.'
        }), 500


@api.route('/website-logout', methods=['POST'])
@requires_website_user
def website_logout():
    """Website user logout - clears manual session"""
    try:
        # Clear ONLY website session keys
        session.pop('website_user_id', None)
        session.pop('website_user_name', None)
        session.pop('website_username', None)
        
        return jsonify({
            'status': 'success',
            'message': 'Logged out successfully',
            'redirect': '/website'
        }), 200
        
    except Exception as e:
        print(f"Logout error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'An error occurred during logout'
        }), 500


@api.route('/website-check-session')
def website_check_session():
    """Check if website user is logged in"""
    website_user_id = session.get('website_user_id')
    
    if website_user_id:
        user = db.session.get(WebsiteUser, website_user_id)
        if user:
            return jsonify({
                'authenticated': True,
                'user': {
                    'id': user.id,
                    'name': user.full_name,
                    'username': user.username,
                    'phone': user.phone
                }
            }), 200
    
    return jsonify({
        'authenticated': False
    }), 200


def parse_full_name(full_name):
    """
    Helper function to parse full_name back into components
    Returns: (first_name, middle_name, last_name)
    
    Examples:
        "John Doe" -> ("John", "", "Doe")
        "John Michael Doe" -> ("John", "Michael", "Doe")
        "Juan dela Cruz" -> ("Juan", "dela", "Cruz")
    """
    if not full_name:
        return ("", "", "")
    
    parts = full_name.strip().split()
    
    if len(parts) == 1:
        return (parts[0], "", "")
    elif len(parts) == 2:
        return (parts[0], "", parts[1])
    else:
        # If 3+ parts, first is first name, last is last name, middle is everything in between
        first_name = parts[0]
        last_name = parts[-1]
        middle_name = " ".join(parts[1:-1])
        return (first_name, middle_name, last_name)


@api.route('/website-user/profile', methods=['GET'])
@requires_website_user
def get_website_user_profile():
    """Get current website user's profile with parsed name"""
    try:
        website_user_id = session.get('website_user_id')
        user = db.session.get(WebsiteUser, website_user_id)
        
        if not user:
            return jsonify({
                'status': 'error',
                'message': 'User not found'
            }), 404
        
        # Parse full name into components
        first_name, middle_name, last_name = parse_full_name(user.full_name)
        
        return jsonify({
            'status': 'success',
            'data': {
                'id': user.id,
                'full_name': user.full_name,
                'first_name': first_name,
                'middle_name': middle_name,
                'last_name': last_name,
                'username': user.username,
                'phone': user.phone,
                'is_active': user.is_active,
                'created_date': user.created_date.isoformat() if user.created_date else None,
                'last_login': user.last_login.isoformat() if user.last_login else None
            }
        }), 200
        
    except Exception as e:
        print(f"Error fetching user profile: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch profile'
        }), 500



# ============================================
# WEBSITE USER ROUTES (Appointments, Messages)
# ============================================

@api.route('/appointment/book', methods=['POST'])
@requires_website_user
def book_appointment():
    """Book a new appointment"""
    try:
        from models import Appointment
        
        data = request.get_json()
        website_user_id = session.get('website_user_id')
        user = db.session.get(WebsiteUser, website_user_id)
        
        # Validate required fields
        service_type = data.get('serviceType', '').strip()
        doctor = data.get('doctor', '').strip()
        appointment_date_str = data.get('appointmentDate', '').strip()
        appointment_time = data.get('appointmentTime', '').strip()
        reason = data.get('reason', '').strip()
        
        if not all([service_type, doctor, appointment_date_str, appointment_time, reason]):
            return jsonify({
                'status': 'error',
                'message': 'All required fields must be filled'
            }), 400
        
        # Parse appointment date
        try:
            appointment_date = datetime.strptime(appointment_date_str, '%Y-%m-%d').date()
        except ValueError:
            return jsonify({
                'status': 'error',
                'message': 'Invalid date format'
            }), 400
        
        # Check if date is in the past
        if appointment_date < datetime.now().date():
            return jsonify({
                'status': 'error',
                'message': 'Cannot book appointments in the past'
            }), 400
        
        # Create new appointment
        appointment = Appointment(
            patient_id=user.id,
            patient_name=user.full_name,
            patient_username=user.username,
            service_type=service_type,
            department=data.get('department', '').strip() if data.get('department') else None,
            doctor=doctor,
            appointment_date=appointment_date,
            appointment_time=appointment_time,
            reason=reason,
            room_type=data.get('roomType', '').strip() if data.get('roomType') else None,
            duration=int(data.get('duration', 0)) if data.get('duration') else None,
            status='Pending'
        )
        
        db.session.add(appointment)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Appointment booked successfully!',
            'data': appointment.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"Error booking appointment: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to book appointment. Please try again.'
        }), 500


@api.route('/appointment/list', methods=['GET'])
@requires_website_user
def list_appointments():
    """Get all appointments for current website user"""
    try:
        from models import Appointment
        
        website_user_id = session.get('website_user_id')
        
        # Get all appointments for current user
        appointments = Appointment.query.filter_by(
            patient_id=website_user_id
        ).order_by(Appointment.appointment_date.desc()).all()
        
        # Get today's date for comparison
        today = datetime.now().date()
        
        upcoming = []
        past = []
        
        for apt in appointments:
            apt_dict = apt.to_dict()
            
            # Determine if appointment should be in upcoming or past
            # Past appointments include:
            # 1. All cancelled appointments
            # 2. All rejected appointments
            # 3. Approved appointments where date has passed
            # 4. Any appointment where date has passed
            
            if apt.status == 'Cancelled':
                # All cancelled go to past
                past.append(apt_dict)
            elif apt.status == 'Rejected':
                # All rejected go to past
                past.append(apt_dict)
            elif apt.appointment_date < today:
                # Date has passed - goes to past regardless of status
                past.append(apt_dict)
            else:
                # Future dates with non-cancelled/non-rejected status go to upcoming
                upcoming.append(apt_dict)
        
        return jsonify({
            'status': 'success',
            'data': {
                'upcoming': upcoming,
                'past': past
            }
        }), 200
        
    except Exception as e:
        print(f"Error fetching appointments: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch appointments'
        }), 500


@api.route('/services/professional-fees', methods=['GET'])
@requires_website_user
def get_professional_fees_for_website():
    """
    Returns all active Professional Fee services.
    Used to populate the Service Type dropdown in the booking modal.
    """
    try:
        services = (
            HospitalService.query
            .filter_by(category='Professional Fee', status='Active')
            .order_by(HospitalService.service_name.asc())
            .all()
        )

        data = [
            {
                'id': s.id,
                'service_name': s.service_name,
                'price': float(s.price),
                'description': s.description
            }
            for s in services
        ]

        return jsonify({
            'status': 'success',
            'data': data
        }), 200

    except Exception as e:
        print(f"Error fetching professional fees: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch services'
        }), 500


@api.route('/employees/departments', methods=['GET'])
@requires_website_user
def get_employee_departments():
    """Get all unique departments from employees"""
    try:
        departments = db.session.query(Employee.department).distinct().filter(
            Employee.status == 'Active'
        ).order_by(Employee.department.asc()).all()
        
        department_list = [dept[0] for dept in departments if dept[0]]
        
        return jsonify({
            'status': 'success',
            'data': department_list
        }), 200
        
    except Exception as e:
        print(f"Error fetching departments: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch departments'
        }), 500


@api.route('/employees/by-department/<department>', methods=['GET'])
@requires_website_user
def get_employees_by_department(department):
    """Get all active employees in a specific department"""
    try:
        employees = Employee.query.filter_by(
            department=department,
            status='Active'
        ).order_by(Employee.name.asc()).all()
        
        employee_list = [
            {
                'id': emp.id,
                'name': emp.name,
                'email': emp.email,
                'department': emp.department
            }
            for emp in employees
        ]
        
        return jsonify({
            'status': 'success',
            'data': employee_list
        }), 200
        
    except Exception as e:
        print(f"Error fetching employees: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch employees'
        }), 500


@api.route('/employees/all-doctors', methods=['GET'])
@requires_website_user
def get_all_doctors():
    """Get all active employees (doctors) from all departments"""
    try:
        employees = Employee.query.filter_by(
            status='Active'
        ).order_by(Employee.department.asc(), Employee.name.asc()).all()
        
        employee_list = [
            {
                'id': emp.id,
                'name': emp.name,
                'email': emp.email,
                'department': emp.department
            }
            for emp in employees
        ]
        
        return jsonify({
            'status': 'success',
            'data': employee_list
        }), 200
        
    except Exception as e:
        print(f"Error fetching all doctors: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch doctors'
        }), 500



@api.route('/services/rooms', methods=['GET'])
@requires_website_user
def get_rooms_for_website():
    """
    Returns all active Room services.
    Used to populate the Room Type dropdown in the booking modal.
    """
    try:
        rooms = (
            HospitalService.query
            .filter_by(category='Room', status='Active')
            .order_by(HospitalService.price.asc())
            .all()
        )

        data = [
            {
                'id': r.id,
                'service_name': r.service_name,
                'price': float(r.price),
                'description': r.description,
                'is_available': r.is_available,
                'quantity_available': r.quantity_available
            }
            for r in rooms
        ]

        return jsonify({
            'status': 'success',
            'data': data
        }), 200

    except Exception as e:
        print(f"Error fetching rooms: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch rooms'
        }), 500



@api.route('/message/send', methods=['POST'])
@requires_website_user
def send_message():
    """Send a new message"""
    try:
        from models import Message
        
        data = request.get_json()
        website_user_id = session.get('website_user_id')
        user = db.session.get(WebsiteUser, website_user_id)
        
        # Validate required fields
        recipient = data.get('recipient', '').strip()
        subject = data.get('subject', '').strip()
        category = data.get('category', '').strip()
        message_body = data.get('messageBody', '').strip()
        priority = data.get('priority', 'normal').strip()
        
        if not all([recipient, subject, category, message_body]):
            return jsonify({
                'status': 'error',
                'message': 'All required fields must be filled'
            }), 400
        
        # Create new message
        message = Message(
            sender_id=user.id,
            sender_name=user.full_name,
            sender_type='patient',
            recipient=recipient,
            subject=subject,
            category=category,
            message_body=message_body,
            priority=priority,
            is_read=False
        )
        
        db.session.add(message)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Message sent successfully!',
            'data': message.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"Error sending message: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to send message. Please try again.'
        }), 500


@api.route('/message/list', methods=['GET'])
@requires_website_user
def list_messages():
    """Get all sent messages for current website user"""
    try:
        from models import Message
        
        website_user_id = session.get('website_user_id')
        
        # Get all messages sent by current user
        messages = Message.query.filter_by(
            sender_id=website_user_id
        ).order_by(Message.sent_date.desc()).all()
        
        return jsonify({
            'status': 'success',
            'data': [msg.to_dict() for msg in messages]
        }), 200
        
    except Exception as e:
        print(f"Error fetching messages: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch messages'
        }), 500


@api.route('/message/inbox', methods=['GET'])
@requires_website_user
def get_inbox():
    """Get inbox messages (received messages) - placeholder for now"""
    try:
        # For now, return empty inbox
        # In future, you can implement admin/doctor replies
        return jsonify({
            'status': 'success',
            'data': []
        }), 200
        
    except Exception as e:
        print(f"Error fetching inbox: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch inbox'
        }), 500


@api.route('/message/<int:message_id>', methods=['GET'])
@requires_website_user
def get_message(message_id):
    """Get single message details"""
    try:
        from models import Message
        
        message = Message.query.get_or_404(message_id)
        website_user_id = session.get('website_user_id')
        
        # Check if message belongs to current user
        if message.sender_id != website_user_id:
            return jsonify({
                'status': 'error',
                'message': 'Unauthorized'
            }), 403
        
        return jsonify({
            'status': 'success',
            'data': message.to_dict()
        }), 200
        
    except Exception as e:
        print(f"Error fetching message: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch message'
        }), 500


@api.route('/message/reply', methods=['POST'])
@requires_website_user
def reply_message():
    """Reply to a message"""
    try:
        from models import Message
        
        data = request.get_json()
        website_user_id = session.get('website_user_id')
        user = db.session.get(WebsiteUser, website_user_id)
        
        parent_message_id = data.get('parentMessageId')
        message_body = data.get('messageBody', '').strip()
        priority = data.get('priority', 'normal').strip()
        
        if not message_body:
            return jsonify({
                'status': 'error',
                'message': 'Message body is required'
            }), 400
        
        if not parent_message_id:
            return jsonify({
                'status': 'error',
                'message': 'Parent message ID is required'
            }), 400
        
        # Get parent message
        parent_message = Message.query.get_or_404(parent_message_id)
        
        # Verify user owns the parent message
        if parent_message.sender_id != website_user_id:
            return jsonify({
                'status': 'error',
                'message': 'Unauthorized'
            }), 403
        
        # Create reply
        reply = Message(
            sender_id=user.id,
            sender_name=user.full_name,
            sender_type='patient',
            recipient=parent_message.recipient,
            subject=f"Re: {parent_message.subject}",
            category=parent_message.category,
            message_body=message_body,
            priority=priority,
            parent_message_id=parent_message_id,
            is_read=False
        )
        
        db.session.add(reply)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Reply sent successfully!',
            'data': reply.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"Error sending reply: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to send reply'
        }), 500


@api.route('/message/delete/<int:message_id>', methods=['DELETE'])
@requires_website_user
def delete_message(message_id):
    """Delete a message"""
    try:
        from models import Message
        
        message = Message.query.get_or_404(message_id)
        website_user_id = session.get('website_user_id')
        
        # Check if message belongs to current user
        if message.sender_id != website_user_id:
            return jsonify({
                'status': 'error',
                'message': 'Unauthorized'
            }), 403
        
        db.session.delete(message)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Message deleted successfully'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting message: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to delete message'
        }), 500


@api.route('/message/mark-read/<int:message_id>', methods=['POST'])
@requires_website_user
def mark_message_read(message_id):
    """Mark a message as read"""
    try:
        from models import Message
        
        message = Message.query.get_or_404(message_id)
        website_user_id = session.get('website_user_id')
        
        # Check if message belongs to current user
        if message.sender_id != website_user_id:
            return jsonify({
                'status': 'error',
                'message': 'Unauthorized'
            }), 403
        
        message.is_read = True
        message.read_date = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Message marked as read'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error marking message as read: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to mark message as read'
        }), 500


@api.route('/appointment/cancel/<int:appointment_id>', methods=['POST'])
@requires_website_user
def cancel_appointment(appointment_id):
    """Cancel an appointment"""
    try:
        from models import Appointment
        
        appointment = Appointment.query.get_or_404(appointment_id)
        website_user_id = session.get('website_user_id')
        
        # Check if appointment belongs to current user
        if appointment.patient_id != website_user_id:
            return jsonify({
                'status': 'error',
                'message': 'Unauthorized'
            }), 403
        
        # Check if appointment is already cancelled
        if appointment.status == 'Cancelled':
            return jsonify({
                'status': 'error',
                'message': 'Appointment is already cancelled'
            }), 400
        
        # Update status
        appointment.status = 'Cancelled'
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Appointment cancelled successfully'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error cancelling appointment: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to cancel appointment'
        }), 500


@api.route('/appointment/<int:appointment_id>', methods=['GET'])
@requires_website_user
def get_appointment(appointment_id):
    """Get single appointment details"""
    try:
        from models import Appointment
        
        appointment = Appointment.query.get_or_404(appointment_id)
        website_user_id = session.get('website_user_id')
        
        # Check if appointment belongs to current user
        if appointment.patient_id != website_user_id:
            return jsonify({
                'status': 'error',
                'message': 'Unauthorized'
            }), 403
        
        return jsonify({
            'status': 'success',
            'data': appointment.to_dict()
        }), 200
        
    except Exception as e:
        print(f"Error fetching appointment: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch appointment'
        }), 500


@api.route('/appointment/update/<int:appointment_id>', methods=['PUT'])
@requires_website_user
def update_appointment(appointment_id):
    """Update appointment (reschedule)"""
    try:
        from models import Appointment
        
        appointment = Appointment.query.get_or_404(appointment_id)
        website_user_id = session.get('website_user_id')
        
        # Check if appointment belongs to current user
        if appointment.patient_id != website_user_id:
            return jsonify({
                'status': 'error',
                'message': 'Unauthorized'
            }), 403
        
        # Check if appointment can be updated
        if appointment.status == 'Cancelled':
            return jsonify({
                'status': 'error',
                'message': 'Cannot update cancelled appointment'
            }), 400
        
        data = request.get_json()
        
        # Update appointment date and time if provided
        if data.get('appointmentDate'):
            try:
                appointment_date = datetime.strptime(data['appointmentDate'], '%Y-%m-%d').date()
                if appointment_date < datetime.now().date():
                    return jsonify({
                        'status': 'error',
                        'message': 'Cannot reschedule to past date'
                    }), 400
                appointment.appointment_date = appointment_date
            except ValueError:
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid date format'
                }), 400
        
        if data.get('appointmentTime'):
            appointment.appointment_time = data['appointmentTime']
        
        if data.get('reason'):
            appointment.reason = data['reason'].strip()
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Appointment updated successfully',
            'data': appointment.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error updating appointment: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to update appointment'
        }), 500



@api.route('/patient/check-info', methods=['GET'])
@requires_website_user
def check_patient_info():
    """Check if patient information exists for current website user"""
    try:
        website_user_id = session.get('website_user_id')
        user = db.session.get(WebsiteUser, website_user_id)
        
        if not user:
            return jsonify({
                'status': 'error',
                'message': 'User not found'
            }), 404
        
        # Parse the full name to get first, middle, last names
        first_name, middle_name, last_name = parse_full_name(user.full_name)
        
        # Check if a patient record exists with matching name components
        patient = Patient.query.filter(
            Patient.first_name == first_name,
            Patient.last_name == last_name
        ).first()
        
        # If middle name exists in user profile, also check that
        if middle_name:
            patient = Patient.query.filter(
                Patient.first_name == first_name,
                Patient.middle_name == middle_name,
                Patient.last_name == last_name
            ).first()
        
        if patient:
            return jsonify({
                'status': 'success',
                'exists': True,
                'message': 'Patient information found'
            }), 200
        else:
            return jsonify({
                'status': 'success',
                'exists': False,
                'message': 'Patient information not found'
            }), 200
            
    except Exception as e:
        print(f"Error checking patient info: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to check patient information'
        }), 500


@api.route('/patient/info', methods=['GET'])
@requires_website_user
def get_patient_info():
    """Get patient information for current website user"""
    try:
        website_user_id = session.get('website_user_id')
        user = db.session.get(WebsiteUser, website_user_id)
        
        if not user:
            return jsonify({
                'status': 'error',
                'message': 'User not found'
            }), 404
        
        # Parse the full name to get first, middle, last names
        first_name, middle_name, last_name = parse_full_name(user.full_name)
        
        # Find patient record with matching name
        patient = Patient.query.filter(
            Patient.first_name == first_name,
            Patient.last_name == last_name
        ).first()
        
        # If middle name exists, also check that
        if middle_name:
            patient = Patient.query.filter(
                Patient.first_name == first_name,
                Patient.middle_name == middle_name,
                Patient.last_name == last_name
            ).first()
        
        if not patient:
            return jsonify({
                'status': 'success',
                'exists': False,
                'message': 'Patient information not found'
            }), 200
        
        return jsonify({
            'status': 'success',
            'exists': True,
            'data': {
                'patient_id': patient.patient_id,
                'first_name': patient.first_name,
                'middle_name': patient.middle_name,
                'last_name': patient.last_name,
                'birthdate': patient.date_of_birth.strftime('%Y-%m-%d') if patient.date_of_birth else None,
                'gender': patient.gender,
                'blood_type': patient.blood_type,
                'civil_status': patient.civil_status,
                'email': patient.email,
                'phone': patient.mobile,
                'address': patient.address,
                'emergency_name': patient.emergency_contact_name,
                'emergency_relation': patient.emergency_contact_relationship,
                'emergency_phone': patient.emergency_contact_phone,
                'emergency_email': patient.emergency_contact_email,
                'allergies': patient.allergies,
                'conditions': patient.chronic_conditions,
                'medications': patient.current_medications,
                'insurance_provider': patient.insurance_provider,
                'policy_number': patient.policy_number
            }
        }), 200
        
    except Exception as e:
        print(f"Error fetching patient info: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch patient information'
        }), 500


@api.route('/patient/save', methods=['POST'])
@requires_website_user
def save_patient_info():
    """Save or update patient information for current website user"""
    try:
        website_user_id = session.get('website_user_id')
        user = db.session.get(WebsiteUser, website_user_id)
        
        if not user:
            return jsonify({
                'status': 'error',
                'message': 'User not found'
            }), 404
        
        data = request.get_json()
        
        # Get name fields
        first_name = data.get('firstName', '').strip()
        middle_name = data.get('middleName', '').strip()
        last_name = data.get('lastName', '').strip()
        
        # Validate required fields
        if not first_name or not last_name:
            return jsonify({
                'status': 'error',
                'message': 'First name and last name are required'
            }), 400
        
        # Parse birthdate
        birthdate = None
        if data.get('birthdate'):
            try:
                birthdate = datetime.strptime(data['birthdate'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid date format for birthdate'
                }), 400
        
        # Check if patient record already exists
        patient = Patient.query.filter(
            Patient.first_name == first_name,
            Patient.last_name == last_name
        ).first()
        
        if middle_name and patient:
            patient = Patient.query.filter(
                Patient.first_name == first_name,
                Patient.middle_name == middle_name,
                Patient.last_name == last_name
            ).first()
        
        if patient:
            # UPDATE existing patient record
            patient.middle_name = middle_name if middle_name else None
            patient.date_of_birth = birthdate
            patient.gender = data.get('gender', patient.gender)
            patient.blood_type = data.get('bloodType')
            patient.civil_status = data.get('civilStatus')
            patient.email = data.get('email', '').strip() if data.get('email') else None
            patient.mobile = data.get('phone', patient.mobile).strip()
            patient.address = data.get('address', patient.address).strip()
            patient.emergency_contact_name = data.get('emergencyName', patient.emergency_contact_name).strip()
            patient.emergency_contact_relationship = data.get('emergencyRelation', patient.emergency_contact_relationship).strip()
            patient.emergency_contact_phone = data.get('emergencyPhone', patient.emergency_contact_phone).strip()
            patient.emergency_contact_email = data.get('emergencyEmail', '').strip() if data.get('emergencyEmail') else None
            patient.allergies = data.get('allergies', '').strip() if data.get('allergies') else None
            patient.chronic_conditions = data.get('conditions', '').strip() if data.get('conditions') else None
            patient.current_medications = data.get('medications', '').strip() if data.get('medications') else None
            patient.insurance_provider = data.get('insuranceProvider')
            patient.policy_number = data.get('policyNumber', '').strip() if data.get('policyNumber') else None
            
            db.session.commit()
            
            return jsonify({
                'status': 'success',
                'message': 'Patient information updated successfully',
                'data': patient.to_dict()
            }), 200
            
        else:
            # CREATE new patient record
            # Generate patient ID
            year = datetime.now().year
            count = Patient.query.filter(Patient.patient_id.like(f'PT-{year}-%')).count() + 1
            patient_id = f'PT-{year}-{str(count).zfill(5)}'
            
            # Validate required fields for new patient
            if not all([first_name, last_name, birthdate, data.get('gender'), 
                       data.get('phone'), data.get('address')]):
                return jsonify({
                    'status': 'error',
                    'message': 'All required fields must be filled'
                }), 400
            
            # Create new patient
            patient = Patient(
                patient_id=patient_id,
                first_name=first_name,
                middle_name=middle_name if middle_name else None,
                last_name=last_name,
                date_of_birth=birthdate,
                gender=data.get('gender'),
                blood_type=data.get('bloodType'),
                civil_status=data.get('civilStatus'),
                email=data.get('email', '').strip() if data.get('email') else None,
                mobile=data.get('phone').strip(),
                address=data.get('address').strip(),
                city='N/A',  # Default value since not in form
                province='N/A',  # Default value since not in form
                emergency_contact_name=data.get('emergencyName', '').strip(),
                emergency_contact_relationship=data.get('emergencyRelation', '').strip(),
                emergency_contact_phone=data.get('emergencyPhone', '').strip(),
                emergency_contact_email=data.get('emergencyEmail', '').strip() if data.get('emergencyEmail') else None,
                allergies=data.get('allergies', '').strip() if data.get('allergies') else None,
                chronic_conditions=data.get('conditions', '').strip() if data.get('conditions') else None,
                current_medications=data.get('medications', '').strip() if data.get('medications') else None,
                insurance_provider=data.get('insuranceProvider'),
                policy_number=data.get('policyNumber', '').strip() if data.get('policyNumber') else None,
                status='Active'
            )
            
            db.session.add(patient)
            db.session.commit()
            
            return jsonify({
                'status': 'success',
                'message': 'Patient information saved successfully',
                'data': patient.to_dict()
            }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"Error saving patient info: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': 'Failed to save patient information. Please try again.'
        }), 500





# DOCTOR APPOINTMENTS ROUTES - ALIGNED WITH FRONT DESK PATTERN
@api.route('/doctor/appointments', methods=['GET'])
@login_required
def doctor_get_appointments():
    """Get all appointments for current doctor - ALIGNED WITH FRONT DESK"""
    try:
        from models import Appointment
        
        # Get doctor's full name from current_user
        doctor_name = current_user.full_name
        
        # Fetch appointments for this doctor only (filter by doctor name)
        appointments = Appointment.query.filter_by(
            doctor=doctor_name
        ).order_by(
            Appointment.appointment_date.desc(),
            Appointment.appointment_time.desc()
        ).all()
        
        return jsonify({
            'status': 'success',
            'data': [apt.to_dict() for apt in appointments]
        }), 200
        
    except Exception as e:
        print(f"Error fetching appointments: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch appointments'
        }), 500


@api.route('/doctor/appointment/approve/<int:appointment_id>', methods=['POST'])
@login_required
def doctor_approve_appointment(appointment_id):
    """Approve appointment - ALIGNED WITH FRONT DESK ACCEPT"""
    try:
        from models import Appointment
        
        appointment = Appointment.query.get_or_404(appointment_id)
        
        # Verify this appointment belongs to the current doctor
        if appointment.doctor != current_user.full_name:
            return jsonify({
                'status': 'error',
                'message': 'Unauthorized - This appointment is not assigned to you'
            }), 403
        
        # Only approve if status is "Waiting to Approved"
        if appointment.status != 'Waiting to Approved':
            return jsonify({
                'status': 'error',
                'message': 'Only appointments waiting for approval can be approved'
            }), 400
        
        # Update status to Approved
        appointment.status = 'Approved'
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Appointment approved successfully',
            'data': appointment.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error approving appointment: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to approve appointment'
        }), 500


@api.route('/doctor/appointment/reject/<int:appointment_id>', methods=['POST'])
@login_required
def doctor_reject_appointment(appointment_id):
    """Reject appointment - ALIGNED WITH FRONT DESK REJECT"""
    try:
        from models import Appointment
        
        appointment = Appointment.query.get_or_404(appointment_id)
        
        # Verify this appointment belongs to the current doctor
        if appointment.doctor != current_user.full_name:
            return jsonify({
                'status': 'error',
                'message': 'Unauthorized - This appointment is not assigned to you'
            }), 403
        
        # Only reject if status is "Waiting to Approved"
        if appointment.status != 'Waiting to Approved':
            return jsonify({
                'status': 'error',
                'message': 'Only appointments waiting for approval can be rejected'
            }), 400
        
        # Update status to Rejected
        appointment.status = 'Rejected'
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Appointment rejected',
            'data': appointment.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error rejecting appointment: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to reject appointment'
        }), 500


@api.route('/doctor/appointment/complete/<int:appointment_id>', methods=['POST'])
@login_required
def doctor_complete_appointment(appointment_id):
    """Complete appointment - DOCTOR ONLY ACTION"""
    try:
        from models import Appointment
        
        appointment = Appointment.query.get_or_404(appointment_id)
        
        # Verify this appointment belongs to the current doctor
        if appointment.doctor != current_user.full_name:
            return jsonify({
                'status': 'error',
                'message': 'Unauthorized - This appointment is not assigned to you'
            }), 403
        
        # Only complete if status is "Approved"
        if appointment.status != 'Approved':
            return jsonify({
                'status': 'error',
                'message': 'Only approved appointments can be completed'
            }), 400
        
        # Check if appointment date is today or has passed
        today = datetime.now().date()
        if appointment.appointment_date > today:
            return jsonify({
                'status': 'error',
                'message': 'Cannot complete future appointments'
            }), 400
        
        # Update status to Completed
        appointment.status = 'Completed'
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Appointment completed successfully',
            'data': appointment.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error completing appointment: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to complete appointment'
        }), 500


@api.route('/doctor/appointment/<int:appointment_id>', methods=['GET'])
@login_required
def doctor_get_appointment(appointment_id):
    """Get single appointment details - ALIGNED WITH FRONT DESK"""
    try:
        from models import Appointment
        
        appointment = Appointment.query.get_or_404(appointment_id)
        
        # Verify this appointment belongs to the current doctor
        if appointment.doctor != current_user.full_name:
            return jsonify({
                'status': 'error',
                'message': 'Unauthorized - This appointment is not assigned to you'
            }), 403
        
        return jsonify({
            'status': 'success',
            'data': appointment.to_dict()
        }), 200
        
    except Exception as e:
        print(f"Error fetching appointment: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch appointment'
        }), 500

@api.route('/doctor/admitted-patients', methods=['GET'])
@login_required
def doctor_get_admitted_patients():
    """Get admitted patients for current doctor"""
    try:
        from models import PatientAdmission
        from datetime import datetime
        
        # Get current doctor's name
        doctor_name = current_user.full_name
        
        # Get all admitted patients assigned to this doctor
        admitted_patients = PatientAdmission.query.filter_by(
            doctor_name=doctor_name,
            status='Admitted'
        ).order_by(PatientAdmission.admission_date.desc()).all()
        
        # Calculate days admitted for each patient
        result = []
        for patient in admitted_patients:
            patient_dict = patient.to_dict()
            
            # Calculate days admitted
            if patient.admission_date:
                days_admitted = (datetime.now() - patient.admission_date).days
                patient_dict['days_admitted'] = days_admitted
            else:
                patient_dict['days_admitted'] = 0
            
            result.append(patient_dict)
        
        return jsonify({
            'status': 'success',
            'data': result
        }), 200
        
    except Exception as e:
        print(f"Error fetching admitted patients: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch admitted patients'
        }), 500

@api.route('/doctor/patient-admission/<int:admission_id>', methods=['GET'])
@login_required
def doctor_get_patient_admission(admission_id):
    """Get single patient admission details for doctor"""
    try:
        from models import PatientAdmission
        from datetime import datetime
        
        # Get patient admission
        admission = PatientAdmission.query.get_or_404(admission_id)
        
        # Verify this patient is assigned to current doctor
        if admission.doctor_name != current_user.full_name:
            return jsonify({
                'status': 'error',
                'message': 'Unauthorized - This patient is not assigned to you'
            }), 403
        
        # Prepare patient data
        patient_dict = admission.to_dict()
        
        # Calculate days admitted
        if admission.admission_date:
            days_admitted = (datetime.now() - admission.admission_date).days
            patient_dict['days_admitted'] = days_admitted
        else:
            patient_dict['days_admitted'] = 0
        
        return jsonify({
            'status': 'success',
            'data': patient_dict
        }), 200
        
    except Exception as e:
        print(f"Error fetching patient admission: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch patient data'
        }), 500


@api.route('/doctor/outpatient-appointments', methods=['GET'])
@login_required
def doctor_get_outpatient_appointments():
    """
    Get approved appointments for current doctor (Out Patient list)
    Shows only appointments with status='Approved' for today's date
    """
    try:
        from models import Appointment
        from datetime import date
        
        # Get current doctor's name
        doctor_name = current_user.full_name
        
        # Get today's date
        today = date.today()
        
        # Fetch approved appointments for this doctor for today
        # These will appear in the Out Patient section
        outpatients = Appointment.query.filter_by(
            doctor=doctor_name,
            status='Approved',
            appointment_date=today
        ).order_by(Appointment.appointment_time.asc()).all()
        
        return jsonify({
            'status': 'success',
            'data': [apt.to_dict() for apt in outpatients]
        }), 200
        
    except Exception as e:
        print(f"Error fetching out patient appointments: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch out patient appointments'
        }), 500


@api.route('/doctor/outpatient-appointment/<int:appointment_id>', methods=['GET'])
@login_required
def doctor_get_outpatient_appointment(appointment_id):
    """
    Get appointment details with patient info for out patient medical records
    This is called when doctor clicks 'Medical Records' button
    """
    try:
        from models import Appointment, Patient, Employee
        
        # Get appointment
        appointment = Appointment.query.get_or_404(appointment_id)
        
        # Verify this appointment is for current doctor
        if appointment.doctor != current_user.full_name:
            return jsonify({
                'status': 'error',
                'message': 'Unauthorized'
            }), 403
        
        # Get doctor specialty from Employee table
        doctor = Employee.query.filter_by(name=current_user.full_name).first()
        doctor_specialty = doctor.department if doctor else 'General Practice'
        
        # Try to find matching patient record in Patient table
        # Parse patient name from appointment
        patient_name_parts = appointment.patient_name.strip().split()
        patient_record = None
        
        if len(patient_name_parts) >= 2:
            first_name = patient_name_parts[0]
            last_name = patient_name_parts[-1]
            
            # Try to find patient record
            patient_record = Patient.query.filter(
                Patient.first_name == first_name,
                Patient.last_name == last_name
            ).first()
        
        # Prepare appointment data
        apt_dict = appointment.to_dict()
        apt_dict['doctor_specialty'] = doctor_specialty
        
        # Add patient info if found in Patient table
        if patient_record:
            apt_dict['patient_id'] = patient_record.patient_id
            apt_dict['patient_gender'] = patient_record.gender
            apt_dict['patient_blood_type'] = patient_record.blood_type
            apt_dict['patient_mobile'] = patient_record.mobile
            apt_dict['patient_email'] = patient_record.email
            apt_dict['patient_address'] = patient_record.address
        
        return jsonify({
            'status': 'success',
            'data': apt_dict
        }), 200
        
    except Exception as e:
        print(f"Error fetching out patient appointment: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch appointment data'
        }), 500


# OPTIONAL: If you want to filter by date range or other criteria
@api.route('/doctor/outpatient-appointments/filter', methods=['GET'])
@login_required
def doctor_filter_outpatient_appointments():
    """
    Get approved appointments with optional date filtering
    Query parameters:
    - date: Specific date (YYYY-MM-DD format)
    - start_date: Start of date range
    - end_date: End of date range
    """
    try:
        from models import Appointment
        from datetime import datetime, date
        
        # Get current doctor's name
        doctor_name = current_user.full_name
        
        # Get query parameters
        date_param = request.args.get('date')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        # Build query
        query = Appointment.query.filter_by(
            doctor=doctor_name,
            status='Approved'
        )
        
        # Apply date filters
        if date_param:
            # Specific date
            filter_date = datetime.strptime(date_param, '%Y-%m-%d').date()
            query = query.filter_by(appointment_date=filter_date)
        elif start_date and end_date:
            # Date range
            start = datetime.strptime(start_date, '%Y-%m-%d').date()
            end = datetime.strptime(end_date, '%Y-%m-%d').date()
            query = query.filter(
                Appointment.appointment_date >= start,
                Appointment.appointment_date <= end
            )
        else:
            # Default to today
            today = date.today()
            query = query.filter_by(appointment_date=today)
        
        outpatients = query.order_by(Appointment.appointment_time.asc()).all()
        
        return jsonify({
            'status': 'success',
            'data': [apt.to_dict() for apt in outpatients]
        }), 200
        
    except Exception as e:
        print(f"Error filtering out patient appointments: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch appointments'
        }), 500





















