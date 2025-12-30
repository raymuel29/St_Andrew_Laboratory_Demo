from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

# =============================================
# ADMIN & USER ACCOUNTS
# =============================================

class AdminAccount(db.Model, UserMixin):
    """Admin accounts table - for hospital administrators"""
    __tablename__ = 'admin_accounts'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), default='Head of Hospital')
    created_date = db.Column(db.DateTime, default=datetime.utcnow)
    last_password_change = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    created_users = db.relationship('UserAccount', backref='creator', lazy=True, foreign_keys='UserAccount.created_by')
    created_employees = db.relationship('Employee', backref='creator', lazy=True)
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)
        self.last_password_change = datetime.utcnow()
    
    def check_password(self, password):
        """Verify password"""
        return check_password_hash(self.password_hash, password)
    
    def get_id(self):
        """Override get_id for flask-login"""
        return f'admin_{self.id}'
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'username': self.username,
            'full_name': self.full_name,
            'role': self.role,
            'created_date': self.created_date.strftime('%b %d, %Y'),
            'last_password_change': self.last_password_change.strftime('%b %d, %Y'),
            'is_active': self.is_active
        }
    
    def __repr__(self):
        return f'<AdminAccount {self.username}>'


class UserAccount(db.Model, UserMixin):
    """User accounts table - for employees (nurses, lab, pharmacy, etc.)"""
    __tablename__ = 'user_accounts'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # Head of Hospital, Business Office, Laboratory, Pharmacy, Nurse
    created_date = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.Integer, db.ForeignKey('admin_accounts.id'))
    
    # Relationships
    created_patients = db.relationship('Patient', backref='creator', lazy=True)
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verify password"""
        return check_password_hash(self.password_hash, password)
    
    def get_id(self):
        """Override get_id for flask-login"""
        return f'user_{self.id}'
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'username': self.username,
            'full_name': self.full_name,
            'role': self.role,
            'created_date': self.created_date.strftime('%b %d, %Y'),
            'is_active': self.is_active
        }
    
    def __repr__(self):
        return f'<UserAccount {self.username} - {self.role}>'


# =============================================
# AUDIT LOGS
# =============================================

class AuditLog(db.Model):
    """Audit logs table - track all system actions"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    user_type = db.Column(db.String(20), nullable=False)  # 'admin' or 'user'
    user_id = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(50), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    action = db.Column(db.String(50), nullable=False, index=True)  # CREATE, UPDATE, DELETE, LOGIN, LOGOUT
    entity = db.Column(db.String(50), nullable=False)  # Employee, Patient, Admin Account, etc.
    details = db.Column(db.Text, nullable=False)
    ip_address = db.Column(db.String(50), nullable=True)
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'user_type': self.user_type,
            'username': self.username,
            'full_name': self.full_name,
            'action': self.action,
            'entity': self.entity,
            'details': self.details,
            'ip_address': self.ip_address
        }
    
    def __repr__(self):
        return f'<AuditLog {self.action} {self.entity} by {self.username}>'


# =============================================
# EMPLOYEES
# =============================================

class Employee(db.Model):
    """Employees table"""
    __tablename__ = 'employees'
    
    id = db.Column(db.Integer, primary_key=True)
    emp_id = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    department = db.Column(db.String(50), nullable=False, index=True)  # nurses, laboratory, pharmacy, business-office
    role = db.Column(db.String(50), nullable=False)  # admin, manager, staff
    status = db.Column(db.String(20), default='Active')
    created_date = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('admin_accounts.id'))
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'emp_id': self.emp_id,
            'name': self.name,
            'email': self.email,
            'department': self.department,
            'role': self.role,
            'status': self.status,
            'created_date': self.created_date.strftime('%Y-%m-%d')
        }
    
    def __repr__(self):
        return f'<Employee {self.name} - {self.department}>'


# =============================================
# PATIENTS
# =============================================

class Patient(db.Model):
    """Patients table"""
    __tablename__ = 'patients'
    
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    email = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    address = db.Column(db.Text)
    blood_type = db.Column(db.String(10))
    last_visit = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='Active')
    created_date = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user_accounts.id'))
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'patient_id': self.patient_id,
            'name': self.name,
            'age': self.age,
            'email': self.email,
            'phone': self.phone,
            'address': self.address,
            'blood_type': self.blood_type,
            'last_visit': self.last_visit.strftime('%Y-%m-%d') if self.last_visit else None,
            'status': self.status,
            'created_date': self.created_date.strftime('%Y-%m-%d')
        }
    
    def __repr__(self):
        return f'<Patient {self.name} - {self.patient_id}>'


# =============================================
# DATABASE INITIALIZATION
# =============================================
def init_db(app):
    """Initialize database and create default admin account only"""
    db.init_app(app)
    
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Check if default admin exists
        default_admin = AdminAccount.query.filter_by(username='admin').first()
        
        if not default_admin:
            admin = AdminAccount(
                username='admin',
                full_name='John Doe',
                role='Head of Hospital'
            )
            admin.set_password('admin123')
            
            db.session.add(admin)
            db.session.commit()
            
            print('✅ Default admin account created')
            print('   Username: admin')
            print('   Password: admin123')
            print('   Role: Head of Hospital')
        else:
            print('✅ Default admin account already exists')


