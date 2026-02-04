from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

# ADMIN & USER ACCOUNTS
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


# AUDIT LOGS
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


# EMPLOYEES
class Employee(db.Model):
    """Employees table"""
    __tablename__ = 'employees'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    gender = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    contact_number = db.Column(db.String(20), nullable=True)
    address = db.Column(db.Text, nullable=True)
    department = db.Column(db.String(50), nullable=False, index=True)
    status = db.Column(db.String(20), default='Active')
    created_date = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('admin_accounts.id'))
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'gender': self.gender,
            'email': self.email,
            'contact_number': self.contact_number,
            'address': self.address,
            'department': self.department,
            'status': self.status,
            'created_date': self.created_date.strftime('%Y-%m-%d') if self.created_date else None
        }
    
    def __repr__(self):
        return f'<Employee {self.name} - {self.department}>'


# BUSINESS OFFICE BACKEND.HTML
# PATIENTS
class Patient(db.Model):
    """Patients table for Front Desk patient registration"""
    __tablename__ = 'patients'
    
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.String(20), unique=True, nullable=False)
    
    # Personal Information
    first_name = db.Column(db.String(50), nullable=False)
    middle_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)
    gender = db.Column(db.String(20), nullable=False)
    blood_type = db.Column(db.String(10))  # NEW FIELD
    civil_status = db.Column(db.String(20))
    
    # Contact Information
    email = db.Column(db.String(100))  # Moved up to match form order
    mobile = db.Column(db.String(20), nullable=False)
    address = db.Column(db.Text, nullable=False)
    city = db.Column(db.String(50), nullable=False)
    province = db.Column(db.String(50))
    
    # Emergency Contact
    emergency_contact_name = db.Column(db.String(100), nullable=False)
    emergency_contact_relationship = db.Column(db.String(50), nullable=False)
    emergency_contact_phone = db.Column(db.String(20), nullable=False)
    emergency_contact_email = db.Column(db.String(100))  # NEW FIELD
    
    # Medical Information - NEW SECTION
    allergies = db.Column(db.Text)
    chronic_conditions = db.Column(db.Text)
    current_medications = db.Column(db.Text)
    
    # Insurance Information
    insurance_provider = db.Column(db.String(100))
    policy_number = db.Column(db.String(100))
    
    # System fields
    status = db.Column(db.String(20), default='Active')
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user_accounts.id'))
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'patient_id': self.patient_id,
            'first_name': self.first_name,
            'middle_name': self.middle_name,
            'last_name': self.last_name,
            'full_name': f"{self.first_name} {self.middle_name or ''} {self.last_name}".strip(),
            'date_of_birth': self.date_of_birth.strftime('%Y-%m-%d'),
            'gender': self.gender,
            'blood_type': self.blood_type,  # NEW
            'civil_status': self.civil_status,
            'email': self.email,
            'mobile': self.mobile,
            'address': self.address,
            'city': self.city,
            'province': self.province,
            'emergency_contact_name': self.emergency_contact_name,
            'emergency_contact_relationship': self.emergency_contact_relationship,
            'emergency_contact_phone': self.emergency_contact_phone,
            'emergency_contact_email': self.emergency_contact_email,  # NEW
            'allergies': self.allergies,  # NEW
            'chronic_conditions': self.chronic_conditions,  # NEW
            'current_medications': self.current_medications,  # NEW
            'insurance_provider': self.insurance_provider,
            'policy_number': self.policy_number,
            'status': self.status,
            'registration_date': self.registration_date.strftime('%b %d, %Y')
        }
    
    def __repr__(self):
        return f'<Patient {self.patient_id} - {self.first_name} {self.last_name}>'


# PHARMACY INVENTORY 
class InventoryProduct(db.Model):
    """Inventory Product Model"""
    __tablename__ = 'inventory_products'
    
    id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    current_stock = db.Column(db.Integer, nullable=False, default=0)
    reorder_level = db.Column(db.Integer, nullable=False, default=50)
    cost_price = db.Column(db.Numeric(10, 2), nullable=False)
    selling_price = db.Column(db.Numeric(10, 2), nullable=False)
    margin_percentage = db.Column(db.Numeric(5, 2), nullable=True)
    
    # Status tracking
    status = db.Column(db.String(20), default='Active')  # Active, Inactive, Discontinued
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # User tracking
    created_by = db.Column(db.Integer, nullable=True)
    updated_by = db.Column(db.Integer, nullable=True)
    
    def calculate_margin(self):
        """Calculate profit margin percentage"""
        if self.cost_price and self.cost_price > 0:
            margin = ((self.selling_price - self.cost_price) / self.cost_price) * 100
            return round(float(margin), 2)
        return 0.0
    
    def get_stock_status(self):
        """Get stock status based on current stock and reorder level"""
        if self.current_stock <= 0:
            return 'out_of_stock'
        elif self.current_stock < self.reorder_level:
            return 'low'
        elif self.current_stock < (self.reorder_level * 2):
            return 'medium'
        else:
            return 'high'
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'product_name': self.product_name,
            'category': self.category,
            'current_stock': self.current_stock,
            'reorder_level': self.reorder_level,
            'cost_price': float(self.cost_price),
            'selling_price': float(self.selling_price),
            'margin_percentage': self.calculate_margin(),
            'stock_status': self.get_stock_status(),
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class InventoryTransaction(db.Model):
    """Inventory Transaction History"""
    __tablename__ = 'inventory_transactions'
    
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('inventory_products.id'), nullable=False)
    transaction_type = db.Column(db.String(50), nullable=False)  # RESTOCK, SALE, ADJUSTMENT, RETURN
    quantity = db.Column(db.Integer, nullable=False)
    previous_stock = db.Column(db.Integer, nullable=False)
    new_stock = db.Column(db.Integer, nullable=False)
    notes = db.Column(db.Text, nullable=True)
    
    # Timestamps
    transaction_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    # User tracking
    performed_by = db.Column(db.Integer, nullable=True)
    
    # Relationship
    product = db.relationship('InventoryProduct', backref='transactions')
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'product_id': self.product_id,
            'product_name': self.product.product_name if self.product else None,
            'transaction_type': self.transaction_type,
            'quantity': self.quantity,
            'previous_stock': self.previous_stock,
            'new_stock': self.new_stock,
            'notes': self.notes,
            'transaction_date': self.transaction_date.isoformat() if self.transaction_date else None,
            'performed_by': self.performed_by
        }


# PHARMACY SALES TRANSACTIONS
class PharmacySale(db.Model):
    """Pharmacy Sales/Transactions table"""
    __tablename__ = 'pharmacy_sales'
    
    id = db.Column(db.Integer, primary_key=True)
    receipt_number = db.Column(db.String(50), unique=True, nullable=False)
    
    # Transaction Details
    sale_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    payment_method = db.Column(db.String(50), nullable=False)  # cash, card, gcash, paymaya
    
    # Financial Details
    subtotal = db.Column(db.Numeric(10, 2), nullable=False)
    discount_percentage = db.Column(db.Numeric(5, 2), default=0)
    discount_amount = db.Column(db.Numeric(10, 2), default=0)
    tax_amount = db.Column(db.Numeric(10, 2), nullable=False)
    total_amount = db.Column(db.Numeric(10, 2), nullable=False)
    
    # Payment Details
    amount_received = db.Column(db.Numeric(10, 2), nullable=False)
    change_amount = db.Column(db.Numeric(10, 2), nullable=False)
    
    # Cost & Profit
    total_cost = db.Column(db.Numeric(10, 2), nullable=False)  # Sum of all item costs
    total_profit = db.Column(db.Numeric(10, 2), nullable=False)  # total_amount - total_cost
    
    # User tracking
    user_id = db.Column(db.Integer, db.ForeignKey('user_accounts.id'), nullable=False)
    user_name = db.Column(db.String(100), nullable=False)  # Store name for quick access
    
    # Relationships
    items = db.relationship('PharmacySaleItem', backref='sale', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'receipt_number': self.receipt_number,
            'sale_date': self.sale_date.isoformat() if self.sale_date else None,
            'payment_method': self.payment_method,
            'subtotal': float(self.subtotal),
            'discount_percentage': float(self.discount_percentage),
            'discount_amount': float(self.discount_amount),
            'tax_amount': float(self.tax_amount),
            'total_amount': float(self.total_amount),
            'amount_received': float(self.amount_received),
            'change_amount': float(self.change_amount),
            'total_cost': float(self.total_cost),
            'total_profit': float(self.total_profit),
            'user_id': self.user_id,
            'user_name': self.user_name,
            'items': [item.to_dict() for item in self.items]
        }


class PharmacySaleItem(db.Model):
    """Individual items in a pharmacy sale"""
    __tablename__ = 'pharmacy_sale_items'
    
    id = db.Column(db.Integer, primary_key=True)
    sale_id = db.Column(db.Integer, db.ForeignKey('pharmacy_sales.id'), nullable=False)
    
    # Product Details
    product_id = db.Column(db.Integer, db.ForeignKey('inventory_products.id'), nullable=False)
    product_name = db.Column(db.String(200), nullable=False)
    
    # Transaction Details
    quantity = db.Column(db.Integer, nullable=False)
    unit_price = db.Column(db.Numeric(10, 2), nullable=False)  # Selling price at time of sale
    unit_cost = db.Column(db.Numeric(10, 2), nullable=False)   # Cost price at time of sale
    
    # Calculated fields
    item_total = db.Column(db.Numeric(10, 2), nullable=False)  # quantity * unit_price
    item_cost_total = db.Column(db.Numeric(10, 2), nullable=False)  # quantity * unit_cost
    item_profit = db.Column(db.Numeric(10, 2), nullable=False)  # item_total - item_cost_total
    
    # Relationship
    product = db.relationship('InventoryProduct', backref='sales')
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'sale_id': self.sale_id,
            'product_id': self.product_id,
            'product_name': self.product_name,
            'quantity': self.quantity,
            'unit_price': float(self.unit_price),
            'unit_cost': float(self.unit_cost),
            'item_total': float(self.item_total),
            'item_cost_total': float(self.item_cost_total),
            'item_profit': float(self.item_profit)
        }


# SERVICE INVENTORY
class HospitalService(db.Model):
    """Hospital Services Model - Rooms, Diagnostics, Procedures, etc."""
    __tablename__ = 'hospital_services'
    
    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100), nullable=False, index=True)  # Room, Diagnostic, Procedure, Professional Fee, Medication, Other
    price = db.Column(db.Numeric(10, 2), nullable=False)
    description = db.Column(db.Text, nullable=True)
    
    # Availability tracking (for rooms and equipment)
    is_available = db.Column(db.Boolean, default=True)
    quantity_available = db.Column(db.Integer, nullable=True)  # For services with limited availability
    
    # Status tracking
    status = db.Column(db.String(20), default='Active')  # Active, Inactive
    
    # Pricing history
    previous_price = db.Column(db.Numeric(10, 2), nullable=True)
    price_last_updated = db.Column(db.DateTime, nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # User tracking
    created_by = db.Column(db.Integer, nullable=True)
    updated_by = db.Column(db.Integer, nullable=True)
    
    # Relationships
    usage_records = db.relationship('ServiceUsageRecord', backref='service', lazy=True)
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'service_name': self.service_name,
            'category': self.category,
            'price': float(self.price),
            'description': self.description,
            'is_available': self.is_available,
            'quantity_available': self.quantity_available,
            'status': self.status,
            'previous_price': float(self.previous_price) if self.previous_price else None,
            'price_last_updated': self.price_last_updated.isoformat() if self.price_last_updated else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def __repr__(self):
        return f'<HospitalService {self.service_name} - ₱{self.price}>'


class ServiceUsageRecord(db.Model):
    """Service Usage Records - Track when services are used"""
    __tablename__ = 'service_usage_records'
    
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey('hospital_services.id'), nullable=False)
    
    # Patient Information (if applicable)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=True)
    patient_name = db.Column(db.String(100), nullable=True)
    
    # Usage Details
    usage_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    quantity = db.Column(db.Integer, default=1, nullable=False)
    
    # Pricing at time of usage
    unit_price = db.Column(db.Numeric(10, 2), nullable=False)
    total_price = db.Column(db.Numeric(10, 2), nullable=False)
    
    # Billing status
    billing_status = db.Column(db.String(20), default='Pending')  # Pending, Billed, Paid
    billed_date = db.Column(db.DateTime, nullable=True)
    payment_date = db.Column(db.DateTime, nullable=True)
    
    # Additional details
    notes = db.Column(db.Text, nullable=True)
    
    # User tracking
    recorded_by = db.Column(db.Integer, nullable=True)
    
    # Relationship
    patient = db.relationship('Patient', backref='service_usage')
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'service_id': self.service_id,
            'service_name': self.service.service_name if self.service else None,
            'service_category': self.service.category if self.service else None,
            'patient_id': self.patient_id,
            'patient_name': self.patient_name,
            'usage_date': self.usage_date.isoformat() if self.usage_date else None,
            'quantity': self.quantity,
            'unit_price': float(self.unit_price),
            'total_price': float(self.total_price),
            'billing_status': self.billing_status,
            'billed_date': self.billed_date.isoformat() if self.billed_date else None,
            'payment_date': self.payment_date.isoformat() if self.payment_date else None,
            'notes': self.notes,
            'recorded_by': self.recorded_by
        }
    
    def __repr__(self):
        return f'<ServiceUsageRecord {self.id} - {self.service.service_name if self.service else "N/A"}>'


class ServicePriceHistory(db.Model):
    """Track price changes for services"""
    __tablename__ = 'service_price_history'
    
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey('hospital_services.id'), nullable=False)
    
    # Price change details
    old_price = db.Column(db.Numeric(10, 2), nullable=False)
    new_price = db.Column(db.Numeric(10, 2), nullable=False)
    change_percentage = db.Column(db.Numeric(5, 2), nullable=False)
    
    # Change tracking
    change_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    reason = db.Column(db.Text, nullable=True)
    
    # User tracking
    changed_by = db.Column(db.Integer, nullable=True)
    
    # Relationship
    service = db.relationship('HospitalService', backref='price_history')
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'service_id': self.service_id,
            'service_name': self.service.service_name if self.service else None,
            'old_price': float(self.old_price),
            'new_price': float(self.new_price),
            'change_percentage': float(self.change_percentage),
            'change_date': self.change_date.isoformat() if self.change_date else None,
            'reason': self.reason,
            'changed_by': self.changed_by
        }
    
    def __repr__(self):
        return f'<ServicePriceHistory {self.service.service_name if self.service else "N/A"} - ₱{self.old_price} → ₱{self.new_price}>'


class PatientAdmission(db.Model):
    __tablename__ = 'patient_admissions'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Patient Info (from form)
    patient_name = db.Column(db.String(200), nullable=False)
    gender = db.Column(db.String(20), nullable=False)
    
    # Doctor Info (from form)
    doctor_name = db.Column(db.String(200), nullable=False)
    
    # Room Info (from form)
    room_type = db.Column(db.String(100), nullable=False)
    
    # Financial Info (from form)
    deposit_amount = db.Column(db.Numeric(10, 2), default=0)
    
    # Auto-generated fields
    admission_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(50), default='Admitted')  # Changed from 'Active' to 'Admitted'
    
    # Tracking
    admitted_by = db.Column(db.Integer, db.ForeignKey('user_accounts.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'patient_name': self.patient_name,
            'gender': self.gender,
            'doctor_name': self.doctor_name,
            'room_type': self.room_type,
            'deposit_amount': float(self.deposit_amount) if self.deposit_amount else 0,
            'admission_date': self.admission_date.strftime('%Y-%m-%d %H:%M:%S') if self.admission_date else None,
            'status': self.status,
            'days_admitted': (datetime.utcnow() - self.admission_date).days if self.admission_date else 0
        }


class WebsiteUser(db.Model, UserMixin):
    """Website user accounts table"""
    __tablename__ = 'website_users'
    
    id = db.Column(db.Integer, primary_key=True)

    # Name (stored as one field, parsed when needed)
    full_name = db.Column(db.String(150), nullable=False)

    # Login credentials
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    # Contact
    phone = db.Column(db.String(20), unique=True, nullable=False, index=True)

    # Status & audit
    is_active = db.Column(db.Boolean, default=True)
    created_date = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    # -------------------------
    # PASSWORD METHODS
    # -------------------------
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # -------------------------
    # FLASK-LOGIN COMPAT
    # -------------------------
    def get_id(self):
        # Keep this if you mix user types elsewhere
        return f'website_{self.id}'

    def __repr__(self):
        return f'<WebsiteUser {self.username}>'


# APPOINTMENTS
class Appointment(db.Model):
    """Patient Appointments table"""
    __tablename__ = 'appointments'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Patient Information
    patient_id = db.Column(db.Integer, db.ForeignKey('website_users.id'), nullable=False)
    patient_name = db.Column(db.String(100), nullable=False)
    patient_username = db.Column(db.String(100), nullable=False)
    
    # Appointment Details
    service_type = db.Column(db.String(50), nullable=False)
    department = db.Column(db.String(100))
    doctor = db.Column(db.String(100), nullable=False)
    appointment_date = db.Column(db.Date, nullable=False, index=True)
    appointment_time = db.Column(db.String(10), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    
    # Room Booking (if service_type is 'room')
    room_type = db.Column(db.String(50))
    duration = db.Column(db.Integer)
    
    # Status
    status = db.Column(db.String(20), default='Pending')
    
    # Timestamps
    created_date = db.Column(db.DateTime, default=datetime.utcnow)
    updated_date = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship
    patient = db.relationship('WebsiteUser', backref='appointments')
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'patient_id': self.patient_id,
            'patient_name': self.patient_name,
            'patient_username': self.patient_username,
            'service_type': self.service_type,
            'department': self.department,
            'doctor': self.doctor,
            'appointment_date': self.appointment_date.strftime('%Y-%m-%d'),
            'appointment_time': self.appointment_time,
            'reason': self.reason,
            'room_type': self.room_type,
            'duration': self.duration,
            'status': self.status,
            'created_date': self.created_date.strftime('%Y-%m-%d %H:%M:%S'),
            'updated_date': self.updated_date.strftime('%Y-%m-%d %H:%M:%S')
        }
    
    def __repr__(self):
        return f'<Appointment {self.id} - {self.patient_name} - {self.doctor}>'


# MESSAGES
class Message(db.Model):
    """Messages table for patient-doctor communication"""
    __tablename__ = 'messages'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Sender Information
    sender_id = db.Column(db.Integer, db.ForeignKey('website_users.id'), nullable=False)
    sender_name = db.Column(db.String(100), nullable=False)
    sender_type = db.Column(db.String(20), default='patient')
    
    # Recipient Information
    recipient = db.Column(db.String(100), nullable=False)
    
    # Message Details
    subject = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    message_body = db.Column(db.Text, nullable=False)
    priority = db.Column(db.String(20), default='normal')
    
    # Status
    is_read = db.Column(db.Boolean, default=False)
    
    # Reply tracking
    parent_message_id = db.Column(db.Integer, db.ForeignKey('messages.id'), nullable=True)
    
    # Timestamps
    sent_date = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    read_date = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    sender = db.relationship('WebsiteUser', backref='sent_messages', foreign_keys=[sender_id])
    replies = db.relationship('Message', backref=db.backref('parent', remote_side=[id]), lazy='dynamic')
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'sender_id': self.sender_id,
            'sender_name': self.sender_name,
            'sender_type': self.sender_type,
            'recipient': self.recipient,
            'subject': self.subject,
            'category': self.category,
            'message_body': self.message_body,
            'priority': self.priority,
            'is_read': self.is_read,
            'parent_message_id': self.parent_message_id,
            'sent_date': self.sent_date.strftime('%Y-%m-%d %H:%M:%S'),
            'read_date': self.read_date.strftime('%Y-%m-%d %H:%M:%S') if self.read_date else None
        }
    
    def __repr__(self):
        return f'<Message {self.id} - {self.sender_name} to {self.recipient}>'


# DATABASE INITIALIZATION
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

