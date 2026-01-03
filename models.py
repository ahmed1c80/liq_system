from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

from flask_login import  UserMixin
db = SQLAlchemy()

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='auditor')
    branch_id = db.Column(db.Integer, db.ForeignKey('branch.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

class Branch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(10), unique=True, nullable=False)
    location = db.Column(db.String(200))
    min_liquidity = db.Column(db.Float, default=1000000.0)  # Minimum required liquidity
    max_liquidity = db.Column(db.Float, default=5000000.0)  # Maximum capacity
    
    # Relationships
    users = db.relationship('User', backref='branch', lazy=True)
    transactions = db.relationship('Transaction', backref='branch', lazy=True)
    liquidity_records = db.relationship('LiquidityRecord', backref='branch', lazy=True)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    branch_id = db.Column(db.Integer, db.ForeignKey('branch.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    transaction_type = db.Column(db.String(20))  # deposit, withdrawal, transfer
    description = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='completed')

class LiquidityRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    branch_id = db.Column(db.Integer, db.ForeignKey('branch.id'), nullable=False)
    current_liquidity = db.Column(db.Float, nullable=False)
    predicted_liquidity = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    alerts = db.Column(db.JSON)  # Store alert information

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    branch_id = db.Column(db.Integer, db.ForeignKey('branch.id'), nullable=False)
    alert_type = db.Column(db.String(50))  # low_liquidity, high_liquidity, suspicious_activity
    message = db.Column(db.String(500))
    severity = db.Column(db.String(20))  # low, medium, high
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)



# Add these models after existing models

class RiskCategory(db.Model):
    """تصنيفات المخاطر"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(20), unique=True, nullable=False)
    description = db.Column(db.Text)
    color = db.Column(db.String(7), default='#3b82f6')  # Hex color
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    risks = db.relationship('Risk', backref='category', lazy=True)
    indicators = db.relationship('RiskIndicator', backref='category', lazy=True)

class Risk(db.Model):
    """سجل المخاطر"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    category_id = db.Column(db.Integer, db.ForeignKey('risk_category.id'), nullable=False)
    branch_id = db.Column(db.Integer, db.ForeignKey('branch.id'), nullable=False)
    
    # Risk Assessment
    impact = db.Column(db.Integer, default=3)  # 1-5 scale
    likelihood = db.Column(db.Integer, default=3)  # 1-5 scale
    risk_score = db.Column(db.Float)  # Calculated: impact * likelihood
    
    # Risk Status
    status = db.Column(db.String(20), default='open')  # open, in_progress, mitigated, closed
    priority = db.Column(db.String(20), default='medium')  # low, medium, high, critical
    
    # Basel III Compliance
    basel_category = db.Column(db.String(50))  # Credit Risk, Market Risk, Operational Risk, Liquidity Risk
    capital_requirement = db.Column(db.Float)  # Capital required for this risk
    
    # Dates
    identified_date = db.Column(db.DateTime, default=datetime.utcnow)
    target_resolution_date = db.Column(db.DateTime)
    actual_resolution_date = db.Column(db.DateTime)
    
    # Responsibility
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Financial Impact
    potential_loss = db.Column(db.Float)  # Potential financial loss
    actual_loss = db.Column(db.Float)  # Actual financial loss occurred
    mitigation_cost = db.Column(db.Float)  # Cost to mitigate
    
    # Relationships
    controls = db.relationship('RiskControl', backref='risk', lazy=True)
    actions = db.relationship('RiskAction', backref='risk', lazy=True)
    assessments = db.relationship('RiskAssessment', backref='risk', lazy=True)
    
    # Metadata
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

class RiskControl(db.Model):
    """ضوابط المخاطر"""
    id = db.Column(db.Integer, primary_key=True)
    risk_id = db.Column(db.Integer, db.ForeignKey('risk.id'), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    control_type = db.Column(db.String(50))  # preventive, detective, corrective
    effectiveness = db.Column(db.Integer, default=3)  # 1-5 scale
    implementation_status = db.Column(db.String(20), default='pending')  # pending, implemented, testing, operational
    implemented_date = db.Column(db.DateTime)
    review_frequency = db.Column(db.String(50))  # daily, weekly, monthly, quarterly, annually
    last_review_date = db.Column(db.DateTime)
    next_review_date = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class RiskAction(db.Model):
    """إجراءات معالجة المخاطر"""
    id = db.Column(db.Integer, primary_key=True)
    risk_id = db.Column(db.Integer, db.ForeignKey('risk.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    action_type = db.Column(db.String(50))  # mitigation, transfer, avoid, accept
    status = db.Column(db.String(20), default='pending')  # pending, in_progress, completed, cancelled
    priority = db.Column(db.String(20), default='medium')
    
    # Dates
    due_date = db.Column(db.DateTime)
    start_date = db.Column(db.DateTime)
    completion_date = db.Column(db.DateTime)
    
    # Responsibility
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    assigned_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Progress
    progress_percentage = db.Column(db.Integer, default=0)  # 0-100
    notes = db.Column(db.Text)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class RiskAssessment(db.Model):
    """تقييمات المخاطر"""
    id = db.Column(db.Integer, primary_key=True)
    risk_id = db.Column(db.Integer, db.ForeignKey('risk.id'), nullable=False)
    assessment_date = db.Column(db.DateTime, default=datetime.utcnow)
    assessed_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Scores
    impact_score = db.Column(db.Integer)  # 1-5
    likelihood_score = db.Column(db.Integer)  # 1-5
    residual_risk_score = db.Column(db.Float)  # After controls
    
    # Changes
    impact_change = db.Column(db.Integer, default=0)  # -2 to +2
    likelihood_change = db.Column(db.Integer, default=0)  # -2 to +2
    
    # Comments
    comments = db.Column(db.Text)
    recommendations = db.Column(db.Text)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class RiskIndicator(db.Model):
    """مؤشرات المخاطر (KRI)"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    code = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.Text)
    category_id = db.Column(db.Integer, db.ForeignKey('risk_category.id'))
    unit = db.Column(db.String(20))  # %, number, currency, etc.
    data_source = db.Column(db.String(200))  # Where data comes from
    
    # Thresholds
    green_min = db.Column(db.Float)
    green_max = db.Column(db.Float)
    yellow_min = db.Column(db.Float)
    yellow_max = db.Column(db.Float)
    red_min = db.Column(db.Float)
    red_max = db.Column(db.Float)
    
    # Basel III Alignment
    basel_component = db.Column(db.String(100))  # LCR, NSFR, etc.
    
    # Frequency
    monitoring_frequency = db.Column(db.String(50))  # daily, weekly, monthly
    collection_frequency = db.Column(db.String(50))
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class RiskIndicatorValue(db.Model):
    """قيم مؤشرات المخاطر"""
    id = db.Column(db.Integer, primary_key=True)
    indicator_id = db.Column(db.Integer, db.ForeignKey('risk_indicator.id'), nullable=False)
    branch_id = db.Column(db.Integer, db.ForeignKey('branch.id'), nullable=False)
    
    # Value
    value = db.Column(db.Float, nullable=False)
    calculated_value = db.Column(db.Float)  # For derived indicators
    value_date = db.Column(db.DateTime, nullable=False)
    
    # Status
    status = db.Column(db.String(20))  # green, yellow, red
    deviation = db.Column(db.Float) # % deviation from target
    
    # Metadata
    collected_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    collection_method = db.Column(db.String(50))  # manual, automated, imported
    notes = db.Column(db.Text)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class RiskIncident(db.Model):
    """حوادث المخاطر"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    category_id = db.Column(db.Integer, db.ForeignKey('risk_category.id'))
    branch_id = db.Column(db.Integer, db.ForeignKey('branch.id'), nullable=False)
    
    # Incident Details
    incident_date = db.Column(db.DateTime, nullable=False)
    discovery_date = db.Column(db.DateTime)
    reporting_date = db.Column(db.DateTime, default=datetime.utcnow)
    resolution_date = db.Column(db.DateTime)
    
    # Impact
    financial_impact = db.Column(db.Float)
    operational_impact = db.Column(db.Text)
    reputational_impact = db.Column(db.Text)
    severity = db.Column(db.String(20))  # low, medium, high, critical
    
    # Root Cause
    root_cause = db.Column(db.Text)
    contributing_factors = db.Column(db.Text)
    
    # Status
    status = db.Column(db.String(20), default='open')  # open, investigating, resolved, closed
    investigation_status = db.Column(db.String(20))
    
    # Responsibility
    reported_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Basel III Reporting
    basel_category = db.Column(db.String(50))
    regulatory_reporting = db.Column(db.Boolean, default=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class RiskReport(db.Model):
    """تقارير المخاطر"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    report_type = db.Column(db.String(50))  # daily, weekly, monthly, quarterly, annual
    period_start = db.Column(db.DateTime, nullable=False)
    period_end = db.Column(db.DateTime, nullable=False)
    generated_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    generated_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Content (stored as JSON for flexibility)
    summary = db.Column(db.JSON)  # Risk summary statistics
    top_risks = db.Column(db.JSON)  # Top risks data
    kri_status = db.Column(db.JSON)  # KRI status
    incidents = db.Column(db.JSON)  # Incidents summary
    recommendations = db.Column(db.JSON)  # Recommendations
    
    # Basel III Compliance
    basel_compliance = db.Column(db.JSON)
    capital_adequacy = db.Column(db.JSON)
    
    # Status
    status = db.Column(db.String(20), default='draft')  # draft, final, published
    approved_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    approval_date = db.Column(db.DateTime)
    
    # Distribution
    distribution_list = db.Column(db.JSON)  # List of users/branches to receive
    last_sent_date = db.Column(db.DateTime)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)