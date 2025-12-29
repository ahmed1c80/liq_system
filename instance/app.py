from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField
from wtforms.validators import DataRequired, Email
from datetime import datetime, timedelta
import pandas as pd
import numpy as np
from sklearn.linear_model import LinearRegression
import eventlet
import json

app = Flask(__name__)
app.config.from_object('config.Config')

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

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

# Forms
class LoginForm(FlaskForm):
    username = StringField('اسم المستخدم', validators=[DataRequired()])
    password = PasswordField('كلمة المرور', validators=[DataRequired()])

class RegistrationForm(FlaskForm):
    username = StringField('اسم المستخدم', validators=[DataRequired()])
    email = StringField('البريد الإلكتروني', validators=[DataRequired(), Email()])
    password = PasswordField('كلمة المرور', validators=[DataRequired()])
    role = SelectField('الدور', choices=[
        ('auditor', 'مراجع'),
        ('manager', 'مدير فرع'),
        ('admin', 'مدير النظام')
    ])

# AI Prediction Model
class LiquidityPredictor:
    def __init__(self):
        self.model = LinearRegression()
    
    def train(self, historical_data):
        """Train the prediction model on historical data"""
        X = np.array(range(len(historical_data))).reshape(-1, 1)
        y = np.array(historical_data)
        self.model.fit(X, y)
    
    def predict(self, days_ahead=7):
        """Predict liquidity for future days"""
        future_days = np.array(range(days_ahead)).reshape(-1, 1)
        predictions = self.model.predict(future_days)
        return predictions.tolist()

# Authentication
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
@login_required
def index():
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.password == form.password.data:  # In production, use hashed passwords
            login_user(user)
            return redirect(url_for('dashboard'))
    
    return render_template('auth/login.html', form=form, rtl=True)
@app.context_processor
def inject_now():
    return {'now': datetime.now}
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get user's branch or all branches for admin
    if current_user.role == 'admin':
        branches = Branch.query.all()
    else:
        branches = [current_user.branch] if current_user.branch else []
    
    # Calculate current liquidity for each branch
    branch_data = []
    for branch in branches:
        recent_record = LiquidityRecord.query.filter_by(branch_id=branch.id)\
            .order_by(LiquidityRecord.timestamp.desc()).first()
        
        if recent_record:
            current_liquidity = recent_record.current_liquidity
            alerts = recent_record.alerts or []
        else:
            current_liquidity = 0
            alerts = []
        
        branch_data.append({
            'id': branch.id,
            'name': branch.name,
            'code': branch.code,
            'current_liquidity': current_liquidity,
            'min_liquidity': branch.min_liquidity,
            'max_liquidity': branch.max_liquidity,
            'alerts': alerts
        })
    
    return render_template('dashboard/main.html', 
                         branches=branch_data,
                         user_role=current_user.role,
                         rtl=True,  now=datetime.now())

# WebSocket for real-time updates
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        emit('connection_response', {'data': 'Connected successfully'})

@socketio.on('request_liquidity_update')
def handle_liquidity_update():
    """Send real-time liquidity updates to clients"""
    while True:
        eventlet.sleep(30)  # Update every 30 seconds
        
        if current_user.is_authenticated:
            if current_user.role == 'admin':
                branches = Branch.query.all()
            else:
                branches = [current_user.branch]
            
            for branch in branches:
                recent_record = LiquidityRecord.query.filter_by(branch_id=branch.id)\
                    .order_by(LiquidityRecord.timestamp.desc()).first()
                
                if recent_record:
                    emit('liquidity_update', {
                        'branch_id': branch.id,
                        'liquidity': recent_record.current_liquidity,
                        'timestamp': recent_record.timestamp.isoformat(),
                        'alerts': recent_record.alerts or []
                    })
        else:
            break

# API Endpoints
@app.route('/api/liquidity/<int:branch_id>', methods=['GET'])
@login_required
def get_liquidity(branch_id):
    """Get current liquidity for a branch"""
    branch = Branch.query.get_or_404(branch_id)
    
    # Check permission
    if current_user.role != 'admin' and current_user.branch_id != branch_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    recent_record = LiquidityRecord.query.filter_by(branch_id=branch_id)\
        .order_by(LiquidityRecord.timestamp.desc()).first()
    
    if recent_record:
        return jsonify({
            'current': recent_record.current_liquidity,
            'predicted': recent_record.predicted_liquidity,
            'min': branch.min_liquidity,
            'max': branch.max_liquidity,
            'timestamp': recent_record.timestamp.isoformat()
        })
    
    return jsonify({'current': 0, 'predicted': 0})

@app.route('/api/predict/<int:branch_id>', methods=['GET'])
@login_required
def predict_liquidity(branch_id):
    """Predict liquidity for next 7 days"""
    # Get last 30 days of liquidity data
    records = LiquidityRecord.query.filter_by(branch_id=branch_id)\
        .order_by(LiquidityRecord.timestamp.desc())\
        .limit(30)\
        .all()
    
    historical_data = [record.current_liquidity for record in reversed(records)]
    
    if len(historical_data) >= 7:
        predictor = LiquidityPredictor()
        predictor.train(historical_data)
        predictions = predictor.predict(7)
        
        return jsonify({
            'predictions': predictions,
            'historical': historical_data[-7:]  # Last 7 days for comparison
        })
    
    return jsonify({'error': 'Insufficient data for prediction'}), 400

@app.route('/api/transfer', methods=['POST'])
@login_required
def transfer_funds():
    """Transfer funds between branches"""
    if current_user.role not in ['admin', 'manager']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.json
    from_branch_id = data.get('from_branch')
    to_branch_id = data.get('to_branch')
    amount = data.get('amount')
    
    # Validate
    if amount <= 0:
        return jsonify({'error': 'Invalid amount'}), 400
    
    # Check if source branch has sufficient liquidity
    from_branch = Branch.query.get(from_branch_id)
    from_record = LiquidityRecord.query.filter_by(branch_id=from_branch_id)\
        .order_by(LiquidityRecord.timestamp.desc()).first()
    
    if from_record.current_liquidity < amount:
        return jsonify({'error': 'Insufficient funds'}), 400
    
    # Create transactions
    withdrawal = Transaction(
        branch_id=from_branch_id,
        amount=-amount,
        transaction_type='transfer_out',
        description=f'Transfer to branch {to_branch_id}'
    )
    
    deposit = Transaction(
        branch_id=to_branch_id,
        amount=amount,
        transaction_type='transfer_in',
        description=f'Transfer from branch {from_branch_id}'
    )
    
    db.session.add_all([withdrawal, deposit])
    db.session.commit()
    
    # Update liquidity records
    update_liquidity_record(from_branch_id)
    update_liquidity_record(to_branch_id)
    
    return jsonify({'message': 'Transfer successful'})

def update_liquidity_record(branch_id):
    """Update liquidity record for a branch"""
    # Calculate current liquidity from transactions
    transactions = Transaction.query.filter_by(branch_id=branch_id).all()
    total = sum(t.amount for t in transactions)
    
    # Create new record
    record = LiquidityRecord(
        branch_id=branch_id,
        current_liquidity=total
    )
    
    # Check for alerts
    branch = Branch.query.get(branch_id)
    alerts = []
    
    if total < branch.min_liquidity * 0.8:  # Below 80% of minimum
        alerts.append({
            'type': 'critical',
            'message': 'السيولة أقل من الحد الأدنى المسموح به',
            'severity': 'high'
        })
    elif total < branch.min_liquidity:
        alerts.append({
            'type': 'warning',
            'message': 'السيولة قريبة من الحد الأدنى',
            'severity': 'medium'
        })
    
    record.alerts = alerts
    db.session.add(record)
    db.session.commit()
    
    # Send real-time alert if needed
    if alerts:
        socketio.emit('new_alert', {
            'branch_id': branch_id,
            'alerts': alerts
        })

# Initialize database
@app.before_first_request
def create_tables():
    db.create_all()
    
    # Create admin user if not exists
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@bank.com',
            password='admin123',  # Change in production
            role='admin'
        )
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)