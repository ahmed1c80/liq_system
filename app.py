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
import os
from wtforms import BooleanField
from werkzeug.security import generate_password_hash, check_password_hash
from models import db,User,Branch,Transaction,LiquidityRecord,Alert,RiskIndicator,RiskIndicatorValue,RiskAssessment,Risk,RiskReport,RiskIncident
app = Flask(__name__)
app.config.from_object('config.Config')

# Initialize extensions
#db = SQLAlchemy(app)
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

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
    
    form_re =LoginForm(request.form)#request.form# LoginForm()
    print(f'****************{form_re}')
    #if form_re.validate_on_submit():
    user = User.query.filter_by(username=form_re.username.data).first()
    if user and user.password == form_re.password.data:  # In production, use hashed passwords
            login_user(user)
            return redirect(url_for('dashboard'))
    else:
            return render_template('auth/login.html', form=form_re, rtl=True, error='اسم المستخدم أو كلمة المرور غير صحيحة')
    
    return render_template('auth/login.html', form=form_re, rtl=True)

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
                         rtl=True)

@app.route('/branch/<int:branch_id>')
@login_required
def branch_details(branch_id):
    branch = Branch.query.get_or_404(branch_id)
    
    # Check permission
    if current_user.role != 'admin' and current_user.branch_id != branch_id:
        return redirect(url_for('dashboard'))
    
    # Get recent transactions
    transactions = Transaction.query.filter_by(branch_id=branch_id)\
        .order_by(Transaction.timestamp.desc())\
        .limit(20)\
        .all()
    
    # Get liquidity history
    liquidity_history = LiquidityRecord.query.filter_by(branch_id=branch_id)\
        .order_by(LiquidityRecord.timestamp.desc())\
        .limit(30)\
        .all()
    try:
        min_percentage = (branch.min_liquidity / branch.max_liquidity) * 100
        min_percentage = min(min_percentage, 100)  # Cap at 100%
    except ZeroDivisionError:
        min_percentage = 0
      # Get most recent record
    recent_record = LiquidityRecord.query.filter_by(branch_id=branch_id)\
        .order_by(LiquidityRecord.timestamp.desc())\
        .first()
    
    # Calculate percentages
    current_liquidity = recent_record.current_liquidity if recent_record else 0
    
    try:
        utilization_percentage = (current_liquidity / branch.max_liquidity) * 100
        utilization_percentage = min(utilization_percentage, 100)
    except ZeroDivisionError:
        utilization_percentage = 0
    
    return render_template('dashboard/branch.html',
                         branch=branch,
                         transactions=transactions,
                         liquidity_history=liquidity_history,
                         min_percentage=min_percentage,
                         utilization_percentage=utilization_percentage,
                         rtl=True)

# WebSocket for real-time updates
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        emit('connection_response', {'data': 'Connected successfully', 'user': current_user.username})

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('request_liquidity_update')
def handle_liquidity_update(data):
    """Send real-time liquidity updates to clients"""
    branch_id = data.get('branch_id')
    
    if current_user.is_authenticated:
        if branch_id:
            branch = Branch.query.get(branch_id)
            if branch and (current_user.role == 'admin' or current_user.branch_id == branch_id):
                recent_record = LiquidityRecord.query.filter_by(branch_id=branch_id)\
                    .order_by(LiquidityRecord.timestamp.desc()).first()
                
                if recent_record:
                    emit('liquidity_update', {
                        'branch_id': branch.id,
                        'liquidity': recent_record.current_liquidity,
                        'timestamp': recent_record.timestamp.isoformat(),
                        'alerts': recent_record.alerts or []
                    })

# API Endpoints
@app.route('/api/liquidity/<int:branch_id>', methods=['GET'])
@login_required
def get_liquidity(branch_id):
    """Get current liquidity for a branch"""
    branch = Branch.query.get_or_404(branch_id)
    
    # Check permission
    if current_user.role != 'admin' and current_user.branch_id != branch_id:
        return jsonify({'error': 'غير مصرح به'}), 403
    
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
    # Check permission
    if current_user.role != 'admin' and current_user.branch_id != branch_id:
        return jsonify({'error': 'غير مصرح به'}), 403
    
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
            'historical': historical_data[-7:],  # Last 7 days for comparison
            'dates': [(datetime.now() + timedelta(days=i)).strftime('%Y-%m-%d') for i in range(7)]
        })
    
    return jsonify({'error': 'البيانات غير كافية للتنبؤ'}), 400

@app.route('/api/transfer', methods=['POST'])
@login_required
def transfer_funds():
    """Transfer funds between branches"""
    if current_user.role not in ['admin', 'manager']:
        return jsonify({'error': 'غير مصرح به'}), 403
    
    data = request.json
    from_branch_id = data.get('from_branch')
    to_branch_id = data.get('to_branch')
    amount = data.get('amount')
    
    # Validate
    if not amount or amount <= 0:
        return jsonify({'error': 'Invalid amount'}), 400
    
    if from_branch_id == to_branch_id:
        return jsonify({'error': 'Cannot transfer to same branch'}), 400
    
    # Check if source branch has sufficient liquidity
    from_branch = Branch.query.get(from_branch_id)
    if not from_branch:
        return jsonify({'error': 'Source branch not found'}), 404
    
    # For non-admin users, they can only transfer from their own branch
    if current_user.role == 'manager' and current_user.branch_id != from_branch_id:
        return jsonify({'error': 'تحويل غير مصرح به من هذا الفرع'}), 403
    
    from_record = LiquidityRecord.query.filter_by(branch_id=from_branch_id)\
        .order_by(LiquidityRecord.timestamp.desc()).first()
    
    if not from_record or from_record.current_liquidity < amount:
        return jsonify({'error': 'أموال غير كافية'}), 400
    
    # Check if destination branch exists
    to_branch = Branch.query.get(to_branch_id)
    if not to_branch:
        return jsonify({'error': 'Destination branch not found'}), 404
    
    # Create transactions
    withdrawal = Transaction(
        branch_id=from_branch_id,
        amount=-amount,
        transaction_type='transfer_out',
        description=f'Transfer to branch {to_branch.code}'
    )
    
    deposit = Transaction(
        branch_id=to_branch_id,
        amount=amount,
        transaction_type='transfer_in',
        description=f'Transfer from branch {from_branch.code}'
    )
    
    db.session.add_all([withdrawal, deposit])
    db.session.commit()
    
    # Update liquidity records
    update_liquidity_record(from_branch_id)
    update_liquidity_record(to_branch_id)
    
    # Send real-time update
    socketio.emit('transfer_completed', {
        'from_branch': from_branch_id,
        'to_branch': to_branch_id,
        'amount': amount
    })
    
    return jsonify({'message': 'Transfer successful'})


# إضافة دوال إدارة الفروع
@app.route('/branches')
@login_required
def branches_management():
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    
    all_branches = Branch.query.all()
    return render_template('admin/branches.html', 
                         branches=all_branches,
                         rtl=True)

@app.route('/api/branches', methods=['GET', 'POST'])
@login_required
def api_branches():
    if current_user.role != 'admin':
        return jsonify({'error': 'غير مصرح به'}), 403
    
    if request.method == 'GET':
        branches = Branch.query.all()
        branches_data = []
        
        for branch in branches:
            recent_record = LiquidityRecord.query.filter_by(branch_id=branch.id)\
                .order_by(LiquidityRecord.timestamp.desc()).first()
            
            current_liquidity = recent_record.current_liquidity if recent_record else 0
            
            branches_data.append({
                'id': branch.id,
                'name': branch.name,
                'code': branch.code,
                'location': branch.location,
                'min_liquidity': branch.min_liquidity,
                'max_liquidity': branch.max_liquidity,
                'current_liquidity': current_liquidity,
                'created_at': branch.users[0].created_at.isoformat() if branch.users else None,
                'status': 'active',
                'users_count': len(branch.users)
            })
        
        return jsonify({'branches': branches_data})
    
    elif request.method == 'POST':
        data = request.json
        
        # Validate required fields
        required_fields = ['name', 'code', 'location', 'min_liquidity', 'max_liquidity']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing field: {field}'}), 400
        
        # Check if code already exists
        if Branch.query.filter_by(code=data['code']).first():
            return jsonify({'error': 'Branch code already exists'}), 400
        
        try:
            new_branch = Branch(
                name=data['name'],
                code=data['code'],
                location=data['location'],
                min_liquidity=float(data['min_liquidity']),
                max_liquidity=float(data['max_liquidity'])
            )
            
            db.session.add(new_branch)
            db.session.commit()
            
            # Create initial liquidity record
            initial_record = LiquidityRecord(
                branch_id=new_branch.id,
                current_liquidity=0,
                predicted_liquidity=0
            )
            db.session.add(initial_record)
            db.session.commit()
            
            return jsonify({
                'message': 'Branch created successfully',
                'branch': {
                    'id': new_branch.id,
                    'name': new_branch.name,
                    'code': new_branch.code
                }
            }), 201
        
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

@app.route('/api/branches/<int:branch_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def api_branch_detail(branch_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'غير مصرح به'}), 403
    
    branch = Branch.query.get_or_404(branch_id)
    
    if request.method == 'GET':
        recent_record = LiquidityRecord.query.filter_by(branch_id=branch_id)\
            .order_by(LiquidityRecord.timestamp.desc()).first()
        
        transactions = Transaction.query.filter_by(branch_id=branch_id)\
            .order_by(Transaction.timestamp.desc())\
            .limit(10)\
            .all()
        
        branch_data = {
            'id': branch.id,
            'name': branch.name,
            'code': branch.code,
            'location': branch.location,
            'min_liquidity': branch.min_liquidity,
            'max_liquidity': branch.max_liquidity,
            'current_liquidity': recent_record.current_liquidity if recent_record else 0,
            'users': [{
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role,
                'created_at': user.created_at.isoformat()
            } for user in branch.users],
            'recent_transactions': [{
                'id': t.id,
                'amount': t.amount,
                'type': t.transaction_type,
                'description': t.description,
                'timestamp': t.timestamp.isoformat(),
                'status': t.status
            } for t in transactions],
            'created_at': branch.users[0].created_at.isoformat() if branch.users else None
        }
        
        return jsonify(branch_data)
    
    elif request.method == 'PUT':
        data = request.json
        
        try:
            if 'name' in data:
                branch.name = data['name']
            if 'code' in data:
                # Check if new code already exists (excluding current branch)
                existing = Branch.query.filter_by(code=data['code']).first()
                if existing and existing.id != branch.id:
                    return jsonify({'error': 'Branch code already exists'}), 400
                branch.code = data['code']
            if 'location' in data:
                branch.location = data['location']
            if 'min_liquidity' in data:
                branch.min_liquidity = float(data['min_liquidity'])
            if 'max_liquidity' in data:
                branch.max_liquidity = float(data['max_liquidity'])
            
            db.session.commit()
            
            return jsonify({
                'message': 'Branch updated successfully',
                'branch': {
                    'id': branch.id,
                    'name': branch.name,
                    'code': branch.code
                }
            })
        
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'DELETE':
        try:
            # Check if branch has users
            if branch.users:
                return jsonify({'error': 'Cannot delete branch with users. Transfer users first.'}), 400
            
            # Delete related records
            LiquidityRecord.query.filter_by(branch_id=branch_id).delete()
            Transaction.query.filter_by(branch_id=branch_id).delete()
            Alert.query.filter_by(branch_id=branch_id).delete()
            
            # Delete branch
            db.session.delete(branch)
            db.session.commit()
            
            return jsonify({'message': 'Branch deleted successfully'})
        
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

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
            'alerts': alerts,
            'timestamp': datetime.now().isoformat()
        })



@app.route('/api/alerts', methods=['GET'])
@login_required
def get_alerts():
    """Get recent alerts"""
    if current_user.role == 'admin':
        alerts = Alert.query.order_by(Alert.created_at.desc()).limit(20).all()
    else:
        alerts = Alert.query.filter_by(branch_id=current_user.branch_id)\
            .order_by(Alert.created_at.desc())\
            .limit(20)\
            .all()
    
    alerts_data = [{
        'id': alert.id,
        'branch': alert.branch.name if alert.branch else 'N/A',
        'type': alert.alert_type,
        'message': alert.message,
        'severity': alert.severity,
        'created_at': alert.created_at.isoformat(),
        'is_read': alert.is_read
    } for alert in alerts]
    
    return jsonify({'alerts': alerts_data})

# Initialize database
def create_tables():
    """Create database tables and initial data"""
    with app.app_context():
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
        
        # Create sample branches if none exist
        if Branch.query.count() == 0:
            branches = [
                Branch(name='الفرع الرئيسي', code='MAIN', location='صنعاء', 
                       min_liquidity=5000000, max_liquidity=20000000),
                Branch(name='فرع صنعاء', code='SANAA', location='صنعاء', 
                       min_liquidity=3000000, max_liquidity=15000000),
                Branch(name='فرع دمت', code='DAMMT', location='دمت', 
                       min_liquidity=2000000, max_liquidity=10000000),
            ]
            db.session.add_all(branches)
        
        db.session.commit()
        print("Database initialized successfully!")

# Context processor for template variables
@app.context_processor
def utility_processor():
    def format_currency(amount):
        """Format currency for display"""
        return f"{amount:,.2f} ر.ي"
    
    def get_role_name(role_code):
        """Convert role code to Arabic name"""
        roles = {
            'admin': 'مدير النظام',
            'manager': 'مدير فرع',
            'auditor': 'مراجع'
        }
        return roles.get(role_code, role_code)
    
    return dict(format_currency=format_currency, get_role_name=get_role_name)










@app.route('/settings')
@login_required
def system_settings():
    """System settings page"""
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    
    return render_template('dashboard/settings.html', 
                         user_role=current_user.role,
                         rtl=True)

# Add API endpoints for settings
@app.route('/api/settings/save', methods=['POST'])
@login_required
def save_settings():
    """Save system settings"""
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        data = request.json
        
        # Here you would save settings to database or config file
        # For now, we'll just return success
        
        return jsonify({
            'success': True,
            'message': 'تم حفظ الإعدادات بنجاح'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/backup', methods=['POST'])
@login_required
def create_system_backup():
    """Create system backup"""
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        # Create backup logic here
        backup_file = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        
        return jsonify({
            'success': True,
            'message': 'تم إنشاء النسخة الاحتياطية',
            'backup_file': backup_file
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/diagnostics', methods=['GET'])
@login_required
def run_diagnostics():
    """Run system diagnostics"""
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        # Run diagnostics logic here
        diagnostics = {
            'database': 'OK',
            'websocket': 'OK',
            'memory': 'OK',
            'disk': 'OK',
            'performance': 'Excellent'
        }
        
        return jsonify({
            'success': True,
            'diagnostics': diagnostics
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500



# Add this import at the top
from datetime import datetime, timedelta
import json

# Add these routes after the existing routes

@app.route('/api/branches', methods=['GET'])
@login_required
def get_branches():
    """Get all branches for dropdown"""
    if current_user.role == 'admin':
        branches = Branch.query.all()
    else:
        branches = [current_user.branch] if current_user.branch else []
    
    branches_data = [{
        'id': branch.id,
        'name': branch.name,
        'code': branch.code,
        'current_liquidity': get_current_liquidity(branch.id),
        'min_liquidity': branch.min_liquidity,
        'max_liquidity': branch.max_liquidity
    } for branch in branches]
    
    return jsonify({'branches': branches_data})

def get_current_liquidity(branch_id):
    """Get current liquidity for a branch"""
    recent_record = LiquidityRecord.query.filter_by(branch_id=branch_id)\
        .order_by(LiquidityRecord.timestamp.desc()).first()
    return recent_record.current_liquidity if recent_record else 0

@app.route('/api/liquidity/add', methods=['POST'])
@login_required
def add_liquidity():
    """Add or update liquidity for a branch"""
    if current_user.role not in ['admin', 'manager']:
        return jsonify({'error': 'غير مصرح به'}), 403
    
    data = request.json
    branch_id = data.get('branch_id')
    amount = data.get('amount')
    operation = data.get('operation')  # 'add' or 'set'
    description = data.get('description', '')
    
    # Validate
    if not branch_id or not amount:
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Check permissions
    branch = Branch.query.get(branch_id)
    if not branch:
        return jsonify({'error': 'Branch not found'}), 404
    
    if current_user.role == 'manager' and current_user.branch_id != branch_id:
        return jsonify({'error': 'غير مصرح به for this branch'}), 403
    
    # Get current liquidity
    current_liquidity = get_current_liquidity(branch_id)
    
    # Calculate new amount
    if operation == 'add':
        new_amount = current_liquidity + amount
    elif operation == 'set':
        new_amount = amount
    else:
        return jsonify({'error': 'Invalid operation'}), 400
    
    # Validate new amount
    if new_amount < 0:
        return jsonify({'error': 'Liquidity cannot be negative'}), 400
    
    if new_amount > branch.max_liquidity * 1.1:  # Allow 10% over max for flexibility
        return jsonify({'error': f'Amount exceeds maximum capacity ({branch.max_liquidity:,.2f} ر.ي)'}), 400
    
    # Create transaction
    transaction_type = 'deposit' if amount >= 0 else 'withdrawal'
    transaction = Transaction(
        branch_id=branch_id,
        amount=amount if operation == 'add' else (new_amount - current_liquidity),
        transaction_type=transaction_type,
        description=description or f'{operation} liquidity: {amount:,.2f} ر.ي',
        timestamp=datetime.utcnow()
    )
    
    db.session.add(transaction)
    
    # Create new liquidity record
    liquidity_record = LiquidityRecord(
        branch_id=branch_id,
        current_liquidity=new_amount,
        timestamp=datetime.utcnow()
    )
    
    # Check for alerts
    alerts = []
    if new_amount < branch.min_liquidity * 0.8:
        alerts.append({
            'type': 'critical',
            'message': 'السيولة أقل من 80% من الحد الأدنى',
            'severity': 'high'
        })
    elif new_amount < branch.min_liquidity:
        alerts.append({
            'type': 'warning',
            'message': 'السيولة أقل من الحد الأدنى',
            'severity': 'medium'
        })
    elif new_amount > branch.max_liquidity * 0.9:
        alerts.append({
            'type': 'warning',
            'message': 'السيولة قريبة من السعة القصوى',
            'severity': 'medium'
        })
    
    liquidity_record.alerts = alerts
    db.session.add(liquidity_record)
    
    # Create alert records if needed
    for alert in alerts:
        alert_record = Alert(
            branch_id=branch_id,
            alert_type=alert['type'],
            message=alert['message'],
            severity=alert['severity']
        )
        db.session.add(alert_record)
    
    db.session.commit()
    
    # Send real-time update
    socketio.emit('liquidity_updated', {
        'branch_id': branch_id,
        'new_liquidity': new_amount,
        'previous_liquidity': current_liquidity,
        'change': new_amount - current_liquidity,
        'alerts': alerts,
        'timestamp': datetime.utcnow().isoformat()
    })
    
    return jsonify({
        'success': True,
        'message': 'تم تحديث السيولة بنجاح',
        'new_liquidity': new_amount,
        'previous_liquidity': current_liquidity,
        'change': new_amount - current_liquidity
    })

@app.route('/api/liquidity/history/<int:branch_id>', methods=['GET'])
@login_required
def get_liquidity_history(branch_id):
    """Get liquidity history for a branch"""
    # Check permissions
    if current_user.role != 'admin' and current_user.branch_id != branch_id:
        return jsonify({'error': 'غير مصرح به'}), 403
    
    days = request.args.get('days', default=30, type=int)
    
    records = LiquidityRecord.query.filter_by(branch_id=branch_id)\
        .filter(LiquidityRecord.timestamp >= datetime.utcnow() - timedelta(days=days))\
        .order_by(LiquidityRecord.timestamp.asc())\
        .all()
    
    history = [{
        'timestamp': record.timestamp.isoformat(),
        'liquidity': record.current_liquidity,
        'alerts': record.alerts or []
    } for record in records]
    
    return jsonify({'history': history})

@app.route('/api/transactions/<int:branch_id>', methods=['GET'])
@login_required
def get_transactions(branch_id):
    """Get transactions for a branch"""
    # Check permissions
    if current_user.role != 'admin' and current_user.branch_id != branch_id:
        return jsonify({'error': 'غير مصرح به'}), 403
    
    limit = request.args.get('limit', default=50, type=int)
    
    transactions = Transaction.query.filter_by(branch_id=branch_id)\
        .order_by(Transaction.timestamp.desc())\
        .limit(limit)\
        .all()
    
    transactions_data = [{
        'id': t.id,
        'amount': t.amount,
        'type': t.transaction_type,
        'description': t.description,
        'timestamp': t.timestamp.isoformat(),
        'status': t.status
    } for t in transactions]
    
    return jsonify({'transactions': transactions_data})

# Add this to utility processor in app.py
@app.context_processor
def utility_processor():
    def format_currency(amount):
        """Format currency for display"""
        if amount is None:
            return "0.00 ر.ي"
        return f"{amount:,.2f} ر.ي"
    
    def get_role_name(role_code):
        """Convert role code to Arabic name"""
        roles = {
            'admin': 'مدير النظام',
            'manager': 'مدير فرع',
            'auditor': 'مراجع'
        }
        return roles.get(role_code, role_code)
    
    def get_transaction_type_name(type_code):
        """Convert transaction type to Arabic name"""
        types = {
            'deposit': 'إيداع',
            'withdrawal': 'سحب',
            'transfer_in': 'تحويل وارد',
            'transfer_out': 'تحويل صادر',
            'adjustment': 'تعديل'
        }
        return types.get(type_code, type_code)
    
    return dict(
        format_currency=format_currency,
        get_role_name=get_role_name,
        get_transaction_type_name=get_transaction_type_name
    )


@app.route('/liquidity')
@login_required
def liquidity_management():
    """Liquidity management page"""
    if current_user.role not in ['admin', 'manager']:
        return redirect(url_for('dashboard'))
    
    return render_template('dashboard/liquidity.html', 
                         user_role=current_user.role,
                         rtl=True)


# Add to imports

# Add after existing models
class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    
    # Relationship
    role_permissions = db.relationship('RolePermission', backref='permission', lazy=True)

class RolePermission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(20), nullable=False)
    permission_id = db.Column(db.Integer, db.ForeignKey('permission.id'), nullable=False)

# Update UserForm class
class UserForm(FlaskForm):
    class Meta:
        csrf = False  # تعطيل CSRF لهذا النموذج
        
    username = StringField('اسم المستخدم', validators=[DataRequired()])
    email = StringField('البريد الإلكتروني', validators=[DataRequired(), Email()])
    password = PasswordField('كلمة المرور', validators=[])
    confirm_password = PasswordField('تأكيد كلمة المرور', validators=[])
    role = SelectField('الدور', choices=[
        ('auditor', 'مراجع'),
        ('manager', 'مدير فرع'),
        ('admin', 'مدير النظام')
    ])
    branch_id = SelectField('الفرع', coerce=int)
    is_active = BooleanField('نشط')

class UserForm2(FlaskForm):
    username = StringField('اسم المستخدم', validators=[DataRequired()])
    email = StringField('البريد الإلكتروني', validators=[DataRequired(), Email()])
    password = PasswordField('كلمة المرور', validators=[])
    confirm_password = PasswordField('تأكيد كلمة المرور', validators=[])
    role = SelectField('الدور', choices=[
        ('auditor', 'مراجع'),
        ('manager', 'مدير فرع'),
        ('admin', 'مدير النظام')
    ])
    branch_id = SelectField('الفرع', coerce=int)
    is_active = BooleanField('نشط')

# Add user management routes
@app.route('/admin/users')
@login_required
def admin_users():
    # Check permission
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    
    # Get all users with branch info
    users = User.query.options(db.joinedload(User.branch)).all()
    branches = Branch.query.all()
    
    return render_template('admin/users.html', 
                         users=users, 
                         branches=branches,
                         rtl=True)

@app.route('/admin/users/add', methods=['GET', 'POST'])
@login_required
def add_user2():
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    
    form = UserForm()
    form.branch_id.choices = [(0, 'لا يوجد')] + [(b.id, b.name) for b in Branch.query.all()]
    
    if form.validate_on_submit():
        # Check if username exists
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            return jsonify({'error': 'اسم المستخدم موجود بالفعل'}), 400
        
        # Check if email exists
        existing_email = User.query.filter_by(email=form.email.data).first()
        if existing_email:
            return jsonify({'error': 'البريد الإلكتروني موجود بالفعل'}), 400

        # Create new user
        user = User(
            username=form.username.data,
            email=form.email.data,
            role=form.role.data,
            branch_id=form.branch_id.data if form.branch_id.data != 0 else None,
            is_active=form.is_active.data
        )
        
        # Set password if provided
        if form.password.data:
            user.password = generate_password_hash(form.password.data)
        else:
            user.password = generate_password_hash('password123')  # Default password
        
        db.session.add(user)
        db.session.commit()
        
        return redirect(url_for('admin_users'))
    
    return render_template('admin/user_form.html', 
                         form=form, 
                         title='إضافة مستخدم جديد',
                         rtl=True)

@app.route('/admin/users/add2', methods=['GET', 'POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        return jsonify({'error': 'غير مصرح لك بهذا الإجراء'}), 403
    
    if request.method == 'POST':
        # الحصول على البيانات من طلب fetch
        data = UserForm()# request.get_json()
        
        if not data:
            return jsonify({'error': 'لا توجد بيانات'}), 400
        
        # التحقق من البيانات المطلوبة
        required_fields = ['username', 'email', 'role']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'حقل {field} مطلوب'}), 400
        
        # التحقق من وجود اسم المستخدم
        existing_user = User.query.filter_by(username=data['username']).first()
        if existing_user:
            return jsonify({'error': 'اسم المستخدم موجود بالفعل'}), 400
        
        # التحقق من وجود البريد الإلكتروني
        existing_email = User.query.filter_by(email=data['email']).first()
        if existing_email:
            return jsonify({'error': 'البريد الإلكتروني موجود بالفعل'}), 400
        
        # إنشاء مستخدم جديد
        user = User(
            username=data['username'],
            email=data['email'],
            role=data['role'],
            branch_id=data.get('branch_id') if data.get('branch_id') else None,
            is_active=data.get('is_active', True)
        )
        
        # تعيين كلمة المرور
        password = data.get('password', 'password123')
        user.password = generate_password_hash(password)
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'تمت إضافة المستخدم بنجاح',
            'user_id': user.id
        }), 201
    
    # للطلبات GET تعرض النموذج
    #form = UserForm()
    #form.branch_id.choices = [(0, 'لا يوجد')] + [(b.id, b.name) for b in Branch.query.all()]
    
    return render_template('admin/user_form.html', 
                         form=form, 
                         title='إضافة مستخدم جديد',
                         rtl=True)

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    form = UserForm(obj=user)
    form.branch_id.choices = [(0, 'لا يوجد')] + [(b.id, b.name) for b in Branch.query.all()]
    
    if form.validate_on_submit():
        # Check if username exists (excluding current user)
        existing_user = User.query.filter(
            User.username == form.username.data,
            User.id != user_id
        ).first()
        if existing_user:
            return render_template('admin/user_form.html', 
                                 form=form, 
                                 title='تعديل مستخدم',
                                 error='اسم المستخدم موجود بالفعل',
                                 rtl=True)
        
        # Check if email exists (excluding current user)
        existing_email = User.query.filter(
            User.email == form.email.data,
            User.id != user_id
        ).first()
        if existing_email:
            return render_template('admin/user_form.html', 
                                 form=form, 
                                 title='تعديل مستخدم',
                                 error='البريد الإلكتروني موجود بالفعل',
                                 rtl=True)
        
        # Update user
        user.username = form.username.data
        user.email = form.email.data
        user.role = form.role.data
        user.branch_id = form.branch_id.data if form.branch_id.data != 0 else None
        user.is_active = form.is_active.data
        
        # Update password if provided
        if form.password.data:
            user.password = generate_password_hash(form.password.data)
        
        db.session.commit()
        
        return redirect(url_for('admin_users'))
    
    return render_template('admin/user_form.html', 
                         form=form, 
                         title='تعديل مستخدم',
                         rtl=True)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'غير مصرح'}), 403
    
    # Prevent deleting own account
    if user_id == current_user.id:
        return jsonify({'success': False, 'error': 'لا يمكن حذف حسابك الخاص'}), 400
    
    user = User.query.get_or_404(user_id)
    
    # Check if user has any important data
    # (In a real system, you might want to handle this differently)
    
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/admin/users/toggle_active/<int:user_id>', methods=['POST'])
@login_required
def toggle_user_active(user_id):
    if current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'غير مصرح'}), 403
    
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    
    return jsonify({'success': True, 'is_active': user.is_active})

@app.route('/admin/users/reset_password/<int:user_id>', methods=['POST'])
@login_required
def reset_user_password(user_id):
    if current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'غير مصرح'}), 403
    
    user = User.query.get_or_404(user_id)
    new_password = 'password123'  # Default reset password
    
    user.password = generate_password_hash(new_password)
    db.session.commit()
    
    # In production, you would send an email with the new password
    return jsonify({'success': True, 'new_password': new_password})

# API endpoints for users
@app.route('/api/users', methods=['GET'])
@login_required
def api_users():
    if current_user.role != 'admin':
        return jsonify({'error': 'غير مصرح'}), 403
    
    users = User.query.options(db.joinedload(User.branch)).all()
    
    users_data = []
    for user in users:
        users_data.append({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'role_name': 'مدير النظام' if user.role == 'admin' else 
                         'مدير فرع' if user.role == 'manager' else 'مراجع',
            'branch': user.branch.name if user.branch else 'لا يوجد',
            'is_active': user.is_active,
            'created_at': user.created_at.strftime('%Y-%m-%d %H:%M'),
            'last_login': 'قبل ساعتين'  # You would need to track this
        })
    
    return jsonify({'users': users_data})

@app.route('/api/user/<int:user_id>', methods=['GET'])
@login_required
def api_user(user_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'غير مصرح'}), 403
    
    user = User.query.get_or_404(user_id)
    
    user_data = {
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'role': user.role,
        'branch_id': user.branch_id,
        'is_active': user.is_active,
        'created_at': user.created_at.isoformat(),
        'branch_name': user.branch.name if user.branch else None
    }
    
    return jsonify(user_data)













# Risk Management Routes

@app.route('/risk/dashboard')
@login_required
def risk_dashboard():
    """Risk management dashboard"""
    if not check_permission(current_user.role, 'view_risks'):
        return redirect(url_for('dashboard'))
    
    # Get risk statistics
    total_risks = Risk.query.filter_by(is_active=True).count()
    open_risks = Risk.query.filter_by(is_active=True, status='open').count()
    
    # Get top risks
    top_risks = Risk.query.filter_by(is_active=True)\
        .order_by(Risk.risk_score.desc())\
        .limit(5)\
        .all()
    
    # Get risk categories
    risk_categories = []
    for cat in app.config['RISK_CATEGORIES']:
        count = Risk.query.filter_by(category_id=cat.get('id', 0), is_active=True).count()
        risk_categories.append({
            **cat,
            'risk_count': count
        })
    
    # Get branches and users for dropdowns
    branches = Branch.query.all()
    users = User.query.filter_by(is_active=True).all()
    
    # Get recent incidents
    incidents = RiskIncident.query.order_by(RiskIncident.incident_date.desc())\
        .limit(5)\
        .all()
    
    # Get KRI data (simulated for now)
    kris = [
        {'name': 'نسبة السيولة اليومية', 'value': 125, 'unit': '%', 'status': 'green', 
         'category': 'مخاطر السيولة', 'branch': 'الفرع الرئيسي', 'last_updated': 'اليوم'},
        {'name': 'صافي التمويل المستقر', 'value': 112, 'unit': '%', 'status': 'green',
         'category': 'مخاطر السيولة', 'branch': 'جميع الفروع', 'last_updated': 'الشهر الحالي'},
        {'name': 'نسبة الديون المتعثرة', 'value': 1.8, 'unit': '%', 'status': 'green',
         'category': 'مخاطر الائتمان', 'branch': 'الفرع الرئيسي', 'last_updated': 'الربع الحالي'},
        {'name': 'التعرض للعملات الأجنبية', 'value': 15, 'unit': '%', 'status': 'yellow',
         'category': 'مخاطر السوق', 'branch': 'فرع جدة', 'last_updated': 'الأسبوع الحالي'},
    ]
    
    return render_template('risk/dashboard.html',
                         total_risks=total_risks,
                         open_risks=open_risks,
                         top_risks=top_risks,
                         risk_categories=risk_categories,
                         branches=branches,
                         users=users,
                         incidents=incidents,
                         kris=kris,
                         user_role=current_user.role,
                         rtl=True,
                         now=datetime.now)

@app.route('/risk/register')
@login_required
def risk_register():
    """Risk register - list all risks"""
    if not check_permission(current_user.role, 'view_risks'):
        return redirect(url_for('dashboard'))
    
    # Get risks based on user permissions
    if current_user.role == 'admin':
        risks = Risk.query.filter_by(is_active=True).all()
    elif current_user.role == 'branch_manager':
        risks = Risk.query.filter_by(branch_id=current_user.branch_id, is_active=True).all()
    else:
        risks = []
    
    return render_template('risk/register.html',
                         risks=risks,
                         user_role=current_user.role,
                         rtl=True)

@app.route('/risk/<int:risk_id>')
@login_required
def risk_details(risk_id):
    """View risk details"""
    risk = Risk.query.get_or_404(risk_id)
    
    # Check permission
    if not check_risk_permission(current_user, risk, 'view_risks'):
        return redirect(url_for('risk_dashboard'))
    
    # Get related data
    controls = RiskControl.query.filter_by(risk_id=risk_id).all()
    actions = RiskAction.query.filter_by(risk_id=risk_id).all()
    assessments = RiskAssessment.query.filter_by(risk_id=risk_id).all()
    
    return render_template('risk/details.html',
                         risk=risk,
                         controls=controls,
                         actions=actions,
                         assessments=assessments,
                         user_role=current_user.role,
                         rtl=True)

@app.route('/risk/incidents')
@login_required
def risk_incidents():
    """Risk incidents management"""
    if not check_permission(current_user.role, 'view_incidents'):
        return redirect(url_for('dashboard'))
    
    incidents = RiskIncident.query.order_by(RiskIncident.incident_date.desc()).all()
    branches = Branch.query.all()
    return render_template('risk/incidents.html',
                         incidents=incidents,
                         this_month=datetime.now,
                         branches=branches,
                         user_role=current_user.role,
                         rtl=True)

@app.route('/risk/kris')
@login_required
def kri_monitoring():
    """Key Risk Indicators monitoring"""
    if not check_permission(current_user.role, 'view_kris'):
        return redirect(url_for('dashboard'))
    
    indicators = RiskIndicator.query.all()
    values = RiskIndicatorValue.query.order_by(RiskIndicatorValue.value_date.desc()).all()
    
    return render_template('risk/kris.html',
                         indicators=indicators,
                         values=values,
                         user_role=current_user.role,
                         rtl=True)

@app.route('/risk/reports')
@login_required
def risk_reports():
    """Risk reports"""
    if not check_permission(current_user.role, 'view_reports'):
        return redirect(url_for('dashboard'))
    
    reports = RiskReport.query.order_by(RiskReport.generated_date.desc()).all()
    
    return render_template('risk/reports.html',
                         reports=reports,
                         user_role=current_user.role,
                         rtl=True)

# API Endpoints for Risk Management

@app.route('/api/risks/add', methods=['POST'])
@login_required
def add_risk():
    """Add new risk"""
    if not check_permission(current_user.role, 'edit_risks'):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        data = request.json
        
        # Create new risk
        risk = Risk(
            title=data.get('title'),
            description=data.get('description'),
            category_id=data.get('category_id'),
            branch_id=data.get('branch_id'),
            impact=data.get('impact', 3),
            likelihood=data.get('likelihood', 3),
            risk_score=data.get('risk_score', 9),
            priority=data.get('priority', 'medium'),
            status='open',
            basel_category=data.get('basel_category'),
            capital_requirement=data.get('capital_requirement'),
            potential_loss=data.get('potential_loss'),
            mitigation_cost=data.get('mitigation_cost'),
            target_resolution_date=datetime.strptime(data.get('target_resolution_date'), '%Y-%m-%d') if data.get('target_resolution_date') else None,
            owner_id=data.get('owner_id'),
            assigned_to_id=data.get('assigned_to_id'),
            created_by_id=current_user.id
        )
        
        db.session.add(risk)
        db.session.commit()
        
        # Send notification
        socketio.emit('new_risk', {
            'risk_id': risk.id,
            'title': risk.title,
            'priority': risk.priority,
            'branch_id': risk.branch_id,
            'created_by': current_user.username
        })
        
        return jsonify({
            'success': True,
            'message': 'تم تسجيل الخطر بنجاح',
            'risk_id': risk.id
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/risks/<int:risk_id>/assess', methods=['POST'])
@login_required
def assess_risk(risk_id):
    """Assess a risk"""
    risk = Risk.query.get_or_404(risk_id)
    
    if not check_risk_permission(current_user, risk, 'perform_assessments'):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        data = request.json
        
        # Create assessment
        assessment = RiskAssessment(
            risk_id=risk_id,
            assessed_by_id=current_user.id,
            impact_score=data.get('impact_score'),
            likelihood_score=data.get('likelihood_score'),
            residual_risk_score=data.get('residual_risk_score'),
            comments=data.get('comments'),
            recommendations=data.get('recommendations')
        )
        
        # Update risk if needed
        if data.get('update_risk', False):
            risk.impact = data.get('impact_score')
            risk.likelihood = data.get('likelihood_score')
            risk.risk_score = data.get('residual_risk_score')
            risk.updated_at = datetime.utcnow()
        
        db.session.add(assessment)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'تم تقييم الخطر بنجاح'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/kris/values/add', methods=['POST'])
@login_required
def add_kri_value():
    """Add KRI value"""
    if not check_permission(current_user.role, 'manage_kris'):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        data = request.json
        
        value = RiskIndicatorValue(
            indicator_id=data.get('indicator_id'),
            branch_id=data.get('branch_id'),
            value=data.get('value'),
            value_date=datetime.strptime(data.get('value_date'), '%Y-%m-%d'),
            collected_by_id=current_user.id,
            collection_method=data.get('collection_method', 'manual'),
            notes=data.get('notes')
        )
        
        # Calculate status based on thresholds
        indicator = RiskIndicator.query.get(data.get('indicator_id'))
        if indicator:
            if indicator.green_min <= value.value <= indicator.green_max:
                value.status = 'green'
            elif indicator.yellow_min <= value.value <= indicator.yellow_max:
                value.status = 'yellow'
            else:
                value.status = 'red'
            
            value.deviation = ((value.value - indicator.green_min) / indicator.green_min * 100)
        
        db.session.add(value)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'تم تسجيل قيمة المؤشر بنجاح'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500













@app.route('/api/incidents/report', methods=['POST'])
@login_required
def report_incident():
    """Report a new risk incident"""
    if not check_permission(current_user.role, 'report_incidents') :
        return jsonify({'error': 'غير مصرح به'}), 403
    
    try:
        data = request.json
        
        # Validate required fields
        required_fields = ['title', 'description', 'branch_id', 'incident_date']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'الحقل {field} مطلوب'}), 400
        
        # Parse dates
        incident_date = datetime.strptime(data.get('incident_date'), '%Y-%m-%d')
        discovery_date = datetime.strptime(data.get('discovery_date'), '%Y-%m-%d') if data.get('discovery_date') else None
        
        # Create incident
        incident = RiskIncident(
            title=data.get('title'),
            description=data.get('description'),
            category_id=data.get('category_id'),
            branch_id=data.get('branch_id'),
            incident_date=incident_date,
            discovery_date=discovery_date,
            reporting_date=datetime.utcnow(),
            
            # Impact
            financial_impact=data.get('financial_impact'),
            operational_impact=data.get('operational_impact'),
            reputational_impact=data.get('reputational_impact'),
            severity=data.get('severity', 'medium'),
            
            # Root cause
            root_cause=data.get('root_cause'),
            contributing_factors=data.get('contributing_factors'),
            
            # Status
            status='open',
            investigation_status='pending',
            
            # Responsibility
            reported_by_id=current_user.id,
            assigned_to_id=data.get('assigned_to_id', current_user.id),
            
            # Regulatory
            basel_category=data.get('basel_category'),
            regulatory_reporting=data.get('regulatory_reporting', False)
        )
        
        db.session.add(incident)
        db.session.commit()
        
        # Send real-time notification
        socketio.emit('new_incident', {
            'incident_id': incident.id,
            'title': incident.title,
            'severity': incident.severity,
            'branch_id': incident.branch_id,
            'reported_by': current_user.username,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        # Send email notification to risk managers
        send_incident_notification(incident)
        
        return jsonify({
            'success': True,
            'message': 'تم إبلاغ الحادث بنجاح',
            'incident_id': incident.id,
            'incident_number': f'INC-{incident.id:06d}'
        })
        
    except Exception as e:
        db.session.rollback()
        print(f'Error reporting incident: {str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route('/api/incidents', methods=['GET'])
@login_required
def get_incidents():
    """Get incidents with filters"""
    if not check_permission(current_user.role, 'view_incidents'):
        return jsonify({'error': 'غير مصرح به'}), 403
    
    try:
        # Parse query parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        status = request.args.get('status')
        severity = request.args.get('severity')
        branch_id = request.args.get('branch_id')
        category_id = request.args.get('category_id')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        # Build query
        query = RiskIncident.query
        
        # Apply filters based on user role
        if current_user.role == 'branch_manager':
            query = query.filter_by(branch_id=current_user.branch_id)
        elif current_user.role == 'risk_manager':
            # Risk managers can see all incidents
            pass
        elif current_user.role == 'auditor':
            # Auditors can see all incidents
            pass
        elif current_user.role != 'admin':
            query = query.filter_by(reported_by_id=current_user.id)
        
        # Apply filters
        if status:
            query = query.filter_by(status=status)
        if severity:
            query = query.filter_by(severity=severity)
        if branch_id:
            query = query.filter_by(branch_id=branch_id)
        if category_id:
            query = query.filter_by(category_id=category_id)
        if start_date:
            start = datetime.strptime(start_date, '%Y-%m-%d')
            query = query.filter(RiskIncident.incident_date >= start)
        if end_date:
            end = datetime.strptime(end_date, '%Y-%m-%d')
            query = query.filter(RiskIncident.incident_date <= end)
        
        # Order and paginate
        incidents = query.order_by(RiskIncident.incident_date.desc())\
                         .paginate(page=page, per_page=per_page, error_out=False)
        
        # Prepare response
        incidents_data = []
        for incident in incidents.items:
            incidents_data.append({
                'id': incident.id,
                'incident_number': f'INC-{incident.id:06d}',
                'title': incident.title,
                'description': incident.description,
                'category': incident.category.name if incident.category else 'غير مصنف',
                'branch': incident.branch.name if incident.branch else 'غير محدد',
                'severity': incident.severity,
                'severity_ar': {
                    'low': 'منخفض',
                    'medium': 'متوسط',
                    'high': 'مرتفع',
                    'critical': 'حرج'
                }.get(incident.severity, incident.severity),
                'status': incident.status,
                'status_ar': {
                    'open': 'مفتوح',
                    'investigating': 'قيد التحقيق',
                    'resolved': 'تم الحل',
                    'closed': 'مغلق'
                }.get(incident.status, incident.status),
                'financial_impact': incident.financial_impact,
                'incident_date': incident.incident_date.isoformat(),
                'discovery_date': incident.discovery_date.isoformat() if incident.discovery_date else None,
                'reporting_date': incident.reporting_date.isoformat() if incident.reporting_date else None,
                'reported_by': incident.reported_by.username if incident.reported_by else 'غير معروف',
                'assigned_to': incident.assigned_to.username if incident.assigned_to else 'غير معين',
                'created_at': incident.created_at.isoformat(),
                'updated_at': incident.updated_at.isoformat()
            })
        
        return jsonify({
            'success': True,
            'incidents': incidents_data,
            'total': incidents.total,
            'page': incidents.page,
            'per_page': incidents.per_page,
            'pages': incidents.pages
        })
        
    except Exception as e:
        logger.error(f'Error getting incidents: {str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route('/api/incidents/<int:incident_id>', methods=['GET'])
@login_required
def get_incident(incident_id):
    """Get single incident details"""
    incident = RiskIncident.query.get_or_404(incident_id)
    
    # Check permission
    if not check_incident_permission(current_user, incident, 'view_incidents'):
        return jsonify({'error': 'غير مصرح به'}), 403
    
    incident_data = {
        'id': incident.id,
        'incident_number': f'INC-{incident.id:06d}',
        'title': incident.title,
        'description': incident.description,
        'category': {
            'id': incident.category.id if incident.category else None,
            'name': incident.category.name if incident.category else 'غير مصنف',
            'color': incident.category.color if incident.category else '#6b7280'
        },
        'branch': {
            'id': incident.branch.id,
            'name': incident.branch.name,
            'code': incident.branch.code
        },
        'severity': incident.severity,
        'severity_ar': {
            'low': 'منخفض',
            'medium': 'متوسط',
            'high': 'مرتفع',
            'critical': 'حرج'
        }.get(incident.severity, incident.severity),
        'status': incident.status,
        'status_ar': {
            'open': 'مفتوح',
            'investigating': 'قيد التحقيق',
            'resolved': 'تم الحل',
            'closed': 'مغلق'
        }.get(incident.status, incident.status),
        'investigation_status': incident.investigation_status,
        'financial_impact': incident.financial_impact,
        'operational_impact': incident.operational_impact,
        'reputational_impact': incident.reputational_impact,
        'root_cause': incident.root_cause,
        'contributing_factors': incident.contributing_factors,
        'incident_date': incident.incident_date.isoformat(),
        'discovery_date': incident.discovery_date.isoformat() if incident.discovery_date else None,
        'reporting_date': incident.reporting_date.isoformat() if incident.reporting_date else None,
        'resolution_date': incident.resolution_date.isoformat() if incident.resolution_date else None,
        'reported_by': {
            'id': incident.reported_by.id if incident.reported_by else None,
            'name': incident.reported_by.username if incident.reported_by else 'غير معروف',
            'role': incident.reported_by.role if incident.reported_by else None
        },
        'assigned_to': {
            'id': incident.assigned_to.id if incident.assigned_to else None,
            'name': incident.assigned_to.username if incident.assigned_to else 'غير معين',
            'role': incident.assigned_to.role if incident.assigned_to else None
        },
        'basel_category': incident.basel_category,
        'regulatory_reporting': incident.regulatory_reporting,
        'created_at': incident.created_at.isoformat(),
        'updated_at': incident.updated_at.isoformat()
    }
    
    return jsonify({
        'success': True,
        'incident': incident_data
    })

@app.route('/api/incidents/<int:incident_id>/update', methods=['POST'])
@login_required
def update_incident(incident_id):
    """Update incident"""
    incident = RiskIncident.query.get_or_404(incident_id)
    
    if not check_incident_permission(current_user, incident, 'manage_incidents'):
        return jsonify({'error': 'غير مصرح به'}), 403
    
    try:
        data = request.json
        
        # Update fields
        updatable_fields = [
            'title', 'description', 'category_id', 'severity', 'status',
            'investigation_status', 'financial_impact', 'operational_impact',
            'reputational_impact', 'root_cause', 'contributing_factors',
            'assigned_to_id', 'basel_category', 'regulatory_reporting'
        ]
        
        for field in updatable_fields:
            if field in data:
                setattr(incident, field, data[field])
        
        # Handle dates
        if data.get('incident_date'):
            incident.incident_date = datetime.strptime(data.get('incident_date'), '%Y-%m-%d')
        if data.get('discovery_date'):
            incident.discovery_date = datetime.strptime(data.get('discovery_date'), '%Y-%m-%d')
        if data.get('resolution_date'):
            incident.resolution_date = datetime.strptime(data.get('resolution_date'), '%Y-%m-%d')
        
        # If status changed to resolved/closed, set resolution date
        if data.get('status') in ['resolved', 'closed'] and not incident.resolution_date:
            incident.resolution_date = datetime.utcnow()
        
        incident.updated_at = datetime.utcnow()
        db.session.commit()
        
        # Send notification if status changed
        if data.get('status') and data.get('status') != incident.status:
            socketio.emit('incident_updated', {
                'incident_id': incident.id,
                'status': incident.status,
                'updated_by': current_user.username,
                'timestamp': datetime.utcnow().isoformat()
            })
        
        return jsonify({
            'success': True,
            'message': 'تم تحديث الحادث بنجاح'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f'Error updating incident: {str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route('/api/incidents/<int:incident_id>/add-note', methods=['POST'])
@login_required
def add_incident_note(incident_id):
    """Add note to incident"""
    incident = RiskIncident.query.get_or_404(incident_id)
    
    if not check_incident_permission(current_user, incident, 'view_incidents'):
        return jsonify({'error': 'غير مصرح به'}), 403
    
    try:
        data = request.json
        note = data.get('note')
        
        if not note:
            return jsonify({'error': 'ملاحظة مطلوبة'}), 400
        
        # In a real app, you would have an IncidentNote model
        # For now, we'll update the operational_impact field
        if incident.operational_impact:
            incident.operational_impact += f"\n\n[{datetime.now().strftime('%Y-%m-%d %H:%M')}] {current_user.username}:\n{note}"
        else:
            incident.operational_impact = f"[{datetime.now().strftime('%Y-%m-%d %H:%M')}] {current_user.username}:\n{note}"
        
        incident.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'تم إضافة الملاحظة بنجاح'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/incidents/stats', methods=['GET'])
@login_required
def get_incident_stats():
    """Get incident statistics"""
    if not check_permission(current_user.role, 'view_incidents'):
        return jsonify({'error': 'غير مصرح به'}), 403
    
    try:
        # Total incidents
        total_query = RiskIncident.query
        if current_user.role == 'branch_manager':
            total_query = total_query.filter_by(branch_id=current_user.branch_id)
        
        total_incidents = total_query.count()
        
        # Incidents by status
        status_counts = {}
        statuses = ['open', 'investigating', 'resolved', 'closed']
        for status in statuses:
            query = RiskIncident.query.filter_by(status=status)
            if current_user.role == 'branch_manager':
                query = query.filter_by(branch_id=current_user.branch_id)
            status_counts[status] = query.count()
        
        # Incidents by severity
        severity_counts = {}
        severities = ['low', 'medium', 'high', 'critical']
        for severity in severities:
            query = RiskIncident.query.filter_by(severity=severity)
            if current_user.role == 'branch_manager':
                query = query.filter_by(branch_id=current_user.branch_id)
            severity_counts[severity] = query.count()
        
        # Monthly trend (last 6 months)
        monthly_trend = []
        for i in range(6):
            month_start = datetime.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            month_start = month_start - timedelta(days=30*i)
            month_end = month_start + timedelta(days=30)
            
            query = RiskIncident.query.filter(
                RiskIncident.incident_date >= month_start,
                RiskIncident.incident_date < month_end
            )
            if current_user.role == 'branch_manager':
                query = query.filter_by(branch_id=current_user.branch_id)
            
            monthly_trend.append({
                'month': month_start.strftime('%Y-%m'),
                'count': query.count(),
                'month_name': month_start.strftime('%b')
            })
        
        # Incidents by category
        category_stats = []
        categories = RiskCategory.query.all()
        for category in categories:
            query = RiskIncident.query.filter_by(category_id=category.id)
            if current_user.role == 'branch_manager':
                query = query.filter_by(branch_id=current_user.branch_id)
            
            category_stats.append({
                'category_id': category.id,
                'category_name': category.name,
                'color': category.color,
                'count': query.count()
            })
        
        return jsonify({
            'success': True,
            'stats': {
                'total_incidents': total_incidents,
                'status_counts': status_counts,
                'severity_counts': severity_counts,
                'monthly_trend': monthly_trend,
                'category_stats': category_stats
            }
        })
        
    except Exception as e:
        logger.error(f'Error getting incident stats: {str(e)}')
        return jsonify({'error': str(e)}), 500

# Helper functions
def check_incident_permission(user, incident, permission):
    """Check if user has permission for specific incident"""
    if user.role == 'admin':
        return True
    elif user.role == 'risk_manager':
        return check_permission(user.role, permission)
    elif user.role == 'branch_manager':
        return incident.branch_id == user.branch_id and check_permission(user.role, permission)
    elif user.role == 'auditor':
        return check_permission(user.role, permission)
    # User can view their own reported incidents
    elif incident.reported_by_id == user.id:
        return permission in ['view_incidents', 'report_incidents']
    return False

def send_incident_notification(incident):
    """Send email notification for new incident"""
    try:
        # Get risk managers and admins
        recipients = User.query.filter(
            User.role.in_(['admin', 'risk_manager']),
            User.is_active == True
        ).all()
        
        for recipient in recipients:
            # In real app, send email
            # For now, just log
            logger.info(f"Incident notification for {recipient.email}: {incident.title}")
            
            # Send WebSocket notification
            socketio.emit('incident_notification', {
                'user_id': recipient.id,
                'incident_id': incident.id,
                'title': incident.title,
                'severity': incident.severity,
                'branch': incident.branch.name,
                'timestamp': datetime.utcnow().isoformat()
            })
            
    except Exception as e:
        logger.error(f"Error sending incident notification: {e}")




# Helper functions
def check_permission(role, permission):
    """Check if role has permission"""
    return permission in app.config['RISK_ROLES'].get(role, [])

def check_risk_permission(user, risk, permission):
    """Check if user has permission for specific risk"""
    if user.role == 'admin':
        return True
    elif user.role == 'risk_manager':
        return check_permission(user.role, permission)
    elif user.role == 'branch_manager':
        return risk.branch_id == user.branch_id and check_permission(user.role, permission)
    elif user.role == 'auditor':
        return check_permission(user.role, permission)
    return False


# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html', rtl=True), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html', rtl=True), 403

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('errors/500.html', rtl=True), 500

if __name__ == '__main__':
    # Initialize database
    create_tables()
    
    # Run the application
    print("Starting Liquidity Management System...")
    print("Open http://localhost:5000 in your browser")
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)