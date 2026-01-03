import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///liquidity.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    
    # Role-Based Access Control
    ROLES = {
        'admin': ['view', 'edit', 'delete', 'manage_users', 'view_reports'],
        'manager': ['view', 'edit', 'view_reports'],
        'auditor': ['view', 'view_reports']
    }


    RISK_ROLES = {
        'admin': ['view_risks', 'edit_risks', 'delete_risks', 'approve_risks', 
                  'manage_risk_categories', 'view_reports', 'generate_reports',
                  'manage_kris', 'view_incidents', 'manage_incidents',
                  'view_assessments', 'perform_assessments','report_incidents'],
        
        'risk_manager': ['view_risks', 'edit_risks', 'approve_risks', 
                        'view_reports', 'generate_reports', 'manage_kris',
                        'view_incidents', 'manage_incidents', 'perform_assessments',
                        'manage_risk_controls'],
        
        'branch_manager': ['view_risks', 'edit_risks', 'view_reports', 
                          'view_incidents', 'report_incidents', 'view_kris'],
        
        'auditor': ['view_risks', 'view_reports', 'view_incidents', 
                   'view_assessments', 'view_risk_controls']
    }
    
    # Risk Categories Configuration
    RISK_CATEGORIES = [
        {'code': 'CR', 'name': 'مخاطر الائتمان', 'color': '#ef4444'},
        {'code': 'MR', 'name': 'مخاطر السوق', 'color': '#f59e0b'},
        {'code': 'OR', 'name': 'مخاطر التشغيل', 'color': '#10b981'},
        {'code': 'LR', 'name': 'مخاطر السيولة', 'color': '#3b82f6'},
        {'code': 'SR', 'name': 'مخاطر الاستراتيجية', 'color': '#8b5cf6'},
        {'code': 'RR', 'name': 'مخاطر السمعة', 'color': '#ec4899'},
        {'code': 'CRR', 'name': 'مخاطر الامتثال التنظيمي', 'color': '#6366f1'},
        {'code': 'FR', 'name': 'مخاطر التمويل', 'color': '#14b8a6'},
    ]
    
    # Basel III Risk Categories
    BASEL_RISK_CATEGORIES = {
        'credit_risk': 'مخاطر الائتمان',
        'market_risk': 'مخاطر السوق',
        'operational_risk': 'مخاطر التشغيل',
        'liquidity_risk': 'مخاطر السيولة',
    }
    
    # Risk Assessment Matrix (Impact x Likelihood)
    RISK_MATRIX = {
        'critical': {'min_score': 20, 'max_score': 25, 'color': '#dc2626'},
        'high': {'min_score': 10, 'max_score': 19, 'color': '#ea580c'},
        'medium': {'min_score': 5, 'max_score': 9, 'color': '#ca8a04'},
        'low': {'min_score': 1, 'max_score': 4, 'color': '#16a34a'},
    }
    
    # Key Risk Indicators (KRIs) Configuration
    DEFAULT_KRIS = [
        {
            'code': 'LCR_DAILY',
            'name': 'نسبة السيولة اليومية',
            'category': 'LR',
            'unit': '%',
            'green_min': 100,
            'green_max': 200,
            'yellow_min': 80,
            'yellow_max': 99,
            'red_min': 0,
            'red_max': 79,
            'basel_component': 'LCR'
        },
        {
            'code': 'NSFR_MONTHLY',
            'name': 'صافي التمويل المستقر',
            'category': 'LR',
            'unit': '%',
            'green_min': 100,
            'green_max': 150,
            'yellow_min': 90,
            'yellow_max': 99,
            'red_min': 0,
            'red_max': 89,
            'basel_component': 'NSFR'
        },
        {
            'code': 'NPL_RATIO',
            'name': 'نسبة الديون المتعثرة',
            'category': 'CR',
            'unit': '%',
            'green_min': 0,
            'green_max': 2,
            'yellow_min': 2.1,
            'yellow_max': 5,
            'red_min': 5.1,
            'red_max': 100,
            'basel_component': 'Credit Risk'
        },
        {
            'code': 'FX_EXPOSURE',
            'name': 'التعرض للعملات الأجنبية',
            'category': 'MR',
            'unit': '%',
            'green_min': 0,
            'green_max': 10,
            'yellow_min': 10.1,
            'yellow_max': 20,
            'red_min': 20.1,
            'red_max': 100,
            'basel_component': 'Market Risk'
        },
    ]