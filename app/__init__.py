import os
from flask import Flask, redirect, url_for
from flask_login import LoginManager
from app.models import db, User

login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message_category = 'warning'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_app():
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cyber-security-secret-key-9988')
    # Set DB path inside the instance folder
    instance_path = os.path.join(app.root_path, '..', 'instance')
    os.makedirs(instance_path, exist_ok=True)
    app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(instance_path, 'database.db')}"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Initialize Extensions
    db.init_app(app)
    login_manager.init_app(app)
    
    # Register Blueprints
    from app.auth import auth_bp
    from app.dashboard import dashboard_bp
    from app.scanner import scanner_bp
    from app.admin import admin_bp
    
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
    app.register_blueprint(scanner_bp, url_prefix='/scanner')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    
    # Root Route
    @app.route('/')
    def index():
        from flask_login import current_user
        if current_user.is_authenticated:
            return redirect(url_for('dashboard.home'))
        from flask import render_template
        return render_template('index.html')
        
    # Shell context for flask cli
    @app.shell_context_processor
    def make_shell_context():
        return {'db': db, 'User': User}
        
    # Database Initialization & Seeding
    with app.app_context():
        db.create_all()
        seed_admin_user()
        
    return app

def seed_admin_user():
    # Seeds default admin if database is empty
    admin = User.query.filter_by(role='admin').first()
    if not admin:
        default_admin = User(
            username='admin',
            email='admin@securemail.ai',
            role='admin'
        )
        default_admin.set_password('Admin123!')
        db.session.add(default_admin)
        
        # Also seed a regular user for demonstration
        default_user = User(
            username='user',
            email='user@securemail.ai',
            role='user'
        )
        default_user.set_password('User123!')
        db.session.add(default_user)
        
        db.session.commit()
        print("Database seeded with default accounts: admin (Admin123!) and user (User123!)")
