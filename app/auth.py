from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from app.models import db, User

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.home'))
        
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return render_template('register.html')
            
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template('register.html')
            
        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "danger")
            return render_template('register.html')
            
        # Check if username or email already exists
        existing_username = User.query.filter_by(username=username).first()
        if existing_username:
            flash("Username already taken. Please choose another one.", "danger")
            return render_template('register.html')
            
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash("Email address already registered.", "danger")
            return render_template('register.html')
            
        # Create user
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('auth.login'))
        
    return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.home'))
        
    if request.method == 'POST':
        username_or_email = request.form.get('username_or_email', '').strip()
        password = request.form.get('password', '')
        remember = True if request.form.get('remember') else False
        
        # Look up by username or email
        user = User.query.filter(
            (User.username == username_or_email) | (User.email == username_or_email)
        ).first()
        
        if not user or not user.check_password(password):
            flash("Invalid username/email or password.", "danger")
            return render_template('login.html')
            
        login_user(user, remember=remember)
        next_page = request.args.get('next')
        flash(f"Welcome back, {user.username}!", "success")
        return redirect(next_page or url_for('dashboard.home'))
        
    return render_template('login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('index'))

@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_profile':
            email = request.form.get('email', '').strip()
            username = request.form.get('username', '').strip()
            
            if not email or not username:
                flash("Username and Email cannot be empty.", "danger")
                return redirect(url_for('auth.profile'))
                
            # Check unique constraints if changed
            if email != current_user.email:
                if User.query.filter_by(email=email).first():
                    flash("Email address already in use.", "danger")
                    return redirect(url_for('auth.profile'))
                current_user.email = email
                
            if username != current_user.username:
                if User.query.filter_by(username=username).first():
                    flash("Username already taken.", "danger")
                    return redirect(url_for('auth.profile'))
                current_user.username = username
                
            db.session.commit()
            flash("Profile updated successfully!", "success")
            
        elif action == 'change_password':
            old_password = request.form.get('old_password', '')
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')
            
            if not current_user.check_password(old_password):
                flash("Incorrect current password.", "danger")
                return redirect(url_for('auth.profile'))
                
            if new_password != confirm_password:
                flash("New passwords do not match.", "danger")
                return redirect(url_for('auth.profile'))
                
            if len(new_password) < 6:
                flash("New password must be at least 6 characters long.", "danger")
                return redirect(url_for('auth.profile'))
                
            current_user.set_password(new_password)
            db.session.commit()
            flash("Password updated successfully!", "success")
            
        return redirect(url_for('auth.profile'))
        
    return render_template('profile.html')
