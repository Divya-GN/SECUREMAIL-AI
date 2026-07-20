from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from app.models import db, User, Scan
from sqlalchemy import func

admin_bp = Blueprint('admin', __name__)

@admin_bp.before_request
@login_required
def require_admin():
    if not current_user.is_admin:
        abort(403)

@admin_bp.route('/dashboard')
def dashboard():
    # Admin System-wide Stats
    total_users = User.query.count()
    total_scans = Scan.query.count()
    
    safe_scans = Scan.query.filter_by(prediction='Safe').count()
    spam_scans = Scan.query.filter_by(prediction='Spam').count()
    phish_scans = Scan.query.filter_by(prediction='Phishing').count()
    
    # List of all users and their scan count
    # Join scan count
    users = db.session.query(
        User,
        func.count(Scan.id).label('scan_count')
    ).outerjoin(Scan).group_by(User.id).all()
    
    # List of recent scans across all users (limit to 10)
    scans = Scan.query.order_by(Scan.created_at.desc()).limit(10).all()
    
    # Global average risk score
    avg_risk = db.session.query(func.avg(Scan.risk_score)).scalar()
    avg_risk = round(avg_risk, 1) if avg_risk is not None else 0.0
    
    return render_template(
        'admin.html',
        total_users=total_users,
        total_scans=total_scans,
        safe_scans=safe_scans,
        spam_scans=spam_scans,
        phish_scans=phish_scans,
        users=users,
        scans=scans,
        avg_risk=avg_risk
    )

@admin_bp.route('/user/delete/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if user_id == current_user.id:
        flash("You cannot delete your own admin account.", "danger")
        return redirect(url_for('admin.dashboard'))
        
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    
    flash(f"User '{user.username}' has been deleted.", "success")
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/user/promote/<int:user_id>', methods=['POST'])
def promote_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == 'admin':
        flash(f"User '{user.username}' is already an admin.", "info")
        return redirect(url_for('admin.dashboard'))
        
    user.role = 'admin'
    db.session.commit()
    
    flash(f"User '{user.username}' has been promoted to Administrator.", "success")
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/scan/delete/<int:scan_id>', methods=['POST'])
def delete_scan(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    db.session.delete(scan)
    db.session.commit()
    
    flash("Scan record deleted by administrator.", "success")
    return redirect(url_for('admin.dashboard'))
