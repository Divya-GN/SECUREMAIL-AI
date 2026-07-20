from flask import Blueprint, render_template, jsonify
from flask_login import login_required, current_user
from app.models import Scan, db
from sqlalchemy import func

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/home')
@login_required
def home():
    # User-specific stats
    total_scans = Scan.query.filter_by(user_id=current_user.id).count()
    safe_count = Scan.query.filter_by(user_id=current_user.id, prediction='Safe').count()
    spam_count = Scan.query.filter_by(user_id=current_user.id, prediction='Spam').count()
    phish_count = Scan.query.filter_by(user_id=current_user.id, prediction='Phishing').count()
    
    # Recent scans (limit to 5)
    recent_scans = Scan.query.filter_by(user_id=current_user.id)\
        .order_by(Scan.created_at.desc())\
        .limit(5).all()
        
    # Calculate average risk score
    avg_risk = db.session.query(func.avg(Scan.risk_score))\
        .filter(Scan.user_id == current_user.id).scalar()
    avg_risk = round(avg_risk, 1) if avg_risk is not None else 0.0
    
    return render_template(
        'dashboard.html',
        total_scans=total_scans,
        safe_count=safe_count,
        spam_count=spam_count,
        phish_count=phish_count,
        recent_scans=recent_scans,
        avg_risk=avg_risk
    )

@dashboard_bp.route('/api/stats')
@login_required
def api_stats():
    # Query database to group scans by date and classification for the last 7 days
    # For a simple robust demonstration, we can fetch count of Safe, Spam, Phishing
    # in the user's scan history and return it as JSON.
    safe_count = Scan.query.filter_by(user_id=current_user.id, prediction='Safe').count()
    spam_count = Scan.query.filter_by(user_id=current_user.id, prediction='Spam').count()
    phish_count = Scan.query.filter_by(user_id=current_user.id, prediction='Phishing').count()
    
    # Get scans over time (grouped by date)
    # Using SQLite date function
    daily_stats_query = db.session.query(
        func.date(Scan.created_at).label('date'),
        func.count(Scan.id).label('count')
    ).filter(Scan.user_id == current_user.id)\
     .group_by(func.date(Scan.created_at))\
     .order_by(func.date(Scan.created_at))\
     .limit(7).all()
     
    dates = [row.date for row in daily_stats_query]
    counts = [row.count for row in daily_stats_query]
    
    # If empty, supply dummy structure to look good
    if not dates:
        dates = ["Today"]
        counts = [0]
        
    return jsonify({
        'pie_data': {
            'labels': ['Safe', 'Spam', 'Phishing'],
            'values': [safe_count, spam_count, phish_count]
        },
        'line_data': {
            'labels': dates,
            'values': counts
        }
    })
