import io
import json
import email
from email import policy
from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request, send_file, abort
from flask_login import login_required, current_user
from app.models import db, Scan
from app.ml.classifier import EmailClassifier

scanner_bp = Blueprint('scanner', __name__)

def parse_eml(file_bytes):
    """Parses a raw EML file and extracts subject, sender, and text body."""
    try:
        # Load email from bytes
        msg = email.message_from_bytes(file_bytes, policy=policy.default)
        
        # Extract metadata
        subject = msg.get('Subject', 'No Subject')
        sender = msg.get('From', 'Unknown Sender')
        
        # Extract body
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get_content_disposition())
                
                # Check for text body parts
                if content_type == 'text/plain' and 'attachment' not in content_disposition:
                    body += part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='ignore')
                elif content_type == 'text/html' and 'attachment' not in content_disposition and not body:
                    # Clean up HTML briefly or take raw HTML (we will strip tags later)
                    raw_html = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='ignore')
                    # Very simple regex to strip basic html tags for cleaner text analysis
                    body += re.sub(r'<[^>]+>', '', raw_html)
        else:
            body = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', errors='ignore')
            
        return subject, sender, body.strip()
    except Exception as e:
        print(f"Error parsing EML file: {e}")
        return None, None, None

@scanner_bp.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    if request.method == 'POST':
        subject = request.form.get('subject', '').strip()
        body = request.form.get('body', '').strip()
        sender = request.form.get('sender', '').strip()
        file_name = None
        
        # Handle file upload
        if 'email_file' in request.files:
            file = request.files['email_file']
            if file.filename != '':
                file_name = file.filename
                file_ext = file.filename.split('.')[-1].lower()
                
                file_bytes = file.read()
                if file_ext == 'eml':
                    import re # Make sure it is imported for EML stripping
                    parsed_sub, parsed_send, parsed_body = parse_eml(file_bytes)
                    if parsed_body:
                        subject = parsed_sub
                        sender = parsed_send
                        body = parsed_body
                    else:
                        flash("Failed to parse EML file. Proceeding with manual input.", "warning")
                elif file_ext == 'txt':
                    try:
                        # Decode text file
                        txt_content = file_bytes.decode('utf-8', errors='ignore')
                        # Extract first line as subject, remainder as body
                        lines = txt_content.split('\n')
                        if len(lines) > 0:
                            subject = lines[0].replace('Subject:', '').strip()
                            body = '\n'.join(lines[1:]).strip()
                    except Exception as e:
                        flash(f"Error reading text file: {e}", "danger")
                        return redirect(url_for('scanner.scan'))
                else:
                    flash("Unsupported file format. Please upload .txt or .eml files.", "danger")
                    return redirect(url_for('scanner.scan'))
                    
        # Check requirements
        if not body:
            flash("Email body is required for scan.", "danger")
            return redirect(url_for('scanner.scan'))
            
        if not subject:
            subject = "No Subject (Manual Scan)"
            
        # Run classifier
        result = EmailClassifier.predict(subject, body, sender)
        
        # Save scan
        new_scan = Scan(
            user_id=current_user.id,
            subject=subject,
            body=body,
            file_name=file_name,
            prediction=result['prediction'],
            confidence=result['confidence'],
            risk_score=result['risk_score'],
            explanation=result['explanation']
        )
        new_scan.indicators = result['indicators'] # serialized to JSON
        
        db.session.add(new_scan)
        db.session.commit()
        
        flash("Scan completed successfully!", "success")
        return redirect(url_for('scanner.result', scan_id=new_scan.id))
        
    return render_template('scanner.html')

@scanner_bp.route('/result/<int:scan_id>')
@login_required
def result(scan_id):
    scan_record = Scan.query.get_or_404(scan_id)
    
    # Authorize: only user or admin can view this scan
    if scan_record.user_id != current_user.id and not current_user.is_admin:
        abort(403)
        
    # Reconstruct predictions dict for display UI
    # We can pass details to templates
    indicators = scan_record.indicators
    
    # Generate recommendations/explanation details dynamically based on stored data
    # (Matches our classifier logic to keep things fresh)
    dummy_res = EmailClassifier.predict(scan_record.subject, scan_record.body, "")
    
    return render_template(
        'scan_result.html',
        scan=scan_record,
        indicators=indicators,
        rec_list=dummy_res['recommendations'],
        explanation_points=dummy_res['explanation_points'],
        probabilities=dummy_res['probabilities']
    )

@scanner_bp.route('/history', methods=['GET'])
@login_required
def history():
    search_query = request.args.get('search', '').strip()
    filter_status = request.args.get('status', '').strip()
    
    # Base query
    query = Scan.query.filter_by(user_id=current_user.id)
    
    if search_query:
        query = query.filter(
            (Scan.subject.contains(search_query)) | (Scan.body.contains(search_query))
        )
        
    if filter_status and filter_status in ['Safe', 'Spam', 'Phishing']:
        query = query.filter_by(prediction=filter_status)
        
    scans_list = query.order_by(Scan.created_at.desc()).all()
    
    return render_template(
        'history.html',
        scans=scans_list,
        search_query=search_query,
        filter_status=filter_status
    )

@scanner_bp.route('/delete/<int:scan_id>', methods=['POST'])
@login_required
def delete(scan_id):
    scan_record = Scan.query.get_or_404(scan_id)
    
    # Authorize
    if scan_record.user_id != current_user.id and not current_user.is_admin:
        abort(403)
        
    db.session.delete(scan_record)
    db.session.commit()
    
    flash("Scan record deleted.", "success")
    return redirect(url_for('scanner.history'))

@scanner_bp.route('/report/<int:scan_id>')
@login_required
def report(scan_id):
    scan_record = Scan.query.get_or_404(scan_id)
    
    # Authorize
    if scan_record.user_id != current_user.id and not current_user.is_admin:
        abort(403)
        
    # Generate PDF in memory
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    
    pdf_buffer = io.BytesIO()
    
    # Page setup
    doc = SimpleDocTemplate(
        pdf_buffer,
        pagesize=letter,
        rightMargin=54,
        leftMargin=54,
        topMargin=54,
        bottomMargin=54
    )
    
    styles = getSampleStyleSheet()
    
    # Define custom styles
    title_style = ParagraphStyle(
        'ReportTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=colors.HexColor('#0f172a'), # Slate 900
        spaceAfter=15
    )
    
    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor('#1e293b'), # Slate 800
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True
    )
    
    body_style = ParagraphStyle(
        'ReportBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#475569') # Slate 600
    )
    
    bold_body_style = ParagraphStyle(
        'ReportBodyBold',
        parent=body_style,
        fontName='Helvetica-Bold'
    )
    
    bullet_style = ParagraphStyle(
        'ReportBullet',
        parent=body_style,
        leftIndent=15,
        firstLineIndent=-10,
        spaceAfter=4
    )
    
    # Color coding based on prediction
    badge_colors = {
        'Safe': colors.HexColor('#10b981'),      # Emerald 500
        'Spam': colors.HexColor('#f59e0b'),      # Amber 500
        'Phishing': colors.HexColor('#ef4444')   # Red 500
    }
    badge_bg = {
        'Safe': colors.HexColor('#d1fae5'),
        'Spam': colors.HexColor('#fef3c7'),
        'Phishing': colors.HexColor('#fee2e2')
    }
    
    pred = scan_record.prediction
    theme_color = badge_colors.get(pred, colors.gray)
    bg_color = badge_bg.get(pred, colors.lightgrey)
    
    story = []
    
    # Header Banner (Title and Date)
    story.append(Paragraph("SecureMail AI", ParagraphStyle('SubTitle', fontName='Helvetica-Bold', fontSize=10, leading=12, textColor=colors.HexColor('#64748b'))))
    story.append(Paragraph("Email Threat Analysis Report", title_style))
    story.append(Spacer(1, 10))
    
    # Table of Metadata
    metadata_data = [
        [Paragraph("Report ID:", bold_body_style), Paragraph(f"SMAI-SCAN-{scan_record.id:06d}", body_style),
         Paragraph("Scan Date:", bold_body_style), Paragraph(scan_record.created_at.strftime('%Y-%m-%d %H:%M:%S UTC'), body_style)],
        [Paragraph("User Account:", bold_body_style), Paragraph(scan_record.user.username, body_style),
         Paragraph("File Source:", bold_body_style), Paragraph(scan_record.file_name or "Direct Input Scan", body_style)],
        [Paragraph("Subject:", bold_body_style), Paragraph(scan_record.subject, body_style), "", ""]
    ]
    
    metadata_table = Table(metadata_data, colWidths=[1.2*inch, 2.3*inch, 1.2*inch, 2.3*inch])
    metadata_table.setStyle(TableStyle([
        ('SPAN', (1, 2), (3, 2)), # Span subject across columns
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
    ]))
    story.append(metadata_table)
    story.append(Spacer(1, 15))
    
    # Horizontal Divider Line
    divider_table = Table([[""]], colWidths=[7.0*inch])
    divider_table.setStyle(TableStyle([
        ('LINEABOVE', (0,0), (-1,-1), 1, colors.HexColor('#e2e8f0')),
        ('BOTTOMPADDING', (0,0), (-1,-1), 0),
        ('TOPPADDING', (0,0), (-1,-1), 0),
    ]))
    story.append(divider_table)
    story.append(Spacer(1, 15))
    
    # Prediction Status Summary Card (using a 1x1 table for border/background)
    card_text = f"""
    <b>THREAT ASSESSMENT RESULT:</b><br/><br/>
    The email subject and body were analyzed using our machine learning models and heuristic rules.<br/>
    <b>Classification:</b> <font color="{theme_color.hexval()}">{pred.upper()}</font><br/>
    <b>Risk Score:</b> {scan_record.risk_score} / 100<br/>
    <b>ML Confidence:</b> {scan_record.confidence}%<br/><br/>
    <i>{scan_record.explanation}</i>
    """
    card_p = Paragraph(card_text, ParagraphStyle('CardText', parent=body_style, fontSize=11, leading=16))
    
    card_table = Table([[card_p]], colWidths=[7.0*inch])
    card_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), bg_color),
        ('BOX', (0, 0), (-1, -1), 1.5, theme_color),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
    ]))
    story.append(card_table)
    story.append(Spacer(1, 20))
    
    # Re-evaluate rules to get bullet points list
    dummy_res = EmailClassifier.predict(scan_record.subject, scan_record.body, "")
    
    # Section: Threat Indicators
    story.append(Paragraph("Detected Threat Indicators", section_heading))
    if dummy_res['explanation_points']:
        for pt in dummy_res['explanation_points']:
            story.append(Paragraph(f"&bull; {pt}", bullet_style))
    else:
        story.append(Paragraph("No significant indicators of concern detected.", body_style))
    story.append(Spacer(1, 12))
    
    # Section: Detailed Rule Matches (if any warnings)
    indicators = scan_record.indicators
    warnings = indicators.get('warnings', [])
    if warnings:
        story.append(Paragraph("Technical Security Matches", section_heading))
        for warning in warnings:
            story.append(Paragraph(f"&bull; <font color='#ef4444'>[TRIGGER]</font> {warning}", bullet_style))
        story.append(Spacer(1, 12))
        
    # Section: Security Recommendations
    story.append(Paragraph("Cybersecurity Recommendations", section_heading))
    for rec in dummy_res['recommendations']:
        story.append(Paragraph(f"&bull; {rec}", bullet_style))
    story.append(Spacer(1, 20))
    
    # Section: Email Text Content (Cleaned/Truncated for visibility)
    story.append(Paragraph("Scanned Email Content", section_heading))
    # Display subject and body
    email_display_content = f"<b>Subject:</b> {scan_record.subject}<br/><br/>"
    # Truncate body if it is too long for the report
    body_text = scan_record.body
    if len(body_text) > 1000:
        body_text = body_text[:1000] + "... [truncated in report for brevity]"
    
    # Replace newlines with HTML breaks
    body_html = body_text.replace('\n', '<br/>')
    email_display_content += f"<b>Body:</b><br/>{body_html}"
    
    email_p = Paragraph(email_display_content, ParagraphStyle('EmailText', parent=body_style, fontSize=9, leading=13))
    email_table = Table([[email_p]], colWidths=[7.0*inch])
    email_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')), # Slate 50
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),  # Slate 300
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(email_table)
    story.append(Spacer(1, 20))
    
    # Footer disclaimer
    story.append(Paragraph("<b>Disclaimer:</b> SecureMail AI threat scores are generated using automated machine learning models and heuristics. This report does not constitute legal or absolute technical guarantees of email safety. Always double check sensitive sender credentials.", ParagraphStyle('Disclaimer', parent=body_style, fontSize=7, leading=10, textColor=colors.HexColor('#94a3b8'))))
    
    # Build Document
    doc.build(story)
    
    # Send PDF buffer
    pdf_buffer.seek(0)
    
    filename = f"SecureMail_AI_Report_Scan_{scan_record.id}.pdf"
    
    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=filename,
        mimetype='application/pdf'
    )
