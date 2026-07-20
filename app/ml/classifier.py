import os
import joblib
from app.ml.rules import RuleEngine

ML_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(ML_DIR, 'phishing_model.joblib')
VECTORIZER_PATH = os.path.join(ML_DIR, 'vectorizer.joblib')

class EmailClassifier:
    _model = None
    _vectorizer = None
    
    @classmethod
    def load_model(cls):
        # Bootstrap: train model if joblib files do not exist
        if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
            print("Model files not found. Bootstrapping training process...")
            from app.ml.train_model import train
            try:
                train()
            except Exception as e:
                print(f"Error training model during bootstrap: {e}")
                
        # Load from disk
        if cls._model is None:
            try:
                cls._model = joblib.load(MODEL_PATH)
                cls._vectorizer = joblib.load(VECTORIZER_PATH)
                print("Model and Vectorizer loaded successfully!")
            except Exception as e:
                print(f"Error loading model files: {e}")
                cls._model = None
                cls._vectorizer = None

    @classmethod
    def predict(cls, subject, body, sender=""):
        cls.load_model()
        
        # Combine text for classification
        email_text = f"Subject: {subject}\n\n{body}"
        cleaned_text = email_text.lower()
        
        # Run Rule-based Heuristics
        rules_result = RuleEngine.analyze(subject, body, sender)
        
        # Default fallback values if model fails to load
        prediction_class = "Safe"
        ml_confidence = 100.0
        probabilities = [1.0, 0.0, 0.0]
        
        if cls._model is not None and cls._vectorizer is not None:
            try:
                vectorized = cls._vectorizer.transform([cleaned_text])
                pred_idx = cls._model.predict(vectorized)[0]
                prob = cls._model.predict_proba(vectorized)[0]
                
                classes = {0: "Safe", 1: "Spam", 2: "Phishing"}
                prediction_class = classes.get(pred_idx, "Safe")
                ml_confidence = float(prob[pred_idx] * 100)
                probabilities = [float(p) for p in prob]
            except Exception as e:
                print(f"Error running model prediction: {e}")
                
        # Heuristic Override / Combined Risk Score Calculation
        rules_score = rules_result['score']
        
        # We compute a combined risk score out of 100
        if prediction_class == "Safe":
            # If model thinks it's Safe but we triggered heavy rules (e.g. brand spoofing, suspicious URL)
            if rules_score >= 40:
                # Elevate risk to suspicious
                risk_score = min(35 + rules_score * 0.4, 65)
                explanation = "Although the machine learning model classified the text pattern as legitimate, significant heuristic threats (such as brand impersonation or suspicious links) were detected, rendering it suspicious."
            else:
                risk_score = max(rules_score * 0.6, (100 - ml_confidence) * 0.2)
                risk_score = min(risk_score, 30)  # Max risk for safe is 30
                explanation = "This email appears to be safe. No significant indicators of spam or phishing were detected. The layout and phrasing match normal business or personal communications."
                
        elif prediction_class == "Spam":
            # Spam has moderate-high risk
            base_risk = 40
            risk_score = base_risk + (ml_confidence * 0.3) + (rules_score * 0.3)
            risk_score = min(risk_score, 80)  # Max risk for spam is 80
            explanation = "This email has been classified as Spam. It contains language and formatting common in unsolicited marketing, newsletters, or bulk promotional emails."
            
        else:  # Phishing
            # Phishing has very high risk
            base_risk = 70
            risk_score = base_risk + (ml_confidence * 0.15) + (rules_score * 0.15)
            risk_score = min(risk_score, 100)  # Max risk is 100
            explanation = "WARNING: This email has been flagged as Phishing. It displays high-risk indicators of identity theft, credit card fraud, or credential harvesting."
            
        # Refine explanation based on rules triggered
        bullet_points = []
        if prediction_class == "Phishing" or rules_score >= 40:
            if rules_result['brand_impersonation']:
                bullet_points.append(f"Impersonation of {', '.join(rules_result['brand_impersonation'])} detected.")
            if rules_result['suspicious_urls']:
                bullet_points.append(f"Contains {len(rules_result['suspicious_urls'])} high-risk links (IP addresses, bad domain suffixes, or typosquats).")
            if rules_result['credential_request_count'] > 0:
                bullet_points.append("Requests input of personal credentials, password resets, or authentication codes (OTPs).")
            if rules_result['urgent_language_count'] > 0:
                bullet_points.append("Uses coercive, urgent, or threatening language to force action.")
            if rules_result['suspicious_sender']:
                bullet_points.append("Sender email address mismatches corporate domain or uses a known high-risk TLD.")
        elif prediction_class == "Spam":
            if rules_result['urgent_language_count'] > 0:
                bullet_points.append("Contains urgent sales pitches or sweepstakes promotional wording.")
            if rules_result['excessive_punctuation']:
                bullet_points.append("Uses excessive punctuation (like '!!!', '$$$') typical of bulk marketing.")
            if len(rules_result['suspicious_urls']) > 0:
                bullet_points.append("Contains commercial links redirecting to promotional websites.")
        else:
            bullet_points.append("No active indicators of identity spoofing, credential theft, or bulk promotion were detected.")
            
        # Security recommendations based on findings
        recommendations = []
        if prediction_class == "Phishing" or rules_score >= 40:
            recommendations = [
                "Do NOT click on any links or download any attachments in this email.",
                "Do NOT reply to the sender or provide passwords, security codes, or OTPs.",
                "Verify the sender's identity through an independent, trusted channel (e.g. call their official number).",
                "Report this message to your organization's IT security team immediately."
            ]
        elif prediction_class == "Spam":
            recommendations = [
                "Unsubscribe from this mailing list if it is a standard newsletter you no longer wish to receive.",
                "Do NOT click unsubscribes on suspicious emails as it confirms your address is active.",
                "Mark the sender as junk/spam to block future emails.",
                "Avoid purchasing items or entering personal details on websites linked from spam."
            ]
        else:
            recommendations = [
                "This email is classified as Safe. However, always exercise caution with external links.",
                "If the sender's tone feels unusual, double-check by contacting them directly.",
                "Ensure your email client displays the actual sender address, not just the display name."
            ]
            
        return {
            'prediction': prediction_class,
            'confidence': round(ml_confidence, 1),
            'risk_score': round(risk_score, 1),
            'explanation': explanation,
            'explanation_points': bullet_points,
            'recommendations': recommendations,
            'indicators': rules_result,
            'probabilities': {
                'Safe': round(probabilities[0] * 100, 1),
                'Spam': round(probabilities[1] * 100, 1),
                'Phishing': round(probabilities[2] * 100, 1)
            }
        }
