import os
import urllib.request
import pandas as pd
import numpy as np
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# Paths
ML_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(ML_DIR, 'phishing_model.joblib')
VECTORIZER_PATH = os.path.join(ML_DIR, 'vectorizer.joblib')

# URL Sources
SPAM_URLS = [
    "https://raw.githubusercontent.com/RimAmarat/email_spam_detection/master/spam_or_not_spam.csv",
    "https://raw.githubusercontent.com/mwitiderrick/keras-spam-detector/master/spam.csv"
]

PHISHING_URLS = [
    "https://raw.githubusercontent.com/sadat1971/Phishing_Email/master/Phishing_Email.csv",
    "https://raw.githubusercontent.com/sadat1971/Phishing_Email/main/Phishing_Email.csv",
    "https://raw.githubusercontent.com/SINANFIROZ/Phishing-Email-Detector/main/Phishing_Email.csv"
]

def generate_synthetic_data(num_samples=1000):
    """Generates high-quality synthetic emails for Safe, Spam, and Phishing classes as a fallback."""
    print("Generating high-quality synthetic dataset as fallback...")
    
    subjects_safe = [
        "Project Update: Q3 Deliverables", "Weekly Team Sync Meeting", "Feedback on your design proposal",
        "Vacation Request Approved", "Lunch plans today?", "Code Review: Pull Request #145",
        "Happy Birthday!", "Summary of yesterday's workshop", "Gym membership renewal receipt",
        "Notes from client demonstration", "Discussion on technical architecture", "Welcome to the team!"
    ]
    bodies_safe = [
        "Hi Team,\nHere is the updated timeline for our Q3 deliverables. Please review and add your comments.",
        "Hi, are you free for lunch today at 12 PM? We can check out the new place down the street.",
        "Hey! The pull request is looking good. Just left a couple of minor comments regarding exception handling.",
        "Hi, your request for time off from next Monday to Wednesday has been approved. Have a great vacation!",
        "Hello, thank you for attending the workshop yesterday. Attached is the slide deck and meeting summary.",
        "Hi all, please remember to update your tasks in Jira before the end of the week sync on Friday. Thanks!",
        "Hey, just wanted to check if you have updated the database schema. The migration scripts need to run today.",
        "Hi team, let's schedule a brief call tomorrow to align on the technical requirements for the user dashboard."
    ]
    
    subjects_spam = [
        "Congratulations! You won the grand lottery!", "Exclusive Crypto offer - 100x gains guaranteed!",
        "Get cheap medications online now - no prescription!", "Refinance your mortgage with 0% interest",
        "Work from home and make $5000/week!", "URGENT: Claim your inheritance money today!",
        "Unbelievable weight loss pills - lose 10lbs in a week", "Invest in gold now before the crash"
    ]
    bodies_spam = [
        "Dear Customer, you have been selected as the winner of our annual sweepstakes! Claim your $1,000,000 cash prize now by clicking here.",
        "Earn passive income from home! No experience required. Start earning $500 to $1000 daily. Limited spots available, register today!",
        "Buy legal pills online with discount. Fast shipping worldwide. Click this link to see catalog of medications at cheap prices.",
        "Bitcoin is going to the moon! Get in early on the next major altcoin. Guaranteed returns of 500% in a week. Sign up now!",
        "Need a cash loan? Get approved in 5 minutes regardless of your credit score. Zero fees, low interest rates. Apply today!",
        "Double your money in just 24 hours! Safe and regulated investment platform. Thousands of members already profiting. Join now!"
    ]
    
    subjects_phishing = [
        "URGENT: Security Alert - Your account has been suspended", "Password reset request for your banking portal",
        "Action Required: Verify your security credentials", "Unusual activity detected on your PayPal account",
        "Netflix Account Update: Payment Declined", "Microsoft Outlook: Confirm your mailbox size limit",
        "Action Required: Confirm your credit card details", "Your package delivery is pending - update address"
    ]
    bodies_phishing = [
        "Dear User, we detected a suspicious login attempt to your bank account from an unknown IP address. To secure your account, please verify your identity immediately by logging in here: http://secure-verify-auth.xyz/login. Failure to verify within 24 hours will result in permanent account suspension.",
        "Alert: Your PayPal account has been temporarily restricted due to unusual activity. Please update your billing information immediately to restore full access. Log in to your portal here: http://paypal-billing-support.net/update.",
        "Important Security Update: Your email inbox is almost full. To increase your storage capacity and keep receiving emails, click the link below and log in with your email and password: http://mail-limit-update.xyz/login.",
        "Netflix: Your subscription payment failed. To avoid interruption of service, please update your payment method immediately by entering your credit card details here: http://netflix-billing-alert.click/payment.",
        "Your bank: We require you to verify your security code and OTP to authorize the pending transaction. Please click this link and enter the OTP received on your mobile: http://banking-verify-otp.top/auth."
    ]
    
    data = []
    
    # Generate samples
    for i in range(num_samples):
        cls = np.random.choice([0, 1, 2], p=[0.4, 0.3, 0.3])
        if cls == 0:  # Safe
            subject = np.random.choice(subjects_safe)
            body = np.random.choice(bodies_safe)
            data.append({"text": f"Subject: {subject}\n\n{body}", "label": 0})
        elif cls == 1:  # Spam
            subject = np.random.choice(subjects_spam)
            body = np.random.choice(bodies_spam)
            data.append({"text": f"Subject: {subject}\n\n{body}", "label": 1})
        else:  # Phishing
            subject = np.random.choice(subjects_phishing)
            body = np.random.choice(bodies_phishing)
            data.append({"text": f"Subject: {subject}\n\n{body}", "label": 2})
            
    return pd.DataFrame(data)

def download_csv(urls, temp_name):
    for url in urls:
        try:
            print(f"Trying to download dataset from: {url}")
            temp_path = os.path.join(ML_DIR, temp_name)
            urllib.request.urlretrieve(url, temp_path)
            print(f"Download successful: {temp_name}")
            return temp_path
        except Exception as e:
            print(f"Failed download from {url}: {e}")
    return None

def train():
    print("Preparing datasets for model training...")
    
    spam_file = download_csv(SPAM_URLS, "temp_spam.csv")
    phish_file = download_csv(PHISHING_URLS, "temp_phish.csv")
    
    df_list = []
    
    # Load Spam/Ham dataset
    if spam_file:
        try:
            df = pd.read_csv(spam_file, encoding='latin-1')
            # Handle different dataset shapes
            if 'email' in df.columns and 'label' in df.columns:
                # RimAmarat dataset: email, label (0=ham, 1=spam)
                df = df[['email', 'label']].rename(columns={'email': 'text'})
                # Map Ham to 0, Spam to 1
                df_list.append(df)
            elif 'v1' in df.columns and 'v2' in df.columns:
                # SMS/Email Spam: v1 (ham/spam), v2 (text)
                df = df[['v2', 'v1']].rename(columns={'v2': 'text', 'v1': 'label'})
                df['label'] = df['label'].map({'ham': 0, 'spam': 1})
                df_list.append(df)
            print(f"Loaded spam dataset successfully. Shape: {df.shape}")
        except Exception as e:
            print(f"Error reading spam dataset: {e}")
            
    # Load Phishing dataset
    if phish_file:
        try:
            df = pd.read_csv(phish_file, encoding='latin-1')
            if 'Email Text' in df.columns and 'Email Type' in df.columns:
                # sadat1971 dataset: Email Text, Email Type ("Safe Email", "Phishing Email")
                df = df[['Email Text', 'Email Type']].rename(columns={'Email Text': 'text', 'Email Type': 'label'})
                # Map Phishing Email to 2, Safe Email to 0
                df['label'] = df['label'].map({'Safe Email': 0, 'Phishing Email': 2})
                df = df.dropna(subset=['label'])
                df_list.append(df)
            print(f"Loaded phishing dataset successfully. Shape: {df.shape}")
        except Exception as e:
            print(f"Error reading phishing dataset: {e}")
            
    # Clean up temp files
    for temp in ["temp_spam.csv", "temp_phish.csv"]:
        tp = os.path.join(ML_DIR, temp)
        if os.path.exists(tp):
            try:
                os.remove(tp)
            except:
                pass
                
    # Combine datasets or fallback
    if len(df_list) >= 2:
        try:
            full_df = pd.concat(df_list, ignore_index=True)
            full_df = full_df.dropna(subset=['text', 'label'])
            full_df['label'] = full_df['label'].astype(int)
            print(f"Merged datasets successfully. Total samples: {full_df.shape[0]}")
            
            # Balance dataset slightly to prevent massive skew
            # Limit safe to max 5000, spam to max 5000, phish to max 5000
            grouped = full_df.groupby('label')
            sampled_dfs = []
            for label, group in grouped:
                sample_size = min(len(group), 5000)
                sampled_dfs.append(group.sample(n=sample_size, random_state=42))
            full_df = pd.concat(sampled_dfs, ignore_index=True)
            print(f"Balanced dataset. Samples per class: {full_df['label'].value_counts().to_dict()}")
        except Exception as e:
            print(f"Failed merging datasets: {e}")
            full_df = generate_synthetic_data()
    else:
        print("Required public datasets not fully available.")
        full_df = generate_synthetic_data()
        
    # Preprocessing
    full_df['text'] = full_df['text'].fillna('')
    full_df['text'] = full_df['text'].str.lower()
    
    # TF-IDF Vectorization
    print("Preprocessing text using TF-IDF vectorization...")
    vectorizer = TfidfVectorizer(
        stop_words='english',
        max_features=5000,
        ngram_range=(1, 2)
    )
    
    X = vectorizer.fit_transform(full_df['text'])
    y = full_df['label'].values
    
    # Train / Test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Train Logistic Regression
    print("Training Logistic Regression model...")
    model = LogisticRegression(max_iter=1000, class_weight='balanced')
    model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Spam', 'Phishing']))
    
    # Save model and vectorizer
    print(f"Saving models to:\n- {MODEL_PATH}\n- {VECTORIZER_PATH}")
    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    print("Model training completed successfully!")

if __name__ == '__main__':
    train()
