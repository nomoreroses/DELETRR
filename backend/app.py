"""
Backend Flask for DELETRR (English Version)
"""
from flask import Flask, jsonify, request, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta, timezone
import os
import imaplib
import smtplib
import email
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import decode_header, make_header
from functools import wraps
import re
import threading
import time
import requests
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

# Gestion de l'import optionnel pour la recherche Google
try:
    from googlesearch import search 
except ImportError:
    print("Module 'googlesearch-python' missing. Web intelligence disabled.")
    search = None

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'deletrr-secret-key-prod')
CORS(app, supports_credentials=True, origins=['http://localhost:5173', 'http://127.0.0.0.1:5173'])

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///deletrr_app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

SCAN_PROGRESS = {}
SCAN_ABORT = {}

# ============ MODELS ============
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    app_password = db.Column(db.String(255))
    full_name = db.Column(db.String(255))
    address = db.Column(db.String(500))
    city = db.Column(db.String(255))
    last_rgpd_scan_uid = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    emails = db.relationship('Email', backref='user', lazy=True, cascade="all, delete-orphan")
    whitelists = db.relationship('Whitelist', backref='user', lazy=True, cascade="all, delete-orphan")
    rgpd_cases = db.relationship('RGPDCase', backref='user', lazy=True, cascade="all, delete-orphan")

class Whitelist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sender_email = db.Column(db.String(255), nullable=False)
    sender_name = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Email(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    gmail_id = db.Column(db.String(255))
    sender = db.Column(db.String(255))
    sender_email = db.Column(db.String(255))
    domain = db.Column(db.String(255))
    subject = db.Column(db.String(500))
    date = db.Column(db.DateTime)
    email_type = db.Column(db.String(50))
    status = db.Column(db.String(50), default='detected')
    is_protected = db.Column(db.Boolean, default=False)
    action_recommended = db.Column(db.String(50))
    action_reason = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class RGPDCase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    email_id = db.Column(db.Integer, db.ForeignKey('email.id'))
    company_name = db.Column(db.String(255))
    company_email = db.Column(db.String(255))
    dpo_email = db.Column(db.String(255))
    status = db.Column(db.String(50), default='pending_response')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    messages = db.relationship('RGPDMessage', backref='case', lazy=True, cascade="all, delete-orphan")

class RGPDMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('rgpd_case.id'), nullable=False)
    direction = db.Column(db.String(10))
    sender_name = db.Column(db.String(255))
    subject = db.Column(db.String(500))
    body = db.Column(db.Text)
    summary = db.Column(db.Text)  # Résumé généré par l'IA
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ============ HELPERS ============
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session: return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

def decode_mime_header(header_value):
    if not header_value: return ""
    decoded_parts = decode_header(header_value)
    result = ""
    for part, encoding in decoded_parts:
        if isinstance(part, bytes): result += part.decode(encoding or 'utf-8', errors='replace')
        else: result += part
    return result

def parse_sender(from_header):
    from_header = decode_mime_header(from_header)
    match = re.match(r'^(?:"?([^"<]*)"?\s*)?<?([^>]+@[^>]+)>?$', from_header)
    if match: return match.group(1).strip() or match.group(2).split('@')[0], match.group(2).strip()
    return from_header.strip(), from_header.strip()

def get_provider_settings(email_addr):
    domain = email_addr.split('@')[-1].lower()
    if 'yahoo' in domain or 'ymail' in domain:
        return {'name': 'yahoo', 'imap_host': 'imap.mail.yahoo.com', 'imap_port': 993, 'smtp_host': 'smtp.mail.yahoo.com', 'smtp_port': 465, 'smtp_tls': False, 'trash_folders': ['Trash', 'Deleted', 'Corbeille']}
    elif 'outlook' in domain or 'hotmail' in domain or 'live' in domain:
        return {'name': 'outlook', 'imap_host': 'outlook.office365.com', 'imap_port': 993, 'smtp_host': 'smtp.office365.com', 'smtp_port': 587, 'smtp_tls': True, 'trash_folders': ['Deleted', 'Deleted Items', 'Corbeille']}
    else:
        return {'name': 'gmail', 'imap_host': 'imap.gmail.com', 'imap_port': 993, 'smtp_host': 'smtp.gmail.com', 'smtp_port': 465, 'smtp_tls': False, 'trash_folders': ['[Gmail]/Trash', '[Gmail]/Corbeille', '[Gmail]/Bin']}

def get_imap_connection(user):
    settings = get_provider_settings(user.email)
    imap = imaplib.IMAP4_SSL(settings['imap_host'], settings['imap_port'])
    imap.login(user.email, user.app_password)
    return imap

def send_confirmation_email(user, dpo_email, company_name):
    subject = f"Confirmation: Right to be Forgotten Request - {company_name}"
    email_body = f"""
Dear Data Protection Officer / Privacy Team,

This email confirms my request for the erasure of my personal data (Right to be Forgotten) for the company {company_name}. 

Please proceed immediately with the final and complete deletion of all my data, as requested in my previous message, and confirm once completed.

Sincerely,
{user.full_name}
"""
    settings = get_provider_settings(user.email)
    msg = MIMEMultipart()
    msg['From'] = user.email
    msg['To'] = dpo_email
    msg['Subject'] = subject
    msg.attach(MIMEText(email_body, 'plain'))
    if settings['smtp_tls']:
        server = smtplib.SMTP(settings['smtp_host'], settings['smtp_port'])
        server.starttls() 
    else:
        server = smtplib.SMTP_SSL(settings['smtp_host'], settings['smtp_port'])
    server.login(user.email, user.app_password)
    server.sendmail(user.email, dpo_email, msg.as_string())
    server.quit()
    return subject, email_body

# ============ IA OLLAMA ============
def ask_ollama_classification(sender, subject):
    url = "http://localhost:11434/api/generate"
    prompt = f"""
    Role: Strict email cleaner. Task: Classify as KEEP or DELETE or RGPD_UNSUB.
    RGPD_UNSUB: Newsletters, Marketing, Promotional content that comes from a specific company (e.g. Netflix, Amazon, etc.).
    DELETE: Notifications, Auto-replies, Security alerts (Google/Yahoo), Job alerts, Social Network notifications.
    KEEP: Personal emails, Invoices, Bills, Travel tickets, Direct Interview invites, Official Government/Bank communications.
    Email: Sender: {sender}, Subject: {subject}
    Output: KEEP or DELETE or RGPD_UNSUB
    """
    try:
        response = requests.post(url, json={ "model": "llama3:8b", "prompt": prompt, "stream": False, "temperature": 0.0, "keep_alive": "5m" }, timeout=30)
        decision = response.json()['response'].strip().upper()
        if "RGPD_UNSUB" in decision: return 'RGPD_UNSUB'
        if "KEEP" in decision: return 'KEEP'
        return 'DELETE'
    except: return 'DELETE'

def ask_ollama_find_email(company_name, search_snippets):
    url = "http://localhost:11434/api/generate"
    prompt = f"""
    Context: I have gathered search results to find the DPO (Data Protection Officer) or Privacy contact email for company: "{company_name}".
    Search Results Snippets: {search_snippets}
    Task: Analyze these snippets and extract the most likely email address to contact for GDPR/Privacy requests.
    Rules: 1. Output ONLY the email address found. 2. Look for 'privacy@', 'dpo@', 'dataprotection@'. 3. If none, look for 'contact@', 'support@'. 4. If absolutely NO email is found, output: NOT_FOUND
    """
    try:
        response = requests.post(url, json={ "model": "llama3:8b", "prompt": prompt, "stream": False, "temperature": 0.0 }, timeout=30)
        return response.json()['response'].strip()
    except: return "NOT_FOUND"

# --- IA JUGE ET RESUMEUR ---
def ask_ollama_judge(sender, body_text):
    """
    IA Juge : Retourne le résumé si c'est pertinent, ou 'IGNORE' si c'est du bruit.
    """
    if not body_text or len(body_text) < 50: return "IGNORE"
    
    clean_body = body_text[:2000]
    url = "http://localhost:11434/api/generate"
    
    prompt = f"""
    Role: GDPR Email Filter.
    Context: The user sent a "Right to be Forgotten" request to {sender}.
    Incoming Email Body:
    {clean_body}
    
    Task: Decide if this is a relevant reply.
    1. If it is a Newsletter, Promo, "Welcome", "New Owner", or General Announcement: Output "IGNORE".
    2. If it is a reply about the deletion request (confirmation, ticket opened, asking for details): Summarize it in 1 sentence.
    
    Output ONLY "IGNORE" or the summary.
    """
    try:
        response = requests.post(url, json={ "model": "llama3:8b", "prompt": prompt, "stream": False, "temperature": 0.0 }, timeout=25)
        return response.json()['response'].strip()
    except: return None

# ============ LOGIQUE GDPR ============
def check_for_and_log_reply(sender_email, subject, body, user_id, is_bulk=False):
    # 1. Filtre Technique (Headers + Mots clés basiques)
    if is_bulk: return False
    
    subject_lower = subject.lower()
    # Mots-clés qui tuent le process direct
    newsletter_keywords = ['newsletter', 'promo', 'solde', 'black friday', 'noël', 'offerte', 'publicité', 'découvrez', 'welcome', 'bienvenue', 'introduction']
    if any(kw in subject_lower for kw in newsletter_keywords): return False

    sender_email_lower = sender_email.lower().strip()
    sender_domain = sender_email_lower.split('@')[-1] if '@' in sender_email_lower else ''
    
    with app.app_context():
        # Trouver le cas correspondant
        active_cases = RGPDCase.query.filter_by(user_id=user_id).filter(
            RGPDCase.status.in_(['pending_response', 'awaiting_confirmation', 'response_received'])
        ).all()
        
        active_case = None
        for case in active_cases:
            dpo_lower = (case.dpo_email or '').lower().strip()
            company_lower = (case.company_email or '').lower().strip()
            # Match flexible
            if (sender_email_lower == dpo_lower or 
                sender_email_lower == company_lower or 
                (sender_domain and sender_domain in [dpo_lower.split('@')[-1], company_lower.split('@')[-1]])):
                active_case = case
                break

        if not active_case: return False

        # Check doublon
        if RGPDMessage.query.filter_by(case_id=active_case.id, direction='received', subject=subject).first():
            return False 

        # 2. LE JUGE IA (Le filtre intelligent)
        ai_verdict = ask_ollama_judge(active_case.company_name, body)
        
        # Si l'IA dit que c'est du bruit, on rejette
        if not ai_verdict or "IGNORE" in ai_verdict.upper():
            print(f"[RGPD FILTER] Rejeté par l'IA : {subject}")
            return False

        # 3. C'est valide -> On sauvegarde avec le résumé
        new_msg = RGPDMessage(
            case_id=active_case.id,
            direction='received', 
            sender_name=active_case.company_name, 
            subject=subject,
            body=body,
            summary=ai_verdict, # On stocke le verdict qui est le résumé
            created_at=datetime.utcnow()
        )
        db.session.add(new_msg)

        # Mise à jour du statut selon le contenu
        body_lower = body.lower()
        if any(kw in body_lower for kw in ['répondre', 'confirmer', 'attente de vous lire']):
            active_case.status = 'awaiting_confirmation'
        elif any(kw in body_lower for kw in ['supprimé', 'clôturé', 'effacé']):
            active_case.status = 'completed'
        else:
            active_case.status = 'response_received'

        db.session.commit()
        return True

def analyze_email_hybrid(email_data, whitelist_set):
    sender, sender_email, subject, date = email_data['sender'], email_data['sender_email'], email_data['subject'], email_data['date']
    subject_lower, sender_lower, domain = subject.lower(), sender.lower(), sender_email.split('@')[-1].lower() if '@' in sender_email else ''
    now = datetime.now(timezone.utc)
    if date.tzinfo is None: date = date.replace(tzinfo=timezone.utc)
    days_old = (now - date).days

    if sender_email in whitelist_set: return 'KEEP', 'Trusted Sender', 'whitelisted'
    if any(d in sender_lower or d in domain for d in DELETE_ALWAYS_DOMAINS): return 'DELETE', 'Blacklist', 'trash_list'
    if any(d in sender_lower or d in domain for d in DELETE_OLDER_30_DOMAINS):
        return ('DELETE', 'Social Network > 30d', 'social_old') if days_old > 30 else ('DELETE', 'Social Network', 'social_recent')
    if any(k in subject_lower for k in TRASH_PATTERNS): return 'DELETE', 'Spam Keyword', 'trash_pattern'
    if any(d in domain for d in SAFE_DOMAINS_STRICT): return 'KEEP', 'Vital/Official', 'vital'

    llama_verdict = ask_ollama_classification(sender, subject)
    if llama_verdict == 'RGPD_UNSUB': return 'RGPD_UNSUB', 'AI: GDPR Unsubscribe', 'ai_rgpd'
    if llama_verdict == 'DELETE': return 'DELETE', 'AI: Useless', 'ai_clean'
    return 'KEEP', 'AI: Important', 'ai_keep'

def process_email_task(email_raw_data, whitelist_set, user_id):
    uid, raw_bytes = email_raw_data
    try:
        msg = email.message_from_bytes(raw_bytes)
        subject = decode_mime_header(msg.get('Subject', '(No Subject)'))
        sender_name, sender_email_addr = parse_sender(msg.get('From', ''))
        date_str = msg.get('Date', '')
        try: email_date = email.utils.parsedate_to_datetime(date_str)
        except: email_date = datetime.now()
        
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype == 'text/plain' and 'attachment' not in str(part.get('Content-Disposition')):
                    try: body = part.get_payload(decode=True).decode('utf-8', errors='replace')
                    except: pass; break
        else:
            if msg.get_content_type() == 'text/plain':
                 try: body = msg.get_payload(decode=True).decode('utf-8', errors='replace')
                 except: pass

        data_dict = {'sender': sender_name, 'sender_email': sender_email_addr, 'subject': subject, 'date': email_date}
        
        # Filtre technique
        is_bulk = msg.get('List-Unsubscribe') is not None or msg.get('List-Unsubscribe-Post') is not None
        
        if check_for_and_log_reply(sender_email_addr, subject, body, user_id, is_bulk=is_bulk):
             return {'uid': uid, 'action': 'RGPD_REPLY', 'reason': 'Incoming DPO reply', 'type': 'reply_handled'}

        action, reason, etype = analyze_email_hybrid(data_dict, whitelist_set)
        return {'uid': uid, 'sender': sender_name, 'sender_email': sender_email_addr, 'domain': sender_email_addr.split('@')[-1], 'subject': subject, 'date': email_date, 'action': action, 'reason': reason, 'type': etype, 'is_protected': (etype == 'whitelisted')}
    except Exception as e: 
        print(f"Error processing email {uid}: {e}")
        return None

def run_scan_process(app_context, user_id):
    with app_context:
        user = User.query.get(user_id)
        if not user: return
        whitelist_set = {w.sender_email for w in Whitelist.query.filter_by(user_id=user.id).all()}
        SCAN_PROGRESS[user_id] = {'status': 'scanning', 'total': 0, 'current': 0, 'eta_seconds': 0, 'current_action': 'Connecting...', 'logs': []}
        start_time = time.time()
        try:
            imap = get_imap_connection(user)
            imap.select('INBOX')
            date_since = (datetime.now() - timedelta(days=365)).strftime('%d-%b-%Y')
            status, messages = imap.search(None, f'(SINCE {date_since})')
            if status != 'OK': raise Exception("IMAP Error")
            email_ids = messages[0].split()
            total_emails = len(email_ids)
            SCAN_PROGRESS[user_id]['total'] = total_emails
            raw_emails = []
            
            for i in range(0, len(email_ids), 100):
                if SCAN_ABORT.get(user_id):
                    SCAN_PROGRESS[user_id]['status'] = 'stopped'
                    SCAN_ABORT[user_id] = False
                    return
                batch_ids = email_ids[i:i+100]
                batch_str = b','.join(batch_ids).decode()
                status, data = imap.fetch(batch_str, '(UID RFC822)') 
                if status == 'OK':
                    for response_part in data:
                        if isinstance(response_part, tuple):
                            uid_match = re.search(r'UID\s+(\d+)', response_part[0].decode())
                            uid = uid_match.group(1).strip() if uid_match else str(time.time())
                            if not Email.query.filter_by(user_id=user.id, gmail_id=uid).first():
                                raw_emails.append((uid, response_part[1]))
                SCAN_PROGRESS[user_id]['current_action'] = f"Downloading: {i + len(batch_ids)}/{total_emails}"
            imap.logout()
            
            new_emails_objects = []
            with ThreadPoolExecutor(max_workers=12) as executor:
                future_to_uid = {executor.submit(process_email_task, item, whitelist_set, user.id): item[0] for item in raw_emails}
                processed_count = 0
                for future in as_completed(future_to_uid):
                    if SCAN_ABORT.get(user_id):
                        SCAN_PROGRESS[user_id]['status'] = 'stopped'
                        SCAN_ABORT[user_id] = False
                        executor.shutdown(wait=False)
                        break
                    result = future.result()
                    processed_count += 1
                    elapsed = time.time() - start_time
                    avg = elapsed / processed_count if processed_count > 0 else 0
                    remaining = len(raw_emails) - processed_count
                    SCAN_PROGRESS[user_id]['current'] = processed_count
                    SCAN_PROGRESS[user_id]['eta_seconds'] = int(remaining * avg)
                    
                    if result and result.get('action') != 'RGPD_REPLY':
                        SCAN_PROGRESS[user_id]['current_action'] = f"Analyzing: {result['sender'][:20]}..."
                        new_email = Email(
                            user_id=user.id, gmail_id=result['uid'], 
                            sender=result['sender'][:255], sender_email=result['sender_email'][:255], 
                            domain=result['domain'][:255], subject=result['subject'][:500], 
                            date=result['date'], email_type=result['type'],
                            action_recommended=result['action'], action_reason=result['reason'],
                            is_protected=result['is_protected']
                        )
                        new_emails_objects.append(new_email)
                    elif result and result.get('action') == 'RGPD_REPLY':
                         SCAN_PROGRESS[user_id]['current_action'] = f"Logged GDPR Reply."
            if new_emails_objects:
                db.session.bulk_save_objects(new_emails_objects)
                db.session.commit()
            if SCAN_PROGRESS[user_id]['status'] != 'stopped':
                SCAN_PROGRESS[user_id]['status'] = 'complete'
        except Exception as e:
            SCAN_PROGRESS[user_id]['status'] = 'error'
            print(f"Scan failed for user {user_id}: {e}")

@app.route('/api/auth/status')
def auth_status():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user: return jsonify({'authenticated': True, 'user': {'email': user.email, 'full_name': user.full_name, 'provider': get_provider_settings(user.email)['name']}})
    return jsonify({'authenticated': False})

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data.get('email')).first()
    if not user:
        user = User(email=data.get('email'))
        db.session.add(user)
    user.app_password = data.get('app_password')
    db.session.commit()
    session['user_id'] = user.id
    return jsonify({'success': True})

@app.route('/api/auth/logout', methods=['POST'])
def logout(): session.clear(); return jsonify({'success': True})

@app.route('/api/emails/scan', methods=['POST'])
@login_required
def start_scan():
    user_id = session['user_id']
    if user_id in SCAN_PROGRESS and SCAN_PROGRESS[user_id]['status'] == 'scanning': return jsonify({'success': True})
    SCAN_ABORT[user_id] = False
    thread = threading.Thread(target=run_scan_process, args=(app.app_context(), user_id))
    thread.start()
    return jsonify({'success': True})

@app.route('/api/emails/scan/stop', methods=['POST'])
@login_required
def stop_scan(): SCAN_ABORT[session['user_id']] = True; return jsonify({'success': True})

@app.route('/api/emails/scan/progress')
@login_required
def get_progress():
    user_id = session['user_id']
    if user_id not in SCAN_PROGRESS: return jsonify({'status': 'idle'})
    p = SCAN_PROGRESS[user_id]
    return jsonify({'status': p['status'], 'percent': int((p['current']/p['total'])*100) if p['total']>0 else 0, 'action': p['current_action']})

@app.route('/api/emails')
@login_required
def get_emails():
    all_emails = Email.query.filter_by(user_id=session['user_id']).order_by(Email.date.desc()).all()
    rgpd_senders = {}
    for e in all_emails:
        if e.action_recommended == 'RGPD_UNSUB':
            key = e.domain.lower()
            if key not in rgpd_senders: rgpd_senders[key] = e
    final_emails = []
    for e in all_emails:
        if e.action_recommended == 'RGPD_UNSUB':
            if rgpd_senders.get(e.domain.lower()) == e: final_emails.append(e)
        else: final_emails.append(e)
    return jsonify([{'id': e.id, 'sender': e.sender, 'sender_email': e.sender_email, 'subject': e.subject, 'date': e.date.strftime('%Y-%m-%d'), 'status': e.status, 'action': e.action_recommended, 'reason': e.action_reason, 'isProtected': e.is_protected} for e in final_emails])

@app.route('/api/emails/<int:email_id>/protect', methods=['POST'])
@login_required
def toggle_protection(email_id):
    em = Email.query.filter_by(id=email_id, user_id=session['user_id']).first()
    if em:
        em.is_protected = not em.is_protected
        db.session.commit()
        return jsonify({'success': True, 'isProtected': em.is_protected})
    return jsonify({'error': '404'}), 404

@app.route('/api/whitelist', methods=['GET'])
@login_required
def get_whitelist():
    items = Whitelist.query.filter_by(user_id=session['user_id']).all()
    return jsonify([{'id': i.id, 'email': i.sender_email, 'name': i.sender_name} for i in items])

@app.route('/api/whitelist', methods=['POST'])
@login_required
def add_whitelist():
    user_id = session['user_id']
    data = request.json
    if not Whitelist.query.filter_by(user_id=user_id, sender_email=data['email']).first():
        db.session.add(Whitelist(user_id=user_id, sender_email=data['email'], sender_name=data['name']))
        Email.query.filter_by(user_id=user_id, sender_email=data['email']).update({'action_recommended': 'KEEP', 'is_protected': True, 'action_reason': 'Whitelisted'})
        db.session.commit()
    return jsonify({'success': True})

@app.route('/api/whitelist/remove-sender', methods=['POST'])
@login_required
def remove_whitelist_sender():
    user_id = session['user_id']
    email_addr = request.json.get('email')
    Whitelist.query.filter_by(user_id=user_id, sender_email=email_addr).delete()
    Email.query.filter_by(user_id=user_id, sender_email=email_addr).update({'is_protected': False})
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/emails/bulk-delete', methods=['POST'])
@login_required
def bulk_delete():
    user = User.query.get(session['user_id'])
    emails = Email.query.filter_by(user_id=user.id, action_recommended='DELETE', is_protected=False, status='detected').all()
    count = 0
    try:
        imap = get_imap_connection(user)
        imap.select('INBOX')
        uids = [e.gmail_id for e in emails if e.gmail_id]
        for i in range(0, len(uids), 50):
            chunk = uids[i:i+50]
            try: imap.uid('STORE', ','.join(chunk), '+FLAGS', '(\\Deleted)'); count += len(chunk)
            except: pass
        imap.expunge(); imap.logout()
    except: pass
    for e in emails: e.status = 'deleted'
    db.session.commit()
    return jsonify({'success': True, 'deleted': count})

@app.route('/api/rgpd/search-contact', methods=['POST'])
@login_required
def search_dpo_contact():
    data = request.json
    company = data.get('company_name')
    domain = data.get('domain')
    default_email = f"dpo@{domain}"
    if search is None: return jsonify({'success': True, 'email': default_email, 'source': "default_dpo_no_search", 'company': company})
    queries = [f"DPO {domain} email contact", f"{company} privacy policy contact email dpo rgpd", f"RGPD {domain} contact", f"GDPR {domain} privacy email"]
    search_results = ""
    seen_urls = set()
    try:
        for q in queries:
            for result in search(q, num_results=2, advanced=True):
                if result.url not in seen_urls:
                    clean_desc = result.description.replace('\n', ' ').strip()
                    search_results += f"Source: {result.url}\nText: {clean_desc}\n\n"
                    seen_urls.add(result.url)
            time.sleep(1)
    except Exception: pass
    found_email_raw = ask_ollama_find_email(company, search_results)
    final_email = default_email
    source = "default_dpo_not_found"
    if "NOT_FOUND" not in found_email_raw:
        all_emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', found_email_raw)
        if all_emails:
            unique_emails = list(dict.fromkeys(all_emails))
            dpo_candidate = next((e for e in unique_emails if 'dpo@' in e.lower()), None)
            privacy_candidate = next((e for e in unique_emails if 'privacy@' in e.lower() or 'rgpd@' in e.lower() or 'data' in e.lower()), None)
            generic_candidate = next((e for e in unique_emails if any(prefix in e.lower() for prefix in ['support@', 'contact@', 'info@'])), None)
            if dpo_candidate: final_email, source = dpo_candidate, "web_search_ai (DPO match)"
            elif privacy_candidate: final_email, source = privacy_candidate, "web_search_ai (Privacy match)"
            elif generic_candidate: final_email, source = generic_candidate, "web_search_ai (Generic match)"
            else: final_email, source = unique_emails[0], "web_search_ai (Best guess)"
    return jsonify({'success': True, 'email': final_email, 'source': source, 'company': company})

@app.route('/api/rgpd/send', methods=['POST'])
@login_required
def send_rgpd_request():
    user = User.query.get(session['user_id'])
    data = request.json
    email_id = data.get('email_id')
    dpo_email = data.get('dpo_email')
    if not user.full_name or not user.address or not user.city: return jsonify({'error': 'User profile incomplete'}), 400
    em = Email.query.filter_by(id=email_id, user_id=user.id).first()
    if not em: return jsonify({'error': 'Email not found'}), 404
    if RGPDCase.query.filter_by(email_id=em.id).first(): return jsonify({'success': True, 'message': 'Case already filed'})
    subject = f"Right to be Forgotten Request - {em.sender}"
    email_body = f"""Dear Data Protection Officer,\n\nI hereby exercise my right to erasure (GDPR Art. 17) regarding my personal data held by {em.sender}.\n\nIdentity:\n{user.full_name}\n{user.email}\n{user.address}, {user.city}\n\nPlease confirm deletion within 30 days.\n\nSincerely,\n{user.full_name}"""
    try:
        settings = get_provider_settings(user.email)
        msg = MIMEMultipart()
        msg['From'] = user.email
        msg['To'] = dpo_email
        msg['Subject'] = subject
        msg.attach(MIMEText(email_body, 'plain'))
        if settings['smtp_tls']:
            server = smtplib.SMTP(settings['smtp_host'], settings['smtp_port'])
            server.starttls() 
        else:
            server = smtplib.SMTP_SSL(settings['smtp_host'], settings['smtp_port'])
        server.login(user.email, user.app_password)
        server.sendmail(user.email, dpo_email, msg.as_string())
        server.quit()
    except Exception as e: return jsonify({'error': str(e)}), 500
    case = RGPDCase(user_id=user.id, email_id=em.id, company_name=em.sender, company_email=em.sender_email, dpo_email=dpo_email, status='pending_response')
    db.session.add(case)
    msg = RGPDMessage(direction='sent', sender_name=user.full_name, subject=subject, body=email_body)
    case.messages.append(msg)
    em.status = 'rgpd_sent' 
    db.session.commit()
    return jsonify({'success': True, 'case_id': case.id})

@app.route('/api/rgpd/confirm-reply', methods=['POST'])
@login_required
def confirm_rgpd_reply():
    user = User.query.get(session['user_id'])
    data = request.json
    case = RGPDCase.query.filter_by(id=data.get('case_id'), user_id=user.id).first()
    if not case: return jsonify({'error': 'Case not found'}), 404
    try:
        subject, body = send_confirmation_email(user, case.dpo_email, case.company_name)
        msg = RGPDMessage(case_id=case.id, direction='sent', sender_name=user.full_name, subject=subject, body=body, created_at=datetime.utcnow())
        db.session.add(msg)
        case.status = 'pending_response' 
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/rgpd/inbox', methods=['POST'])
@login_required
def add_manual_response():
    data = request.json
    user = User.query.get(session['user_id'])
    case = RGPDCase.query.filter_by(id=data.get('case_id'), user_id=user.id).first()
    if not case: return jsonify({'error': 'Case not found'}), 404
    
    body = data.get('body')
    # On demande un résumé, mais cette fois-ci l'IA sert aussi de juge
    # Si le user l'ajoute manuellement, on suppose que c'est pertinent, mais on vérifie quand même si l'IA peut résumer
    ai_verdict = ask_ollama_judge(case.company_name, body)
    if ai_verdict == "IGNORE": ai_verdict = None 

    msg = RGPDMessage(
        direction='received', 
        sender_name=case.company_name or "Company DPO", 
        subject=data.get('subject'), 
        body=body,
        summary=ai_verdict 
    )
    case.messages.append(msg)
    
    body_lower = body.lower()
    if any(k in body_lower for k in ['réponse à ce message', 'répondre pour confirmer', 'confirmation de votre part']):
        case.status = 'awaiting_confirmation'
    else:
        case.status = 'response_received' 
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/rgpd/cases')
@login_required
def get_cases():
    cases = RGPDCase.query.filter_by(user_id=session['user_id']).all()
    result = []
    now = datetime.now(timezone.utc)
    for c in cases:
        msgs = RGPDMessage.query.filter_by(case_id=c.id).order_by(RGPDMessage.created_at).all()
        sent_msg = next((m for m in msgs if m.direction == 'sent'), None)
        sent_date_str, days_ago = "N/A", -1
        if sent_msg:
            sent_date_str = sent_msg.created_at.strftime('%Y-%m-%d')
            sent_date_utc = sent_msg.created_at.replace(tzinfo=timezone.utc)
            days_ago = max(0, (now - sent_date_utc).days)
        result.append({
            'id': c.id, 
            'company_name': c.company_name, 
            'dpo_email': c.dpo_email, 
            'status': c.status, 
            'sent_date': sent_date_str, 
            'days_elapsed': days_ago, 
            'messages': [{'from': 'me' if m.direction=='sent' else 'them', 'senderName': m.sender_name, 'date': m.created_at.strftime('%d/%m/%Y'), 'subject': m.subject, 'body': m.body, 'summary': m.summary} for m in msgs]
        })
    return jsonify(result)

@app.route('/api/rgpd/scan-replies', methods=['POST'])
@login_required
def scan_rgpd_replies():
    user = User.query.get(session['user_id'])
    last_scanned_uid = user.last_rgpd_scan_uid or 0
    try:
        imap = get_imap_connection(user)
        imap.select('INBOX')
        date_since = (datetime.now() - timedelta(days=7)).strftime('%d-%b-%Y')
        status, messages = imap.search(None, f'(SINCE {date_since})')
        if status != 'OK': return jsonify({'error': 'IMAP search failed'}), 500
        email_ids = messages[0].split()
        scanned, matches, max_uid = 0, 0, last_scanned_uid
        for i in range(0, len(email_ids), 50):
            batch_str = b','.join(email_ids[i:i+50]).decode()
            status, data = imap.fetch(batch_str, '(UID RFC822)')
            if status != 'OK': continue
            for item in data:
                if isinstance(item, tuple):
                    uid_match = re.search(rb'UID (\d+)', item[0])
                    if uid_match:
                        current_uid = int(uid_match.group(1))
                        if current_uid <= last_scanned_uid: continue
                        max_uid = max(max_uid, current_uid)
                        try:
                            msg = email.message_from_bytes(item[1])
                            is_bulk = msg.get('List-Unsubscribe') is not None
                            from_h = msg.get('From', '')
                            sender = re.search(r'<(.+?)>', from_h).group(1) if re.search(r'<(.+?)>', from_h) else from_h.split()[0]
                            subj = str(make_header(decode_header(msg.get('Subject', ''))))
                            body = ""
                            if msg.is_multipart():
                                for part in msg.walk():
                                    if part.get_content_type() == 'text/plain': 
                                        body = part.get_payload(decode=True).decode('utf-8', errors='replace'); break
                            else: body = msg.get_payload(decode=True).decode('utf-8', errors='replace')
                            scanned += 1
                            if check_for_and_log_reply(sender, subj, body, user.id, is_bulk=is_bulk): matches += 1
                        except: pass
        if max_uid > last_scanned_uid: user.last_rgpd_scan_uid = max_uid; db.session.commit()
        imap.logout()
        return jsonify({'message': 'Scan completed', 'scanned': scanned, 'matches': matches})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/stats')
@login_required
def get_stats():
    uid = session['user_id']
    return jsonify({'total': Email.query.filter_by(user_id=uid).count(), 'deleted': Email.query.filter_by(user_id=uid, status='deleted').count(), 'ongoing': RGPDCase.query.filter_by(user_id=uid, status='pending_response').count(), 'issues': 0})

@app.route('/api/profile', methods=['PUT'])
@login_required
def update_profile():
    user = User.query.get(session['user_id'])
    data = request.json
    user.full_name, user.address, user.city = data.get('full_name'), data.get('address'), data.get('city')
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/reset', methods=['POST'])
@login_required
def reset():
    uid = session['user_id']
    Email.query.filter_by(user_id=uid).delete()
    RGPDCase.query.filter_by(user_id=uid).delete()
    db.session.commit()
    return jsonify({'success': True})

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    app.run(debug=True, port=5000)