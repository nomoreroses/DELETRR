<p align="center">
  <img src="./src/assets/logo.webp" alt="DELETRR" width="200">
</p>

# DELETRR

AI-powered GDPR compliance tool. Scans your inbox to detect marketing emails, auto-generates data deletion requests (Right to be Forgotten), and tracks company responses.

## Features

- **Inbox Scanning**: Connects to your email via IMAP and analyzes emails using local AI
- **Smart Classification**: Categorizes emails as KEEP, DELETE, or GDPR_UNSUB (marketing/newsletters)
- **Automated GDPR Requests**: Generates and sends Right to be Forgotten requests to companies
- **DPO Discovery**: Automatically searches for Data Protection Officer emails using web scraping + AI
- **Response Tracking**: Monitors replies from companies and summarizes them with AI
- **Whitelist Management**: Protect senders you trust from being flagged
- **Multi-Provider Support**: Works with Gmail, Outlook, and Yahoo

## Tech Stack

**Backend**
- Flask (Python)
- SQLite with Flask-SQLAlchemy
- IMAP/SMTP for email operations
- Ollama (llama3:8b) for local AI inference

**Frontend**
- React 18
- Tailwind CSS
- Lucide React icons
- Vite

## Architecture Choices

### Local AI with Ollama
I chose Ollama over cloud APIs (OpenAI, Claude) for privacy reasons. Since the app handles sensitive email data, keeping AI inference local ensures no data leaves the user's machine. The trade-off is requiring users to run Ollama locally.

### IMAP over Gmail API
Using raw IMAP instead of Gmail's API makes the app provider-agnostic. Same codebase works for Gmail, Outlook, Yahoo without managing multiple OAuth flows. Users generate app-specific passwords instead.

### SQLite
Simple, file-based, no server needed. Fits the local-first philosophy of the project.

### Flask Sessions
Stateful sessions store user credentials server-side. Not scalable for production but simple for a personal tool.

## Installation

### Prerequisites
- Python 3.10+
- Node.js 18+
- Ollama with llama3:8b model

### Backend Setup

```bash
cd backend
pip install -r requirements.txt
python app.py
```

### Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

### Ollama Setup

```bash
ollama pull llama3:8b
ollama serve
```

## Configuration

### Email App Passwords

**Gmail**: Create an app password at https://myaccount.google.com/apppasswords (requires 2FA enabled)

**Outlook**: Create an app password in Microsoft account security settings

**Yahoo**: Create an app password at https://login.yahoo.com/account/security

## Usage

1. Start Ollama, backend, and frontend
2. Login with your email and app password
3. Click "Scan" to analyze your inbox
4. Review detected emails by category
5. Click "Manage" on GDPR items to send deletion requests
6. Track responses in the Tracking tab

## Project Structure

```
├── app.py              # Flask backend (API routes, IMAP logic, AI calls)
├── requirements.txt    # Python dependencies
├── src/
│   ├── App.jsx         # Main React component
│   ├── App.css         # Component styles
│   ├── index.css       # Global styles (Tailwind)
│   ├── Loader.css      # Loading toast styles
│   └── main.jsx        # React entry point
└── public/
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/login | Authenticate with email/app password |
| POST | /api/scan | Scan inbox for emails |
| GET | /api/emails | Get scanned emails |
| POST | /api/delete | Delete email from inbox |
| POST | /api/rgpd/send | Send GDPR deletion request |
| GET | /api/rgpd/cases | Get all GDPR cases |
| POST | /api/rgpd/scan-replies | Scan for company responses |
| POST | /api/whitelist | Add sender to whitelist |

## Security Notes

- App passwords are stored in SQLite (not hashed). This is a local tool, not meant for multi-user deployment.
- Set `SECRET_KEY` environment variable in production
- CORS is configured for localhost only

## License

MIT
