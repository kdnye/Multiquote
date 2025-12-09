# Quote Tool

Quote Tool is a Flask-based web app for generating expedited truck (Hotshot) and Air freight quotes. Users can register, sign in, and create quotes via HTML forms or JSON APIs. Administrators manage rate tables and user privileges.

## Features

- User registration, login, and token-based password reset
- Hotshot and Air pricing with dimensional weight support and accessorial add-ons
- Google Maps distance lookup with graceful fallbacks when no API key is provided
- Admin dashboards to manage users and edit rate tables
- Quote history and JSON API for programmatic quoting
- Rate limiting on sensitive endpoints

## Getting Started

1. **Install dependencies**

   ```bash
   python -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Configure environment**

   Create a `.env` file with at least:

   ```bash
   SECRET_KEY=<random secret>
   DATABASE_URL=sqlite:///quote_tool.db
   GOOGLE_MAPS_API_KEY=<optional>
   SMTP_HOST=<optional>
   SMTP_USERNAME=<optional>
   SMTP_PASSWORD=<optional>
   MAIL_SENDER=no-reply@example.com
   ```

3. **Run the app locally**

   ```bash
   python -m quote_tool.app
   ```

   The app will create tables automatically and listen on `http://127.0.0.1:5000/`.

4. **Seed rate data**

   Use the admin dashboard to add Hotshot, Beyond, Air Cost, ZIP zone, and Cost zone entries. CSV templates in the repository (`*_template.csv`) outline the expected headers if you prefer bulk import scripts.

## Production notes

- Point `DATABASE_URL` to PostgreSQL for production deployments.
- Configure SMTP settings and enable mail privileges for staff users before using booking or summary email workflows.
- Enable rate-limit headers by setting `RATELIMIT_HEADERS_ENABLED=true` if you need standard quota metadata at the edge.

## Windows one-file build

Create a tiny entry point `run_quote_tool.py`:

```python
from quote_tool import create_app
app = create_app()

if __name__ == "__main__":
    app.run()
```

Package with PyInstaller:

```bash
pyinstaller --onefile -n quote_tool run_quote_tool.py
```

## Testing

Run the automated tests with pytest:

```bash
pytest
```
