# Quote Tool

Quote Tool is a web app for quick freight quotes. It handles Hotshot and Air jobs for Freight Services staff and trusted partners.
Enter ZIP codes, weight, and extras to see a price, then escalate the booking through the internal email workflows or the Freight
Services portal.

## Features

- Sign up, log in, and reset passwords
- Global request throttling protects login and password reset endpoints
- Freight Services sign-ups using `@freightservices.net` emails are created as
  pending employees so administrators can approve their access
- Admin area to approve users, edit rates, and review the quote history
- Staff-only booking helpers let approved Freight Services employees email booking or volume-pricing requests directly from a quote
- Super admins can manage Office 365 SMTP credentials from the dashboard
- Price engine uses Google Maps and rate tables
- Quotes saved in a database
- Warns when shipment weight or cost exceeds tool limits

## Feature status

| Feature | Status | Notes |
| --- | --- | --- |
| Hotshot and Air quoting | ✅ Stable | Accepts form and JSON submissions and persists quotes. |
| Booking email workflow (`Email to Request Booking`) | 🔒 Staff-only | Restricted to approved employees or super admins whose email matches `MAIL_PRIVILEGED_DOMAIN`. Customers see the button disabled. |
| Volume-pricing email workflow | 🔒 Staff-only | Surfaces when a quote exceeds thresholds; limited to users with mail privileges. |
| Quote summary emailer | 🔒 Staff-only | Enabled for Freight Services staff only. Requires SMTP credentials and mail privileges. |
| Redis caching | ⚙️ Optional | Enabled by default when using `startup_detached.sh`. Remove `cache` from `COMPOSE_PROFILES` if you want to skip Redis or point to an external instance. |
| Duplicati backups | ⚙️ Optional | Disabled by default. Start with `docker compose --profile backup up -d duplicati`. |


## Documentation hub

- [Documentation Hub](docs/README.md) – Cross-reference of every guide, inline
  comment, and help topic.
- [Architecture](ARCHITECTURE.md) – Component breakdown and reimplementation
  notes for porting the app to another stack.
- [Deployment](DEPLOYMENT.md) – Production roll-out, TLS, and maintenance
  checklists.
- [Backup operations](docs/backups.md) – Duplicati automation, retention, and
  monitoring guidance.
- In-app Help Center (`/help`) – Task-oriented user guides rendered from
  `templates/help/`.

## Quick Start

1. Install Python 3.8 or newer.
2. Copy `.env.example` to `.env` and fill in keys, database info, and the
   Postgres container variables.
   - Generate a long random value for `SECRET_KEY` (for example,
     `python -c 'import secrets; print(secrets.token_urlsafe(32))'`) so sessions
     persist across restarts. Without it the app falls back to an ephemeral key
     at startup.
   - Set `PUID`/`PGID` to the host user that owns `./data/postgres` and choose a
     strong `POSTGRES_PASSWORD`. The Compose file defaults to the `postgres`
     service hostname via `POSTGRES_HOST`, so the application and helper scripts
     share the same containerised database. Override `POSTGRES_HOST` when you
     run scripts like `python init_db.py` or `python migrate_quotes.py` outside
     Docker so they can reach your Postgres server.
    - Examples for overriding the hostname outside Docker:
      - macOS/Linux: `POSTGRES_HOST=localhost python init_db.py`
      - PowerShell: `$env:POSTGRES_HOST="localhost"; python init_db.py`
      - Command Prompt: `set POSTGRES_HOST=localhost && python init_db.py`
        (the variable only persists for that window)
3. Create the data directories and grant ownership to the configured user:
   `mkdir -p data/postgres data/redis && sudo chown "${PUID:-$(id -u)}:${PGID:-$(id -g)}" data/postgres data/redis`.
   The local Compose override now starts Postgres and Redis as `root` so they can
   repair ownership automatically on first boot, but pre-creating the
   directories avoids permission prompts on hosts with stricter defaults.
4. Install packages: `pip install -r requirements.txt`.
5. Start the bundled database: `docker compose up -d postgres`.
   - Compose automatically loads `.env`, so overrides to `DATABASE_URL` or the
     Postgres credentials propagate to the container.
6. Create tables: `alembic upgrade head`.
7. Import ZIP and air rate data before starting the app:
   `python scripts/import_air_rates.py path/to/rates_dir`.
8. Seed rate tables and (optionally) create an admin user:
   `python init_db.py` (uses the directory above by default).
9. Run the app: `python flask_app.py`.
   - For production use `gunicorn flask_app:app`.
   - The server reads ``FLASK_DEBUG`` (defaults to ``false``) to control
     debugging. Set ``FLASK_DEBUG=true`` while developing locally and leave it
     unset or ``false`` in production so the hardened configuration stays in
     effect.

### Windows executable

Administrators who prefer a self-contained Windows build can package the app
with PyInstaller. The Dockerfile at `Dockerfile.windows` runs the following
command to produce `windows_setup.exe` and embed the rate CSV fixtures alongside
the launcher:

```powershell
pyinstaller --noconfirm --onefile --name windows_setup `
  --add-data ".env.example;." `
  --add-data "Hotshot_Rates.csv;rates" `
  --add-data "beyond_price.csv;rates" `
  --add-data "accessorial_cost.csv;rates" `
  --add-data "Zipcode_Zones.csv;rates" `
  --add-data "cost_zone_table.csv;rates" `
  --add-data "air_cost_zone.csv;rates" `
  windows_setup.py
```

Launching `windows_setup.exe` (or the copied `run_app.exe`) walks through a
guided configuration that collects:

- `ADMIN_EMAIL` for the initial administrator account.
- `ADMIN_PASSWORD`, entered securely with `getpass` so it is not echoed back.
- `GOOGLE_MAPS_API_KEY` used by address validation and quoting forms.
- `SECRET_KEY`, with the option to press Enter and let the launcher generate a
  new random key.

The answers are written to a `.env` file that lives beside the executable. Rerun
the prompts at any time with `windows_setup.exe --reconfigure`; leaving the
`SECRET_KEY` blank during reconfiguration rotates it to a freshly generated
value.

On first launch the executable seeds the database by invoking
[`init_db.initialize_database`](init_db.py#L82). The bundled rate data includes
`Hotshot_Rates.csv`, `beyond_price.csv`, `accessorial_cost.csv`,
`Zipcode_Zones.csv`, `cost_zone_table.csv`, and `air_cost_zone.csv`. Replace the
CSV files in the `rates` directory next to the executable (or its
`resources\rates` extraction folder when frozen) to load custom pricing the next
time you run the launcher.

Security guidance:

- Treat the generated `.env` as sensitive because it stores administrator
  credentials and API keys. Restrict NTFS permissions to the operations team and
  keep a copy in an enterprise secret vault rather than on shared drives.
- Rotate the Flask `SECRET_KEY` if the `.env` might have leaked. Run
  `windows_setup.exe --reconfigure` and press Enter when prompted for the key to
  create a new one.
- Update credentials recorded in `.env` (for example, `ADMIN_PASSWORD`) through
  your password manager, then rerun the launcher to synchronize the file.
- Review the docstring of
  [`init_db.initialize_database`](init_db.py#L82) for additional background on
  how seeding works and what tables are touched so you can plan migrations and
  audits accordingly.

### Testing

Run the automated test suite with [pytest](https://docs.pytest.org/) after you
install the dependencies and configure your environment variables. From the
project root, execute:

```bash
pytest
```

This command discovers and runs all tests in the `tests/` directory. Use it to
verify changes before deploying or opening a pull request.

### Rate limiting

The application uses [Flask-Limiter](https://flask-limiter.readthedocs.io/) to
throttle abusive traffic. By default each client IP may perform up to 200
requests per day and 50 per hour, while the `/login` and `/reset` endpoints are
restricted to five POST attempts per minute for a given IP and email
combination. Override the defaults with environment variables as needed:

| Variable | Purpose | Default |
| --- | --- | --- |
| `RATELIMIT_DEFAULT` | Global limits applied to all routes | `200 per day;50 per hour` |
| `RATELIMIT_STORAGE_URI` | Backend storage for counters | `memory://` |
| `AUTH_LOGIN_RATE_LIMIT` | Per-user/IP throttle for `/login` | `5 per minute` |
| `AUTH_RESET_RATE_LIMIT` | Per-user/IP throttle for `/reset` | `5 per minute` |
| `AUTH_RESET_TOKEN_RATE_LIMIT` | Frequency cap for issuing password reset tokens | `1 per 15 minutes` |

Set `RATELIMIT_HEADERS_ENABLED=true` to expose standard rate-limit headers if
your proxy or monitoring stack expects them.

### Rate CSV formats

The `Zipcode_Zones.csv` file must include a header row with these columns in
order:

1. `Zipcode`
2. `Dest Zone`
3. `BEYOND`

Headers must match exactly; missing or transposed columns will cause the import
script to raise an error.

### Docker

To start the full stack with Docker Compose, run the following command from the
repository root:

```bash
docker compose up -d postgres
docker compose up -d quote_tool swag
docker compose --profile backup up -d duplicati
```

Compose builds the images (if needed) and launches the services defined in
`docker-compose.yml`. Bring up the `postgres` container first so the health
check passes before the application starts. The stack automatically loads
environment variables from a `.env` file that sits alongside the Compose file.
Define `DUPLICATI_WEBSERVICE_PASSWORD` with a random value before starting the
backup profile so the Duplicati UI is protected. You can also hard-code values
under the `environment` section of `docker-compose.yml` or export them in your
shell before running the command to override defaults. Create
`./data/postgres` ahead of time and ensure it is owned by the UID/GID specified
by `PUID`/`PGID`; for example:

```bash
mkdir -p data/postgres
sudo chown 1000:1000 data/postgres  # Replace 1000 with your deployment user IDs.
```

If you want to verify Postgres is ready before starting the app, tail the
database logs or run a readiness probe that uses the configured credentials:

```bash
docker compose logs -f postgres --tail 200
docker compose exec -T postgres \
  pg_isready -U "${POSTGRES_USER:-quote_tool}" -d "${POSTGRES_DB:-quote_tool}"
```

The default Compose configuration creates the `quote_tool` database and user.
Using `pg_isready` without matching the `POSTGRES_USER`/`POSTGRES_DB` values
will fail with a "role does not exist" error.

After the services start, apply migrations with Alembic:

```bash
docker compose run --rm quote_tool alembic upgrade head
```

Visit `https://127.0.0.1:8200` (or tunnel the port over SSH) to configure
Duplicati after the containers settle. See [`DEPLOYMENT.md`](DEPLOYMENT.md) for
the full runbook.

#### Enable Redis caching

The Compose stack ships with an optional Redis service that accelerates page
rendering and centralises rate-limit counters. `startup_detached.sh` injects
the `cache` profile automatically so Redis starts alongside PostgreSQL. If you
prefer to manage profiles yourself, set `COMPOSE_PROFILES` explicitly before
running Compose commands (omit `cache` to disable Redis).

1. Set `COMPOSE_PROFILES=cache` in `.env` (or export it) when running `docker
   compose` manually so the Redis service is included. If you want to skip
   Redis even when using `startup_detached.sh`, set `COMPOSE_PROFILES` without
   `cache`.
2. Optionally override the cache settings:
   - Leave `CACHE_TYPE`, `CACHE_REDIS_URL`, and `RATELIMIT_STORAGE_URI` unset to
     accept the defaults generated by `config.Config` when the `cache` profile
     is active (`redis://redis:6379/0` for the application cache and
     `redis://redis:6379/1` for Flask-Limiter).
   - Provide custom values if you prefer an external Redis instance.
3. Start the service with `docker compose --profile cache up -d redis` (or
   `docker compose up -d redis` when `COMPOSE_PROFILES` already includes
   `cache`). Bring up the full stack with the same profile.
4. Verify connectivity by running `docker compose exec redis redis-cli PING`. A
   successful setup prints `PONG`.

Create `./data/redis` before the first run (step 3 in the quick start) and
match its ownership to `PUID`/`PGID` so LinuxServer's init scripts can persist
data across container restarts.

```bash
# Build the image
docker build -t quote_tool .

# Start the container and expose port 5000 (debug disabled)
docker run -d --name quote_tool -p 5000:5000 quote_tool

# Start a separate container with the debugger enabled for local work
docker run -d --name quote_tool_dev -e FLASK_DEBUG=1 -p 5000:5000 quote_tool

# Seed an admin user inside the container
docker exec -e ADMIN_EMAIL=admin@example.com -e ADMIN_PASSWORD=change_me \
  quote_tool python init_db.py
```

The final command seeds an admin user; replace the example email and password
with your own credentials. It also loads all rate tables from the bundled
CSV files in the repository root. Set `RATE_DATA_DIR` to point to a custom
directory if needed. If `ADMIN_EMAIL` and `ADMIN_PASSWORD` are defined in a
`.env` file, `init_db.py` loads them automatically and the `-e` flags can be
omitted.

### Inspect existing users

Use the built-in CLI to inspect who can log in. Because it reuses the
application configuration, you do not have to specify database flags and it
avoids the common "role \"root\" does not exist" error that appears when `psql`
falls back to the container user.

```bash
# From the host using your virtualenv
python scripts/list_users.py

# From inside Docker
docker compose exec quote_tool python scripts/list_users.py
```

Add `--include-inactive` to see deactivated accounts and `--admin-only` to
limit output to administrators.

### Bulk seeding user accounts

Use `scripts/seed_users.py` when you need to load several accounts at once.
The repository root contains `users_seed_template.csv` with two example rows.
Copy the file, replace the placeholder values, and run the script:

```bash
python scripts/seed_users.py --file path/to/your_users.csv
```

Passwords must either satisfy the complexity rules enforced by
`services.auth_utils.is_valid_password` or be pre-hashed values generated by
`werkzeug.security.generate_password_hash`. Set `--update-existing` to modify
accounts that already exist and `--dry-run` to validate the CSV without writing
changes. The script automatically upgrades records flagged with
`is_admin=TRUE` to the `super_admin` role and ensures employee approvals align
with the selected role.

> ⚠️ Leave ``FLASK_DEBUG`` unset (the default) in production deployments. Turning
> it on exposes the Werkzeug debugger and prevents Gunicorn from running with
> the hardened configuration.

### Running behind a reverse proxy

Many production deployments put the container behind NGINX, Traefik, or a
similar reverse proxy so the application can respond to HTTPS requests on a
friendly domain (for example `quotes.fsi.internal`; replace with your own DNS
name). The general flow is:

1. Provide the required configuration in a `.env` file so the container has
   access to the external services it needs.
2. Start the `quote_tool` service with Docker Compose and make it available on
   an internal Docker network.
3. Point the reverse proxy at the internal container and map your public
   domain name to the host running Docker.

#### Configure environment variables

Create a `.env` file next to `docker-compose.yml` and set the keys required for
production:

```dotenv
FLASK_DEBUG=false
GOOGLE_MAPS_API_KEY=your_google_key
DATABASE_URL=postgresql+psycopg2://user:password@db/quote_tool
# Generate with: python -c 'import secrets; print(secrets.token_urlsafe(32))'
SECRET_KEY=super_secret_value
```

Docker Compose automatically loads values from `.env`. You can also reference
the same variables inside the Compose definition to pass them directly to the
container:

When targeting an external PostgreSQL instance (for example, Google Cloud SQL)
leave ``DATABASE_URL`` unset and provide the individual ``POSTGRES_*`` values
instead. The configuration helper automatically percent-encodes credentials so
passwords containing characters such as ``?`` or ``@`` do not break the
connection string. Optional ``POSTGRES_OPTIONS`` accepts a query-string-style
value that is appended to the generated URI, enabling flags like
``sslmode=require`` without manually editing the DSN:

```dotenv
POSTGRES_USER=quote_tool
POSTGRES_PASSWORD=ChangeMeSuperSecret!
POSTGRES_DB=quote_tool
POSTGRES_HOST=34.132.95.126
POSTGRES_PORT=5432
POSTGRES_OPTIONS=sslmode=require&application_name=quote-tool
```

> Replace the example password with your real secret. Because
> ``POSTGRES_PASSWORD`` is encoded automatically, special characters do not need
> manual escaping.

##### Configure Google BigQuery credentials

The configuration module can now build a BigQuery connection string when the
component environment variables are present. Add the following keys to your
`.env` file (or export them in your shell) and omit ``DATABASE_URL`` so the
application selects BigQuery automatically:

```dotenv
BIGQUERY_PROJECT=quote-tool-472316
BIGQUERY_DATASET=quote_tool
# Optional: pick the region closest to your dataset
BIGQUERY_LOCATION=us-central1

# Path to the downloaded service account JSON key.
# When running inside WSL, convert paths such as
# "\\\wsl.localhost\Ubuntu\home\dave\quote-tool-472316-e921acc21738.json"
# to their Linux equivalent:
GOOGLE_APPLICATION_CREDENTIALS=/home/dave/quote-tool-472316-e921acc21738.json
```

The Flask app and auxiliary scripts honour ``GOOGLE_APPLICATION_CREDENTIALS``
via the Google Cloud client libraries. Ensure the referenced key has BigQuery
read/write permissions for the dataset. On startup the application now calls
``google.cloud.bigquery`` to create the configured dataset (when it does not
exist) and provisions any missing tables, ensuring all quoting data is written
to BigQuery without manual setup.

```yaml
services:
  quote_tool:
    build: .
    env_file: .env  # Loads GOOGLE_MAPS_API_KEY, DATABASE_URL, SECRET_KEY
    environment:
      SECRET_KEY: ${SECRET_KEY}  # Explicit example; others are inherited
    ports:
      - "5000:5000"  # Publish the Flask app on the Docker host
    expose:
      - "5000"  # Keep the port reachable for other containers such as SWAG
    networks:
      - web

networks:
  web:
    driver: bridge
```

> Tip: If you already keep secrets in another system, you can remove
> `env_file` and define the variables inline under `environment` instead.

With the port mapping in place you can now browse to
`http://<docker-host-ip>:5000/` from other machines on your LAN. When running
purely behind a reverse proxy you can drop the `ports` section so the service
stays isolated on the internal Docker network.

#### Reverse proxy with SWAG

The Compose stack ships with LinuxServer's SWAG container, which terminates TLS
and proxies inbound traffic to the internal `quote_tool` service. Populate
`URL`, `SUBDOMAINS`, `VALIDATION`, and `EMAIL` in `.env` before launching SWAG
so Certbot can request certificates. For DNS validation add `DNSPLUGIN` and the
plugin-specific credentials described in the SWAG documentation; HTTP
validation only requires inbound access on ports 80/443.

SWAG persists all configuration under `deploy/swag/`. The bundled proxy
template at `deploy/swag/proxy-confs/quote_tool.subdomain.conf` forwards
requests to `quote_tool:5000` on the Docker network and includes optional
Authelia directives you can enable by uncommenting them once an Authelia
container is present. Adjust the file to layer on additional headers or path
rules, then restart the proxy with `docker compose restart swag`.

Certificate material lives under `deploy/swag/etc/letsencrypt/` and Nginx logs
are written to `deploy/swag/log/nginx/`. Follow issuance progress and diagnose
problems with `docker compose logs -f swag`; the output shows challenge status
as well as configuration errors.

## Advanced

- Run only the JSON API: `python standalone_flask_app.py`.
- Import rate data any time with the same script as above.
- Admin pages let you manage rate tables and fuel surcharges.

## Troubleshooting

If you see `no such table` errors, the database is missing required tables.
Delete `instance/app.db`, set `ADMIN_EMAIL` and `ADMIN_PASSWORD` in `.env` (the script
loads this file automatically), then run `python init_db.py` to recreate the
full schema.

If quotes warn that "Air rate table(s) missing or empty", ensure the CSV
directory is present or specify its path via `RATE_DATA_DIR` before initializing
the database.

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for an overview of the application's components and guidance on rebuilding the app in another stack.
