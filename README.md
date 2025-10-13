# python-waf
Capstone project developed in python using TTD. Web application firewall to block attacks

## Features

- Rule-based inspection engine (SQLi, extensible for XSS, etc.)
- Concurrent request inspection for high performance
- Logging of blocked requests to a database
- RESTful reverse proxy using Flask
- Configurable via `.env` and `rules.json`
- Unit tests for core components

## Project Structure

- `main.py`: Entry point, sets up WAF and proxy server
- `engine/`: WAF engine, database, and logging logic
- `rules/`: Rule definitions, loader, and factory
- `proxy/`: Flask-based reverse proxy server
- `tests/`: Unit tests for all modules

## Getting Started

### Prerequisites

- Python 3.10+
- `pip install -r requirements.txt`
- SQLite (default, or configure another DB)

### Configuration

Edit `.env` to set:
- `LISTEN_PORT`: Proxy listen port
- `BACKEND_URL`: URL of your backend app
- `RULES`: Path to your rules JSON file
- `DB_STATS`: Path to your SQLite DB file
- `SECRET_DASHBOARD`: Token for dashboard access

### Running

```sh
python main.py
```
### Testing
Run all unit tests:

```sh
pytest
```

### API Endpoints

`/healthcheck`: Health check (requires bearer token)

`/eventsByTime`: Query blocked events (requires bearer token)

`/<path:path>`: Main proxy endpoint

### Extending

Add new rule types in `rules/rule_factory.py`

Implement new inspection logic in `rules/inspection_rules.py`