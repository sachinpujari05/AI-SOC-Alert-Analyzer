$env:SOC_API_TOKEN = Read-Host "Enter your existing API token"
$env:SESSION_SECRET = python -c "import secrets; print(secrets.token_hex(32))"
python -m fastapi dev main.py
