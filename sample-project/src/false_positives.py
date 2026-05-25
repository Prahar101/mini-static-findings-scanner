"""Patterns that LOOK risky but are not -- the validators should suppress these.

Each line below would trip a naive regex scanner. Our validator layer drops
them, which is what keeps the false-positive rate low.
"""

import os

# Sourced from the environment, not hardcoded -> suppressed (env_reference).
API_KEY = os.environ["API_KEY"]
db_password = os.getenv("DB_PASSWORD")

# Obvious placeholders -> suppressed (placeholder).
example_token = "your_api_key_here"
sample_secret = "changeme"

# Local / reserved-example URLs are not a transport risk -> suppressed (benign_url).
LOCAL_URL = "http://localhost:8080/health"
DOCS_URL = "http://example.com/docs"

# A real-looking secret that WOULD fire, explicitly acknowledged -> suppressed (nosec).
password = "Sup3rS3cr3tValue123"  # nosec - test fixture, not a real credential

# Dangerous calls mentioned only in a comment -> suppressed (code_context).
# eval(user_input) and os.system(cmd) here are documentation, not real calls.

# Dangerous calls inside a docstring/string -> suppressed (code_context).
USAGE = """
Risky calls, shown for documentation only:
    eval(expr)
    exec(code)
    subprocess.run(cmd, shell=True)
"""
