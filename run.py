"""Start the PhishGuard engine on 127.0.0.1 only.

    python run.py            start the server

Environment overrides (used by tests): PHISHGUARD_INSTANCE, PHISHGUARD_PORT.
"""
import os

from waitress import serve

from phishguard import create_app


def main():
    overrides = {"START_WORKER": os.environ.get("PHISHGUARD_NO_WORKER") != "1"}
    if os.environ.get("PHISHGUARD_INSTANCE"):
        overrides["INSTANCE_DIR"] = os.environ["PHISHGUARD_INSTANCE"]
    if os.environ.get("PHISHGUARD_PORT"):
        overrides["PORT"] = int(os.environ["PHISHGUARD_PORT"])
    app = create_app(overrides)
    host, port = app.config["HOST"], app.config["PORT"]
    print(f"PhishGuard running at http://{host}:{port}", flush=True)
    serve(app, host=host, port=port, threads=8, ident="PhishGuard")


if __name__ == "__main__":
    main()
