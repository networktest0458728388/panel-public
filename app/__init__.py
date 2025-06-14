from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
migrate = Migrate()
csrf = CSRFProtect()

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')

    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)

    with app.app_context():
        _ensure_schema()

    with app.app_context():
        from . import views, models
    return app


def _ensure_schema():
    """Add missing columns used by the application if needed."""
    insp = db.inspect(db.engine)
    columns = {col["name"] for col in insp.get_columns("device")}
    if "vulns_loaded" not in columns:
        db.session.execute(
            db.text(
                "ALTER TABLE device ADD COLUMN vulns_loaded BOOLEAN NOT NULL DEFAULT 0"
            )
        )
        db.session.commit()
