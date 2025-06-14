from app import db

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vendor = db.Column(db.String(128), nullable=False)
    product = db.Column(db.String(128), nullable=False)
    version = db.Column(db.String(64))
    cpe = db.Column(db.String(256))
    vulnerabilities = db.relationship('Vulnerability', backref='device', lazy=True)
    final_criticality = db.Column(db.Float)
    vulns_loaded = db.Column(db.Boolean, default=False, nullable=False)

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    cve = db.Column(db.String(32), nullable=False)
    cvss_score = db.Column(db.Float)
    description = db.Column(db.Text)
    severity = db.Column(db.String(16))
    final_criticality = db.Column(db.Float)
