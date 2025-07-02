from app import db

class AssignmentCode(db.Model):
    id                     = db.Column(db.Integer, primary_key=True)
    code                   = db.Column(db.String(32), unique=True, nullable=False)  # Например, VKS, P, TP и т.д.
    name                   = db.Column(db.String(128), nullable=False, default='-') # Расшифровка
    criticality_multiplier = db.Column(db.Float, nullable=False, default=1.0)

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    equip_model_name     = db.Column(db.String(64), nullable=False)    # Модель оборудования
    prod_name            = db.Column(db.String(32), nullable=False)    # Производитель
    part_num             = db.Column(db.String(32), nullable=False)    # Part Number
    cont_point_id        = db.Column(db.String(64), nullable=False)    # Идентификатор пункта связи
    cont_point_name      = db.Column(db.String(64), nullable=False)    # Пункт связи
    eos                  = db.Column(db.String(32), nullable=True)     # Окончание срока продажи
    eol                  = db.Column(db.String(32), nullable=True)     # Окончание срока поддержки
    start_date           = db.Column(db.String(16), nullable=True)     # Дата ввода в эксплуатацию (или db.Date)
    rack_id              = db.Column(db.String(32), nullable=True)     # Идентификатор стойки
    target               = db.Column(db.String(64), nullable=True)     # Назначение оборудования
    target_code          = db.Column(db.String(16), nullable=True)     # Код назначения IP оборудования
    dns_name             = db.Column(db.String(64), nullable=True)     # DNS имя устройства
    sdns_name            = db.Column(db.String(64), nullable=True)     # DNS имя устройства (системное)
    soft_name            = db.Column(db.String(64), nullable=True)     # SoftWare
    soft_ver             = db.Column(db.String(32), nullable=True)     # Версия SoftWare
    software_id          = db.Column(db.Integer, db.ForeignKey('software.id'), nullable=True)
    software             = db.relationship("Software", backref="devices", lazy="joined")

class Software(db.Model):
    id                   = db.Column(db.Integer, primary_key=True)
    vendor               = db.Column(db.String(128), nullable=False)
    product              = db.Column(db.String(128), nullable=False)
    version              = db.Column(db.String(64))
    cpe                  = db.Column(db.String(256))
    confident_score      = db.Column(db.Float)
    integrity_score      = db.Column(db.Float)
    accessibility_score  = db.Column(db.Float)
    epss_score           = db.Column(db.Float)
    bugs_count           = db.Column(db.Integer)
    status               = db.Column(db.Boolean, default=False, nullable=False)
    vulnerabilities      = db.relationship('Vulnerability', backref='software', lazy=True)

class Vulnerability(db.Model):
    id                   = db.Column(db.Integer, primary_key=True)
    software_id          = db.Column(db.Integer, db.ForeignKey('software.id'), nullable=False)
    cve                  = db.Column(db.String(32), nullable=False)
    cvss_score           = db.Column(db.Float)
    description          = db.Column(db.Text)
    confident_score      = db.Column(db.Float)
    integrity_score      = db.Column(db.Float)
    accessibility_score  = db.Column(db.Float)
    epss_score           = db.Column(db.Float)
    severity             = db.Column(db.String(16))