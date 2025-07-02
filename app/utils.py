import re
import requests
from .models import Device, Vulnerability, Software
from . import db

NVD_API_KEY = "16ee4afe-e8f4-441f-a4fc-d085d74747c3"

def guess_vendor(row):
    v = str(row).lower().strip()
    known_vendors = ["cisco", "eltex", "huawei", "juniper", "moxa", "fujitsu", "mikrotik", "ubiquiti", "hp", "arista", "d-link", "tp-link", "eci-telecom"]
    for vendor in known_vendors:
        if vendor in v:
            return vendor
    return re.sub(r'\s+', '_', v)

def guess_product(row):
    vendor = guess_vendor(row['Производитель'])
    version = str(row.get('Версия SoftWare', row.get('Версия', ''))).lower()
    model = str(row['Модель']).lower().strip()

    product_mappings = {
        'cisco': [
            (r'(ios-xe|xe)', 'ios_xe'),
            (r'(ios-xr|xr)', 'ios_xr'),
            (r'(nx-os|nxos)', 'nx-os'),
            (r'asa', 'asa_software'),
            (r'.*', 'ios')
        ],
        'juniper': [(r'.*', 'junos')],
        'huawei': [(r'.*', 'vrp')],
        'mikrotik': [(r'.*', 'routeros')],
        'ubiquiti': [(r'.*', 'edgeos')],
        'hp': [(r'(procurve|arubaos)', 'arubaos')],
        'arista': [(r'.*', 'eos')],
        'd-link': [(r'.*', 'firmware')],
        'tp-link': [(r'.*', 'firmware')],
        'eci-telecom': [(r'.*', 'as9206')]
    }

    for pattern, prod in product_mappings.get(vendor, []):
        if re.search(pattern, version):
            return prod

    return product_mappings.get(vendor, [(r'.*', re.sub(r'\s+', '_', model))])[0][1]

def parse_version(row):
    v = str(row.get('Версия SoftWare', row.get('Версия', ''))).strip()

    if v in ('0', '-', '', 'nan', 'none', 'unknown'):
        return 'unknown'

    patterns = [
        r'[Vv]ersion[:\s]*([\w\.\-\(\)\+]+)',
        r'[Vv]er\.[:\s]*([\w\.\-\(\)\+]+)',
        r'v([\w\.\-\(\)\+]+)',
        r'([\d]+(?:\.[\w\-\(\)\+]+)+)',
        r'(\w+[\w\.\-\(\)\+]*)'
    ]

    version_cleaned = None
    for pattern in patterns:
        match = re.search(pattern, v)
        if match:
            version_cleaned = match.group(1).strip()
            break

    if not version_cleaned:
        return 'unknown'

    version_parts = re.split(r'(\.|\(|\)|-)', version_cleaned)
    normalized_parts = []
    for part in version_parts:
        if part.isdigit():
            normalized_parts.append(str(int(part)))
        else:
            normalized_parts.append(part)

    return ''.join(normalized_parts).lower()

def get_severity(cvss):
    if cvss is None:
        return "Unknown"
    if cvss >= 9:
        return "Critical"
    elif cvss >= 7:
        return "High"
    elif cvss >= 4:
        return "Medium"
    elif cvss > 0:
        return "Low"
    return "None"

def escape_cpe_special_chars(version):
    return version.replace('(', '\\(').replace(')', '\\)') if version else ""

def build_cpe_variants(vendor, product, version):
    vendor = vendor.strip().lower()
    product = product.strip().lower()
    version_raw = str(version).strip().lower()
    version_escaped = escape_cpe_special_chars(version_raw)
    variants = set()

    product_variants = {product}
    vendor_products = {
        "cisco": {"ios", "ios_xe", "ios_xr", "asa_software", "asa", "nx-os"},
        "juniper": {"junos"},
        "mikrotik": {"routeros"},
        "ubiquiti": {"edgeos"},
        "hp": {"arubaos"},
        "arista": {"eos"},
        "d-link": {"firmware"},
        "tp-link": {"firmware"}
    }

    product_variants |= vendor_products.get(vendor, set())

    for prod in product_variants:
        for prefix in ['o', 'h', 'a']:
            variants.add(f"cpe:2.3:{prefix}:{vendor}:{prod}:{version_raw}:*:*:*:*:*:*:*")
            variants.add(f"cpe:2.3:{prefix}:{vendor}:{prod}:{version_escaped}:*:*:*:*:*:*:*")

    return list(variants)

def find_cpes_by_keyword(vendor, product, version):
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    keyword = f"{vendor} {product} {version}"
    
    r = requests.get(url, params={"keywordSearch": keyword}, headers=headers, timeout=20)
    if r.ok:
        return [item["cpe"]["cpeName"] for item in r.json().get("products", [])]
    else:
        print("Error!")
        print(r)
        print(r.json())
    return []

def fetch_and_save_nvd_vulns(software, force_update=False):
    AV_VALUES = {"NETWORK": 1.0, "ADJACENT_NETWORK": 0.646, "LOCAL": 0.395, "PHYSICAL": 0.2}
    AC_VALUES = {"LOW": 0.71, "MEDIUM": 0.61, "HIGH": 0.35}
    AU_VALUES = {"NONE": 0.704, "SINGLE": 0.56, "MULTIPLE": 0.45}
    E_VALUES = {"UNPROVEN": 0.85, "PROOF-OF-CONCEPT": 0.9, "FUNCTIONAL": 0.95, "HIGH": 1.0, "NOT_DEFINED": 1.0}
    RL_VALUES = {"OFFICIAL_FIX": 0.87, "TEMPORARY_FIX": 0.9, "WORKAROUND": 0.95, "UNAVAILABLE": 1.0, "NOT_DEFINED": 1.0}
    RC_VALUES = {"UNCONFIRMED": 0.9, "UNCORROBORATED": 0.95, "CONFIRMED": 1.0, "NOT_DEFINED": 1.0}
    IMPACT_VALUES = {"NONE": 0.0, "PARTIAL": 0.275, "COMPLETE": 0.66, "LOW": 0.22, "HIGH": 1.0}

    IR = 0.1

    if force_update:
        Vulnerability.query.filter_by(software_id=software.id).delete()
        db.session.commit()

    cpe_list = find_cpes_by_keyword(software.vendor, software.product, software.version)
    selected_cpe = cpe_list[0] if cpe_list else None
    software.cpe = selected_cpe
    db.session.commit()
    if not cpe_list:
        cpe_list = build_cpe_variants(software.vendor, software.product, software.version)
    print(software.vendor, software.product, software.version)
    print(cpe_list)
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    found_cves = set()
    vulns_added = 0

    residual_c = 1.0
    residual_i = 1.0
    residual_a = 1.0

    risk_prod = 1.0 

    for cpe in cpe_list:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        r = requests.get(url, params={"cpeName": cpe}, headers=headers, timeout=30)
        if not r.ok:
            continue
        data = r.json()
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id or cve_id in found_cves:
                continue

            with db.session.no_autoflush:
                exists = Vulnerability.query.filter_by(software_id=software.id, cve=cve_id).first()
            if exists:
                continue

            desc = cve.get("descriptions", [{"value": ""}])[0]["value"]
            metrics = cve.get("metrics", {})

            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]
                baseScore = cvss.get("baseScore")
                AV = AV_VALUES.get(cvss.get("attackVector", "NETWORK").upper(), 1.0)
                AC = AC_VALUES.get(cvss.get("attackComplexity", "LOW").upper(), 0.71)
                AU = AU_VALUES.get(cvss.get("privilegesRequired", "NONE").upper(), 0.704)
                E = E_VALUES.get(cvss.get("exploitCodeMaturity", "NOT_DEFINED").upper(), 1.0)
                RL = RL_VALUES.get(cvss.get("remediationLevel", "NOT_DEFINED").upper(), 1.0)
                RC = RC_VALUES.get(cvss.get("reportConfidence", "NOT_DEFINED").upper(), 1.0)
                C = IMPACT_VALUES.get(cvss.get("confidentialityImpact", "NONE").upper(), 0.0)
                I = IMPACT_VALUES.get(cvss.get("integrityImpact", "NONE").upper(), 0.0)
                A = IMPACT_VALUES.get(cvss.get("availabilityImpact", "NONE").upper(), 0.0)
            elif "cvssMetricV30" in metrics:
                cvss = metrics["cvssMetricV30"][0]["cvssData"]
                baseScore = cvss.get("baseScore")
                AV = AV_VALUES.get(cvss.get("attackVector", "NETWORK").upper(), 1.0)
                AC = AC_VALUES.get(cvss.get("attackComplexity", "LOW").upper(), 0.71)
                AU = AU_VALUES.get(cvss.get("privilegesRequired", "NONE").upper(), 0.704)
                E = E_VALUES.get(cvss.get("exploitCodeMaturity", "NOT_DEFINED").upper(), 1.0)
                RL = RL_VALUES.get(cvss.get("remediationLevel", "NOT_DEFINED").upper(), 1.0)
                RC = RC_VALUES.get(cvss.get("reportConfidence", "NOT_DEFINED").upper(), 1.0)
                C = IMPACT_VALUES.get(cvss.get("confidentialityImpact", "NONE").upper(), 0.0)
                I = IMPACT_VALUES.get(cvss.get("integrityImpact", "NONE").upper(), 0.0)
                A = IMPACT_VALUES.get(cvss.get("availabilityImpact", "NONE").upper(), 0.0)
            elif "cvssMetricV2" in metrics:
                cvss = metrics["cvssMetricV2"][0]["cvssData"]
                baseScore = cvss.get("baseScore")
                AV = AV_VALUES.get(cvss.get("accessVector", "NETWORK").upper(), 1.0)
                AC = AC_VALUES.get(cvss.get("accessComplexity", "LOW").upper(), 0.71)
                AU = AU_VALUES.get(cvss.get("authentication", "NONE").upper(), 0.704)
                E = E_VALUES.get(cvss.get("exploitability", "NOT_DEFINED").upper(), 1.0)
                RL = RL_VALUES.get(cvss.get("remediationLevel", "NOT_DEFINED").upper(), 1.0)
                RC = RC_VALUES.get(cvss.get("reportConfidence", "NOT_DEFINED").upper(), 1.0)
                C = IMPACT_VALUES.get(cvss.get("confidentialityImpact", "NONE").upper(), 0.0)
                I = IMPACT_VALUES.get(cvss.get("integrityImpact", "NONE").upper(), 0.0)
                A = IMPACT_VALUES.get(cvss.get("availabilityImpact", "NONE").upper(), 0.0)
            else:
                baseScore, AV, AC, AU, E, RL, RC, C, I, A = None, 1.0, 0.71, 0.704, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0

            Pe = AV * AC * AU * E * RL * RC
            Pc = C * IR
            Pi = I * IR
            Pa = A * IR

            residual_c *= (1 - Pe * Pc)
            residual_i *= (1 - Pe * Pi)
            residual_a *= (1 - Pe * Pa)

            epss_score = None
            try:
                epss_resp = requests.get(
                    "https://api.first.org/data/v1/epss",
                    params={"cve": cve_id},
                    timeout=10
                )
                if epss_resp.ok:
                    epss_data = epss_resp.json()
                    if "data" in epss_data and len(epss_data["data"]) > 0:
                        epss_score = float(epss_data["data"][0].get("epss", 0))
            except Exception as e:
                print(f"EPSS fetch error for {cve_id}: {e}")

            risk_i = 0.0
            if epss_score is not None and baseScore is not None:
                risk_i = epss_score * (baseScore / 10.0)
                risk_prod *= (1 - risk_i)

            severity = get_severity(baseScore)
            v = Vulnerability(
                software_id=software.id,
                cve=cve_id,
                cvss_score=baseScore,
                description=desc,
                severity=severity,
                integrity_score=Pc,
                confident_score=Pi,
                accessibility_score=Pa,
                epss_score=epss_score
            )
            try:
                db.session.add(v)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                print(f"DB insert error for {cve_id}: {e}")
            vulns_added += 1
            found_cves.add(cve_id)

    print(residual_c)

    device_epss_score = 1 - risk_prod
    software.epss_score = device_epss_score

    software.confident_score = 1 - residual_c
    software.integrity_score = 1 - residual_i
    software.accessibility_score = 1 - residual_a
    software.status = True
    db.session.commit()
    return vulns_added