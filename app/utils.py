from .models import Device, Vulnerability
from . import db
import os
import requests
import re
# тут типа все функции чтобы
NVD_API_KEY = "16ee4afe-e8f4-441f-a4fc-d085d74747c3" # api key


#------ парсим инфу по софту (переделать отдельно логику и добавить) ------

def guess_vendor(row):
    v = str(row).lower().strip()
    if "cisco" in v:
        return "cisco"
    if "eltex" in v:
        return "eltex"
    if "huawei" in v:
        return "huawei"
    if "juniper" in v:
        return "juniper"
    if "moxa" in v:
        return "moxa"
    if "fujitsu" in v:
        return "fujitsu"
    return v.replace(" ", "_")

def guess_product(row):
    vendor = guess_vendor(row['Производитель'])
    version = str(row['Версия']).lower()
    if vendor == 'cisco':
        if 'ios-xe' in version or 'xe' in version:
            return 'ios_xe'
        elif 'ios-xr' in version or 'xr' in version:
            return 'ios_xr'
        elif 'nx-os' in version or 'nxos' in version:
            return 'nx-os'
        elif 'asa' in version:
            return 'asa_software'
        else:
            return 'ios'
    if vendor == 'juniper':
        return 'junos'
    if vendor == 'huawei':
        return 'vrp'
    return str(row['Модель']).replace(' ', '_')

def parse_version(row):
    v = str(row['Версия'])
    m = re.search(r'[Vv]ersion\s*([^\s,]+)', v)
    if m:
        return m.group(1)
    m = re.search(r'(\d{1,2}\.\d{1,2}[A-Z]?\d{0,2}(\.\d{1,2})?(-S\d+(\.\d+)?)?)', v)
    if m:
        return m.group(1)
    m = re.match(r'([\d\.vVRr]+)', v)
    if m:
        return m.group(1)
    return v

#------ тех. функции ------

def get_severity(cvss): # критичность типа
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

#------ модули обработки cpe ------

def escape_cpe_special_chars(version): # делаем из ( --> \( и ) --> \) ввиду особенностей NVD
    if not version:
        return ""
    return version.replace('(', '\\(').replace(')', '\\)')

def build_cpe_variants(vendor, product, version):
    # генерим кучу cpe в случае если не удалось спарсить с NVD, метод тыка.
    vendor = vendor.strip().lower()
    product = product.strip().lower()
    version_raw = str(version).strip().lower()
    version_escaped = escape_cpe_special_chars(version_raw)
    variants = set()
    products = {product}
    if vendor == "cisco":
        products |= {"ios", "ios_xe", "ios_xr", "asa_software", "asa", "nx-os"}
    if vendor == "juniper":
        products |= {"junos"}
    for prod in products:
        variants.add(f"cpe:2.3:o:{vendor}:{prod}:{version_raw}:*:*:*:*:*:*:*")
        variants.add(f"cpe:2.3:o:{vendor}:{prod}:{version_escaped}:*:*:*:*:*:*:*")
        variants.add(f"cpe:2.3:h:{vendor}:{prod}:{version_raw}:*:*:*:*:*:*:*")
        variants.add(f"cpe:2.3:h:{vendor}:{prod}:{version_escaped}:*:*:*:*:*:*:*")
        variants.add(f"cpe:2.3:a:{vendor}:{prod}:{version_raw}:*:*:*:*:*:*:*")
        variants.add(f"cpe:2.3:a:{vendor}:{prod}:{version_escaped}:*:*:*:*:*:*:*")
    return list(variants)

def find_cpes_by_keyword(vendor, product, version):
    # парсим cpe
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

def fetch_and_save_nvd_vulns(device, force_update=False):
    AV_VALUES = {"NETWORK": 1.0, "ADJACENT_NETWORK": 0.646, "LOCAL": 0.395, "PHYSICAL": 0.2}
    AC_VALUES = {"LOW": 0.71, "MEDIUM": 0.61, "HIGH": 0.35}
    AU_VALUES = {"NONE": 0.704, "SINGLE": 0.56, "MULTIPLE": 0.45}
    E_VALUES = {"UNPROVEN": 0.85, "PROOF-OF-CONCEPT": 0.9, "FUNCTIONAL": 0.95, "HIGH": 1.0, "NOT_DEFINED": 1.0}
    RL_VALUES = {"OFFICIAL_FIX": 0.87, "TEMPORARY_FIX": 0.9, "WORKAROUND": 0.95, "UNAVAILABLE": 1.0, "NOT_DEFINED": 1.0}
    RC_VALUES = {"UNCONFIRMED": 0.9, "UNCORROBORATED": 0.95, "CONFIRMED": 1.0, "NOT_DEFINED": 1.0}
    IMPACT_VALUES = {"NONE": 0.0, "PARTIAL": 0.275, "COMPLETE": 0.66, "LOW": 0.22, "HIGH": 1.0}
    IR = 0.1

    if force_update:
        Vulnerability.query.filter_by(device_id=device.id).delete()
        db.session.commit()
    cpe_list = find_cpes_by_keyword(device.vendor, device.product, device.version)
    selected_cpe = cpe_list[0] if cpe_list else None
    device.cpe = selected_cpe
    db.session.commit()
    if not cpe_list:
        cpe_list = build_cpe_variants(device.vendor, device.product, device.version)

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    found_cves = set()
    vulns_added = 0

    residual_c = 1.0
    residual_i = 1.0
    residual_a = 1.0

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
            # Проверка на дубликаты
            if Vulnerability.query.filter_by(device_id=device.id, cve=cve_id).first():
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

            severity = get_severity(baseScore)
            v = Vulnerability(
                device_id=device.id,
                cve=cve_id,
                cvss_score=baseScore,
                description=desc,
                severity=severity,
                final_criticality=baseScore or 0
            )
            db.session.add(v)
            vulns_added += 1
            found_cves.add(cve_id)
        db.session.commit()

    final_Pc = 1 - residual_c
    final_Pi = 1 - residual_i
    final_Pa = 1 - residual_a

    device.final_criticality = max(final_Pc, final_Pi, final_Pa)  
    device.vulns_loaded = True
    db.session.commit()
    return vulns_added
#------ туда сюда и так далее ------