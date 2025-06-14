from flask import render_template, request, redirect, url_for, flash, has_request_context
from . import db
from .models import Device, Vulnerability
from .forms import ImportXLSForm, AddDeviceForm
import os
os.environ["OMP_NUM_THREADS"] = "4"
os.environ["OPENBLAS_NUM_THREADS"] = "4"
os.environ["MKL_NUM_THREADS"] = "6"
os.environ["VECLIB_MAXIMUM_THREADS"] = "4" 
os.environ["NUMEXPR_NUM_THREADS"] = "6"
import pandas as pd
import requests
import re
from threading import Thread

from flask import current_app as app

NVD_API_KEY = os.environ.get('NVD_API_KEY')

def _process_device(device_id):
    with app.app_context():
        device = Device.query.get(device_id)
        if device:
            fetch_and_save_nvd_vulns(device)


def schedule_device_processing(device_id):
    Thread(target=_process_device, args=(device_id,), daemon=True).start()


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
    # костыль переделать
    if not version:
        return ""
    return version.replace('(', '\\(').replace(')', '\\)')

def build_cpe_variants(vendor, product, version):
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
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    keyword = f"{vendor} {product} {version}"
    try:
        r = requests.get(url, params={"keywordSearch": keyword}, headers=headers, timeout=20)
        if r.ok:
            return [item["cpe"]["cpeName"] for item in r.json().get("products", [])]
    except Exception as ex:
        if has_request_context():
            flash(f"Ошибка поиска CPE: {ex}", "danger")
    return []

def fetch_and_save_nvd_vulns(device, force_update=False):
    if force_update:
        Vulnerability.query.filter_by(device_id=device.id).delete()
        db.session.commit()
    # cpe доделать
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

    for cpe in cpe_list:
        try:
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
                cvss = None
                metrics = cve.get("metrics", {})
                if "cvssMetricV31" in metrics:
                    cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV30" in metrics:
                    cvss = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV2" in metrics:
                    cvss = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
                severity = get_severity(cvss)
                v = Vulnerability(
                    device_id=device.id,
                    cve=cve_id,
                    cvss_score=cvss,
                    description=desc,
                    severity=severity,
                    final_criticality=cvss or 0
                )
                db.session.add(v)
                vulns_added += 1
                found_cves.add(cve_id)
            db.session.commit()
        except Exception as ex:
            if has_request_context():
                flash(f"Ошибка при обращении к NVD для {cpe}: {ex}", "danger")

    vuls = Vulnerability.query.filter_by(device_id=device.id).all()
    device.final_criticality = round(sum([v.final_criticality for v in vuls]), 2)  # сюда потом формулу вставить
    device.vulns_loaded = True
    db.session.commit()
    return vulns_added

def guess_vendor(raw_vendor):
    v = str(raw_vendor).lower().strip()
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

@app.route('/')
def dashboard():
    devices_count = Device.query.count()
    vulnerabilities_count = Vulnerability.query.count()
    avg_criticality = round(db.session.query(db.func.avg(Device.final_criticality)).scalar() or 0, 2)
    crits = {
        'critical': Vulnerability.query.filter(Vulnerability.final_criticality >= 9).count(),
        'high': Vulnerability.query.filter(Vulnerability.final_criticality >= 7, Vulnerability.final_criticality < 9).count(),
        'medium': Vulnerability.query.filter(Vulnerability.final_criticality >= 4, Vulnerability.final_criticality < 7).count(),
        'low': Vulnerability.query.filter(Vulnerability.final_criticality < 4).count(),
    }
    top_devices = Device.query.order_by(Device.final_criticality.desc()).limit(5).all()
    latest_vulns = Vulnerability.query.order_by(Vulnerability.id.desc()).limit(5).all()
    return render_template('dashboard.html', devices_count=devices_count, vulnerabilities_count=vulnerabilities_count,
                           avg_criticality=avg_criticality, crits=crits, top_devices=top_devices, latest_vulns=latest_vulns)

@app.route('/devices', methods=['GET', 'POST'])
def devices():
    add_form = AddDeviceForm()
    devices = Device.query.order_by(Device.final_criticality.desc()).all()
    if add_form.validate_on_submit():
        vendor = add_form.vendor.data.strip()
        product = add_form.product.data.strip()
        version = add_form.version.data.strip()
        exist = Device.query.filter_by(vendor=vendor, product=product, version=version).first()
        if exist:
            # temp
            flash('Такое устройство уже добавлено!', 'warning')
            return redirect(url_for('devices'))
        new_device = Device(
            vendor=vendor,
            product=product,
            version=version,
            final_criticality=0,
            vulns_loaded=False
        )
        db.session.add(new_device)
        db.session.commit()

        fetch_and_save_nvd_vulns(new_device)
        flash('Устройство добавлено и уязвимости импортированы!', 'success')
        return redirect(url_for('device_detail', device_id=new_device.id))

    return render_template('devices.html', devices=devices, add_form=add_form)

@app.route('/device/<int:device_id>')
def device_detail(device_id):
    device = Device.query.get_or_404(device_id)
    vulnerabilities = Vulnerability.query.filter_by(device_id=device.id).order_by(Vulnerability.final_criticality.desc()).all()
    return render_template('device_detail.html', device=device, vulnerabilities=vulnerabilities)

@app.route('/device/<int:device_id>/refresh', methods=['POST'])
def device_refresh(device_id):
    device = Device.query.get_or_404(device_id)
    vulns_added = fetch_and_save_nvd_vulns(device, force_update=True)
    flash(f"Обновление завершено. Найдено и добавлено уязвимостей: {vulns_added}", "success")
    return redirect(url_for('device_detail', device_id=device.id))

@app.route('/device/<int:device_id>/delete', methods=['POST'])
def device_delete(device_id):
    device = Device.query.get_or_404(device_id)
    Vulnerability.query.filter_by(device_id=device.id).delete()
    db.session.commit()
    db.session.delete(device)
    db.session.commit()
    flash('Устройство и все связанные уязвимости удалены.', 'success')
    return redirect(url_for('devices'))

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    form = ImportXLSForm()
    if form.validate_on_submit():
        file = form.file.data
        try:
            df = pd.read_excel(file)
        except Exception as ex:
            flash(f"Ошибка чтения файла: {ex}", "danger")
            return redirect(url_for('settings'))

        count_new = 0
        created_ids = []
        for _, row in df.iterrows():
            vendor = guess_vendor(row['Производитель'])
            product = guess_product(row)
            version = parse_version(row)
            device = Device.query.filter_by(
                vendor=vendor, product=product, version=version
            ).first()
            if not device:
                device = Device(
                    vendor=vendor,
                    product=product,
                    version=version,
                    final_criticality=0,
                    vulns_loaded=False,
                )
                db.session.add(device)
                db.session.commit()
                created_ids.append(device.id)
            count_new += 1
        for dev_id in created_ids:
            schedule_device_processing(dev_id)
        flash(
            f'Импортировано устройств: {count_new}. Загрузка уязвимостей выполняется в фоне',
            'success',
        )
        return redirect(url_for('settings'))
    return render_template('settings.html', form=form)

@app.route('/settings/delete_all_devices', methods=['POST'])
def delete_all_devices():
    Vulnerability.query.delete()
    Device.query.delete()
    db.session.commit()
    flash('Все устройства и уязвимости удалены.', 'success')
    return redirect(url_for('settings'))
