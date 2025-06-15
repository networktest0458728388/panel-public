from flask import render_template, request, redirect, url_for, flash, has_request_context
from . import db
from .models import Device, Vulnerability
from .forms import ImportXLSForm, AddDeviceForm
from .utils import fetch_and_save_nvd_vulns, find_cpes_by_keyword, build_cpe_variants, guess_product, get_severity, escape_cpe_special_chars, guess_vendor, parse_version
import os
os.environ["OMP_NUM_THREADS"] = "4"
os.environ["OPENBLAS_NUM_THREADS"] = "4"
os.environ["MKL_NUM_THREADS"] = "6"
os.environ["VECLIB_MAXIMUM_THREADS"] = "4" 
os.environ["NUMEXPR_NUM_THREADS"] = "6"
import pandas as pd
import requests
import re
import subprocess
import sys

from flask import current_app as app

# тут чисто роуты и обработка запросов

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
            flash('Такое устройство уже добавлено!', 'warning')
            return redirect(url_for('devices'))
        new_device = Device(
            vendor=vendor,
            product=product,
            version=version,
            final_criticality=0,
            vulns_loaded=True
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
    # по идее тоже вынести в отдельную функцию, но в целом и так не читабельно, пусть тут пока что будет
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
