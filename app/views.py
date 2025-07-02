from flask import render_template, request, redirect, url_for, flash, has_request_context
from . import db
from .models import Device, Vulnerability, Software
from .forms import ImportXLSForm, AddSoftwareForm
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
from datetime import datetime 
from flask import current_app as app

@app.route('/')
def dashboard():
    devices_count = Device.query.count()
    vulnerabilities_count = Vulnerability.query.count()
    avg_criticality = 0
    crits = {
        'critical': 1,
        'high': 1,
        'medium': 1,
        'low': 1,
    }
    top_devices = {}
    latest_vulns = Vulnerability.query.order_by(Vulnerability.id.desc()).limit(5).all()
    return render_template('dashboard.html', devices_count=devices_count, vulnerabilities_count=vulnerabilities_count,
                           avg_criticality=avg_criticality, crits=crits, top_devices=top_devices, latest_vulns=latest_vulns)

from .models import AssignmentCode
from flask_wtf import FlaskForm
from wtforms import StringField, FloatField, SubmitField
from wtforms.validators import DataRequired, NumberRange

class AssignmentCodeForm(FlaskForm):
    code = StringField('Код', validators=[DataRequired()])
    name = StringField('Описание', validators=[DataRequired()])
    criticality_multiplier = FloatField('Коэффициент', validators=[DataRequired(), NumberRange(min=0.01, max=100)])
    submit = SubmitField('Сохранить')

@app.route('/assignment_codes')
def assignment_codes():
    codes = AssignmentCode.query.order_by(AssignmentCode.code).all()
    return render_template('assignment_codes.html', codes=codes)

@app.route('/assignment_codes/edit/<int:id>', methods=['GET', 'POST'])
def edit_assignment_code(id):
    code = AssignmentCode.query.get_or_404(id)
    form = AssignmentCodeForm(obj=code)
    if form.validate_on_submit():
        code.code = form.code.data.strip()
        code.name = form.name.data.strip()
        code.criticality_multiplier = form.criticality_multiplier.data
        db.session.commit()
        flash("Коэффициент обновлен!", "success")
        return redirect(url_for('assignment_codes'))
    return render_template('edit_assignment_code.html', form=form, code=code)

@app.route('/assignment_codes/delete/<int:id>', methods=['POST'])
def delete_assignment_code(id):
    code = AssignmentCode.query.get_or_404(id)
    db.session.delete(code)
    db.session.commit()
    flash(f"Код назначения «{code.code}» удалён.", "success")
    return redirect(url_for('assignment_codes'))

@app.route('/assignment_codes/add', methods=['GET', 'POST'])
def add_assignment_code():
    form = AssignmentCodeForm()
    if form.validate_on_submit():
        exists = AssignmentCode.query.filter_by(code=form.code.data.strip()).first()
        if exists:
            flash("Такой код уже есть!", "danger")
        else:
            ac = AssignmentCode(
                code=form.code.data.strip(),
                name=form.name.data.strip(),
                criticality_multiplier=form.criticality_multiplier.data
            )
            db.session.add(ac)
            db.session.commit()
            flash("Добавлен!", "success")
            return redirect(url_for('assignment_codes'))
    return render_template('edit_assignment_code.html', form=form, code=None)

from flask import render_template, request, send_file
from .models import Device, Software, AssignmentCode
from math import ceil
from datetime import datetime, date
import json
import pandas as pd
from io import BytesIO

def parse_eol(eol_raw):
    if not eol_raw:
        return None
    for fmt in ("%d-%m-%Y", "%Y-%m-%d", "%d.%m.%Y", "%Y.%m.%d"):
        try:
            return datetime.strptime(eol_raw.strip(), fmt).date()
        except Exception:
            continue
    return None

@app.route('/devices')
def devices():
    page = request.args.get('page', 1, type=int)
    per_page = 100

    selected_prod = request.args.get('prod', '').strip()
    selected_model = request.args.get('model', '').strip()
    selected_crit = request.args.get('criticality', '').strip()
    selected_target_code = request.args.get('target_code', '').strip()

    query = Device.query

    if selected_prod:
        query = query.filter(Device.prod_name == selected_prod)
    if selected_model:
        query = query.filter(Device.equip_model_name == selected_model)
    if selected_target_code:
        query = query.filter(Device.target_code == selected_target_code)

    today = date.today()
    query = query.order_by(Device.id)
    total = query.count()
    devices_page = query.offset((page - 1) * per_page).limit(per_page).all()

    prod_models_map = {}
    all_prods = set()
    all_models = set()
    for dev in Device.query.order_by(Device.prod_name, Device.equip_model_name).all():
        if dev.prod_name:
            all_prods.add(dev.prod_name)
            prod_models_map.setdefault(dev.prod_name, set())
        if dev.equip_model_name:
            all_models.add(dev.equip_model_name)
            if dev.prod_name:
                prod_models_map[dev.prod_name].add(dev.equip_model_name)

    prod_list = sorted(all_prods)
    model_list = sorted(all_models)
    prod_models_dict = {k: sorted(list(v)) for k, v in prod_models_map.items()}
    prod_models_json = json.dumps(prod_models_dict, ensure_ascii=False)

    assignment_codes = AssignmentCode.query.order_by(AssignmentCode.code).all()
    
    rows = []
    for dev in devices_page:
        software = dev.software
        assignment_code = AssignmentCode.query.filter_by(code=dev.target_code).first()
        multiplier = assignment_code.criticality_multiplier if assignment_code else 1.0

        eol_date = parse_eol(dev.eol)
        conf = (software.confident_score or 0) * multiplier if software else 0
        integ = (software.integrity_score or 0) * multiplier if software else 0
        avail = (software.accessibility_score or 0) * multiplier if software else 0
        crit_bad = conf > 0.5 or integ > 0.5 or avail > 0.5
        is_eol_expired = eol_date and eol_date < today
        crit_level = "high" if crit_bad or is_eol_expired else "low"

        if selected_crit == "high" and crit_level != "high":
            continue
        if selected_crit == "low" and crit_level != "low":
            continue

        rows.append({
            'input': dev,
            'device': software,
            'eol_date': eol_date.isoformat() if eol_date else '',
            'crit_level': crit_level,
            'assignment_code': dev.target_code or '-',
            'multiplier': multiplier,
        })

    today_str = today.isoformat()
    total_pages = ceil(total / per_page)

    return render_template(
        'devices.html',
        rows=rows,
        today_str=today_str,
        page=page,
        total_pages=total_pages,
        prod_list=prod_list,
        model_list=model_list,
        prod_models_dict=prod_models_dict,
        prod_models_json=prod_models_json,
        selected_prod=selected_prod,
        selected_model=selected_model,
        selected_crit=selected_crit,
        assignment_codes=assignment_codes,
        selected_target_code=selected_target_code,
    )


@app.route('/devices/export')
def devices_export():
    selected_prod = request.args.get('prod', '').strip()
    selected_model = request.args.get('model', '').strip()
    selected_crit = request.args.get('criticality', '').strip()
    selected_target_code = request.args.get('target_code', '').strip()

    query = Device.query
    if selected_prod:
        query = query.filter(Device.prod_name == selected_prod)
    if selected_model:
        query = query.filter(Device.equip_model_name == selected_model)
    if selected_target_code:
        query = query.filter(Device.target_code == selected_target_code)

    today = date.today()
    devices_all = query.order_by(Device.id).all()

    data = []
    for dev in devices_all:
        software = dev.software
        assignment_code = AssignmentCode.query.filter_by(code=dev.target_code).first()
        multiplier = assignment_code.criticality_multiplier if assignment_code else 1.0

        eol_date = parse_eol(dev.eol)
        conf = (software.confident_score or 0) * multiplier if software else 0
        integ = (software.integrity_score or 0) * multiplier if software else 0
        avail = (software.accessibility_score or 0) * multiplier if software else 0
        crit_bad = conf > 0.5 or integ > 0.5 or avail > 0.5
        is_eol_expired = eol_date and eol_date < today
        crit_level = "high" if crit_bad or is_eol_expired else "low"

        if selected_crit == "high" and crit_level != "high":
            continue
        if selected_crit == "low" and crit_level != "low":
            continue

        data.append({
            'ID': dev.id,
            'Производитель': dev.prod_name,
            'Модель': dev.equip_model_name,
            'Код назначения': dev.target_code or '-',
            'Коэффициент': multiplier,
            'Дата ввода': dev.start_date,
            'EOL': dev.eol,
            'Критичность': 'Высокая' if crit_level == "high" else 'Низкая',
            'EPSS': software.epss_score if software else '-',
            'Bugs': software.bugs_count if software else '-',
            'Статус': '✔' if software and software.status else '-',
        })

    df = pd.DataFrame(data)
    out = BytesIO()
    df.to_excel(out, index=False)
    out.seek(0)

    filter_part = []
    if selected_prod: filter_part.append(f"prod-{selected_prod}")
    if selected_model: filter_part.append(f"model-{selected_model}")
    if selected_crit: filter_part.append(f"crit-{selected_crit}")
    if selected_target_code: filter_part.append(f"target-{selected_target_code}")
    fname = "devices" + ("__" + "__".join(filter_part) if filter_part else "") + ".xlsx"

    return send_file(out, download_name=fname, as_attachment=True, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.route('/device/<int:device_id>')     
def device_detail(device_id):
    device = Device.query.get_or_404(device_id)
    software = Software.query.get_or_404(device.software_id)
    vulnerabilities = Vulnerability.query.filter_by(software_id=device.software_id).all()
    return render_template('device_detail.html', software=software, vulnerabilities=vulnerabilities, device=device)

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
    add_form = AddSoftwareForm()

    if add_form.validate_on_submit():
        vendor = add_form.vendor.data.strip()
        product = add_form.product.data.strip()
        version = add_form.version.data.strip()
        exist = Software.query.filter_by(vendor=vendor, product=product, version=version).first()
        if exist:
            flash('Такое устройство уже добавлено!', 'warning')
        else:
            new_software = Software(
                vendor=vendor,
                product=product,
                version=version,
                confident_score=0,
                integrity_score=0,
                accessibility_score=0,
                status=True
            )
            db.session.add(new_software)
            db.session.commit()
            fetch_and_save_nvd_vulns(new_software)
            flash('Устройство добавлено и уязвимости импортированы!', 'success')

    form = ImportXLSForm()
    if form.validate_on_submit():
        file = form.file.data
        try:
            df = pd.read_excel(file, dtype=str)
            df.columns = df.columns.str.strip()
            df = df.fillna('-')
            print('COLUMNS:', df.columns.tolist())
            print('HEAD:')
            print(df.head(3).to_string())
        except Exception as ex:
            flash(f"Ошибка чтения файла: {ex}", "danger")
            return redirect(url_for('settings'))

        def get_val(row, col, default='-'):
            val = row.get(col, default)
            if pd.isnull(val) or str(val).lower() in ['nan', 'nat', 'none']:
                return default
            return str(val).strip()

        count_new_devices = 0

        for _, row in df.iterrows():
            equip_model_name = get_val(row, 'Модель оборудования')
            prod_name = get_val(row, 'Производитель')
            part_num = get_val(row, 'Part Number')
            cont_point_id = get_val(row, 'Идентификатор пункта связи')
            cont_point_name = get_val(row, 'Пункт связи')
            eos = get_val(row, 'Окончание срока продажи (Endof Sale, EndOFMarketing)')
            eol = get_val(row, 'Окончание срока технической поддержки (EndOfSupport, EndofLife)')
            start_date = get_val(row, 'Дата ввода в эксплуатацию')
            rack_id = get_val(row, 'Идентификатор стойки')
            target = get_val(row, 'Назначение оборудования')
            target_code = get_val(row, 'Код назначения IP оборудования')
            dns_name = get_val(row, 'DNS имя устройства')
            sdns_name = get_val(row, 'DNS имя устройства (системное)')
            soft_name = get_val(row, 'SoftWare')
            soft_ver = get_val(row, 'Версия SoftWare')


            if prod_name == '-' and equip_model_name == '-':
                continue

            if target_code and target_code != "-":
                ac = AssignmentCode.query.filter_by(code=target_code).first()
                if not ac:
                    ac = AssignmentCode(code=target_code, name=target or '-', criticality_multiplier=1.0)
                    db.session.add(ac)
                    db.session.commit()


            # Стандартизация
            vendor = guess_vendor(prod_name)
            product = guess_product({'Модель': equip_model_name, 'Производитель': prod_name, 'Версия': soft_ver, 'Версия SoftWare': soft_name})
            version = parse_version({'Версия': soft_ver})

            software = Software.query.filter_by(
                vendor=vendor,
                product=product,
                version=version
            ).first()
            if not software:
                software = Software(
                    vendor=vendor,
                    product=product,
                    version=version,
                    confident_score=None,
                    integrity_score=None,
                    accessibility_score=None,
                    status=False
                )
                db.session.add(software)
                db.session.commit()

            input_row = Device(
                equip_model_name=equip_model_name,
                prod_name=prod_name,
                part_num=part_num,
                cont_point_id=cont_point_id,
                cont_point_name=cont_point_name,
                eos=eos,
                eol=eol,
                start_date=start_date,
                rack_id=rack_id,
                target=target,
                target_code=target_code,
                dns_name=dns_name,
                sdns_name=sdns_name,
                soft_name=soft_name,
                soft_ver=soft_ver,
                software_id=software.id
            )
            db.session.add(input_row)
            count_new_devices += 1

        db.session.commit()
        flash(
            f'Импортировано {count_new_devices} записей. Новых устройств: {count_new_devices}.',
            'success',
        )
        return redirect(url_for('settings'))

    return render_template('settings.html', form=form, add_form=add_form)

@app.route('/settings/delete_all', methods=['POST'])
def delete_all():
    Vulnerability.query.delete()
    Software.query.delete()
    Device.query.delete()
    db.session.commit()
    flash('Вся информация удалена.', 'success')
    return redirect(url_for('settings'))

@app.route('/settings/delete_all_devices', methods=['POST'])
def delete_all_devices():
    Device.query.delete()
    db.session.commit()
    flash('Вся информация удалена.', 'success')
    return redirect(url_for('settings'))