from flask_wtf import FlaskForm
from wtforms import FileField, SubmitField, StringField
from wtforms.validators import DataRequired
from flask_wtf.file import FileAllowed

class AddSoftwareForm(FlaskForm):
    vendor = StringField('Вендор', validators=[DataRequired()])
    product = StringField('Продукт', validators=[DataRequired()])
    version = StringField('Версия')
    submit = SubmitField('Добавить ПО')

class ImportXLSForm(FlaskForm):
    file = FileField('XLS/XLSX файл', validators=[FileAllowed(['xls', 'xlsx'])])
    submit = SubmitField('Импортировать')