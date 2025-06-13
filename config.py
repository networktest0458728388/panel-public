import os
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'verysecret'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    NVD_API_KEY = os.environ.get('NVD_API_KEY') or '16ee4afe-e8f4-441f-a4fc-d085d74747c3'
