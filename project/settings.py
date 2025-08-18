# project/settings.py
from pathlib import Path
from dotenv import load_dotenv
import os

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE_ME")
DEBUG = os.getenv("DEBUG", "False").lower() in ("1", "true", "yes")

def csv_list(name, default=""):
    raw = os.getenv(name, default)
    return [x.strip() for x in raw.split(",") if x.strip()]

ALLOWED_HOSTS = csv_list("ALLOWED_HOSTS", "202.28.49.122")
CSRF_TRUSTED_ORIGINS = csv_list("CSRF_TRUSTED_ORIGINS", "http://202.28.49.122:8080")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.sites",
    "allauth",
    "allauth.account",
    "allauth.socialaccount",
    "myapp",
    "notifications",
]

SITE_ID = int(os.getenv("SITE_ID", "1"))

AUTHENTICATION_BACKENDS = (
    "allauth.account.auth_backends.AuthenticationBackend",
    "django.contrib.auth.backends.ModelBackend",
)

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "allauth.account.middleware.AccountMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.middleware.security.SecurityMiddleware",
]

ROOT_URLCONF = "project.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "project.wsgi.application"

# PostgreSQL ONLY
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("DB_NAME"),
        "USER": os.getenv("DB_USER"),
        "PASSWORD": os.getenv("DB_PASSWORD"),
        "HOST": os.getenv("DB_HOST", "db"),
        "PORT": int(os.getenv("DB_PORT", "5432")),
        "CONN_MAX_AGE": int(os.getenv("DB_CONN_MAX_AGE", "60")),
    }
}

LANGUAGE_CODE = "en-us"
TIME_ZONE = os.getenv("TIME_ZONE", "Asia/Bangkok")
USE_I18N = True
USE_TZ = os.getenv("USE_TZ", "True").lower() in ("1", "true", "yes")

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "myapp" / "static"] if (BASE_DIR / "myapp" / "static").exists() else []

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

SESSION_ENGINE = "django.contrib.sessions.backends.db"
SESSION_COOKIE_NAME = "sessionid"

AUTH_USER_MODEL = "myapp.CustomUser"

FILE_UPLOAD_HANDLERS = [
    "django.core.files.uploadhandler.MemoryFileUploadHandler",
    "django.core.files.uploadhandler.TemporaryFileUploadHandler",
]
FILE_UPLOAD_MAX_MEMORY_SIZE = 104857600
DATA_UPLOAD_MAX_MEMORY_SIZE = 104857600

EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = os.getenv("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", "587"))
EMAIL_USE_TLS = os.getenv("EMAIL_USE_TLS", "True").lower() in ("1", "true", "yes")
EMAIL_USE_SSL = os.getenv("EMAIL_USE_SSL", "False").lower() in ("1", "true", "yes")
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD", "")
DEFAULT_FROM_EMAIL = os.getenv("DEFAULT_FROM_EMAIL", EMAIL_HOST_USER or "webmaster@localhost")
SERVER_EMAIL = os.getenv("SERVER_EMAIL", DEFAULT_FROM_EMAIL)

from decouple import config

ALLOWED_HOSTS = [
    h.strip()
    for h in config("ALLOWED_HOSTS", default="").split(",")
    if h.strip()
]

# ใส่ทั้ง http และ https พร้อมพอร์ต (เช่น 8080)
def _with_port(host, port="8080"):
    return f"http://{host}:{port}", f"https://{host}:{port}"

_csrf = []
for h in ALLOWED_HOSTS:
    if h in ("", "localhost", "127.0.0.1"):
        # สำหรับ dev/localhost (ถ้าจะใช้) ไม่ใส่พอร์ตก็ได้ถ้าใช้ 80/443
        _csrf.extend([f"http://{h}:8080", f"https://{h}:8080"])
    else:
        http, https = _with_port(h, "8080")
        _csrf.extend([http, https])

CSRF_TRUSTED_ORIGINS = _csrf

DEBUG = False

STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"