from . import create_app
from .models import Device, Software
from .utils import fetch_and_save_nvd_vulns
import sys


def main(device_id: int):
    app = create_app()
    with app.app_context():
        device = Software.query.get(device_id)
        if device:
            fetch_and_save_nvd_vulns(device)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Usage: python -m app.worker DEVICE_ID')
    main(int(sys.argv[1]))