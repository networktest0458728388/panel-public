import time
import subprocess
import sys
from app import create_app
from app.models import Device, Software

MAX_WORKERS = 5
SCAN_INTERVAL = 10 

def get_pending_device_ids():
    app = create_app()
    with app.app_context():
        devices = Software.query.filter_by(status=False).all()
        return [d.id for d in devices]

def main():
    processed_ids = set()
    active_processes = []

    print("Запущен диспетчер обработки устройств.")
    while True:
        pending_ids = set(get_pending_device_ids())
        new_ids = pending_ids - processed_ids - {d for d, _ in active_processes}
        
        for device_id in new_ids:
            if len(active_processes) >= MAX_WORKERS:
                break
            print(f"Старт воркера для устройства {device_id}")
            p = subprocess.Popen([sys.executable, "-m", "app.worker", str(device_id)])
            active_processes.append((device_id, p))
            processed_ids.add(device_id)
            time.sleep(1) 
  
        still_active = []
        for device_id, p in active_processes:
            ret = p.poll()
            if ret is not None:
                print(f"Воркер для {device_id} завершён с кодом {ret}")
            else:
                still_active.append((device_id, p))
        active_processes = still_active

        if not get_pending_device_ids() and not active_processes:
            print("Все устройства обработаны. Ожидание новых...")
        time.sleep(SCAN_INTERVAL)

if __name__ == "__main__":
    main()