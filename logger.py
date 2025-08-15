import logging
import os
from datetime import datetime, timedelta

BASE_LOG_DIR = "logs"

def _date_str():
    return datetime.now().strftime("%Y-%m-%d")

def _day_dir(day):
    return os.path.join(BASE_LOG_DIR, day)

def _log_path(day):
    return os.path.join(_day_dir(day), "app.log")

def _ensure_dir(p):
    os.makedirs(p, exist_ok=True)

def _cleanup(max_days=7):
    if not os.path.isdir(BASE_LOG_DIR):
        return
    now = datetime.now()
    for name in os.listdir(BASE_LOG_DIR):
        p = os.path.join(BASE_LOG_DIR, name)
        if not os.path.isdir(p):
            continue
        try:
            d = datetime.strptime(name, "%Y-%m-%d")
        except ValueError:
            continue
        if now - d > timedelta(days=max_days):
            import shutil
            try:
                shutil.rmtree(p)
            except:
                pass

class _DailyRotateFilter(logging.Filter):
    def filter(self, record):
        day = _date_str()
        if getattr(logger, "_current_day", None) != day:
            _switch_handler(day)
            _cleanup()
        return True

def _switch_handler(day):
    _ensure_dir(_day_dir(day))
    fh = logging.FileHandler(_log_path(day), encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] [%(module)s]: %(message)s", datefmt="%H:%M:%S"))
    for h in list(logger.handlers):
        try:
            h.flush()
            h.close()
        except:
            pass
        logger.removeHandler(h)
    logger.addHandler(fh)
    logger._current_day = day

logger = logging.getLogger("OTPLogger")
logger.setLevel(logging.DEBUG)

if not getattr(logger, "_initialized", False):
    _ensure_dir(BASE_LOG_DIR)
    _switch_handler(_date_str())
    logger.addFilter(_DailyRotateFilter())
    logger._initialized = True