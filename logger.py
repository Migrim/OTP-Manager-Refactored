import logging
import os
from datetime import datetime, timedelta

BASE_LOG_DIR = "logs"
TODAY = datetime.now().strftime("%Y-%m-%d")
TODAY_LOG_DIR = os.path.join(BASE_LOG_DIR, TODAY)
LOG_PATH = os.path.join(TODAY_LOG_DIR, "app.log")

os.makedirs(TODAY_LOG_DIR, exist_ok=True)

for folder in os.listdir(BASE_LOG_DIR):
    folder_path = os.path.join(BASE_LOG_DIR, folder)
    try:
        folder_date = datetime.strptime(folder, "%Y-%m-%d")
        if datetime.now() - folder_date > timedelta(days=7):
            import shutil
            shutil.rmtree(folder_path)
    except ValueError:
        continue 

logger = logging.getLogger("OTPLogger")
logger.setLevel(logging.DEBUG)

if not logger.hasHandlers():
    file_handler = logging.FileHandler(LOG_PATH)
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] [%(module)s]: %(message)s",
        datefmt="%H:%M:%S"
    ))
    logger.addHandler(file_handler)