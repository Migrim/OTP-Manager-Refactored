import logging

def get_logger(name):
    logger = logging.getLogger(name)
    logger.propagate = False
    logger.setLevel(logging.INFO)

    file_handler = logging.FileHandler('OTP-Manager.log')
    file_handler.setLevel(logging.INFO)
    
    # Correct the formatter string here
    formatter = logging.Formatter('%(asctime)s | [%(levelname)s] | %(message)s', datefmt='%Y.%m.%d | %H:%M:%S')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    return logger
