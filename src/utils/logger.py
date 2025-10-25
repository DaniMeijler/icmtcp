import logging
import sys

class Logger:
    def __init__(self, name: str = __name__) -> None:
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)

        console_handler = logging.StreamHandler()
        console_handler.setStream(sys.stdout)
        console_handler.setLevel(logging.DEBUG)

        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)

        self.logger.addHandler(console_handler)

    def log(self, level: int, message: str) -> None:
        self.logger.log(level, message)

    def info(self, message: str) -> None:
        self.log(logging.INFO, message)
    
    def debug(self, message: str) -> None:
        self.log(logging.DEBUG, message)
    
    def error(self, message: str) -> None:
        self.log(logging.ERROR, message)
    
    def warning(self, message: str) -> None:
        self.log(logging.WARNING, message)
    