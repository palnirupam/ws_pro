import logging
import sys
import os

# Create logs directory if it doesn't exist
log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
os.makedirs(log_dir, exist_ok=True)

# Configure logger
log = logging.getLogger('ws_scanner')
log.setLevel(logging.DEBUG)

# Console handler
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_format = logging.Formatter('%(levelname)s - %(message)s')
console_handler.setFormatter(console_format)
log.addHandler(console_handler)

# File handler
file_handler = logging.FileHandler(os.path.join(log_dir, 'scanner.log'))
file_handler.setLevel(logging.DEBUG)
file_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_format)
log.addHandler(file_handler)
