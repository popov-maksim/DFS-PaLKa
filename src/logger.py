import logging

_logger = logging.getLogger(__name__)
_logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('[%(asctime)s]  %(message)s', datefmt='%d/%m/%Y %H:%M:%S')

# Console
c_handler = logging.StreamHandler()
c_handler.setFormatter(formatter)
_logger.addHandler(c_handler)

# File
f_handler = logging.FileHandler('log.log')
f_handler.setFormatter(formatter)
_logger.addHandler(f_handler)


def debug_log(*log_info):
    _logger.debug(log_info)
