import logging
from src.utils.logger import Logger


def test_logger_initialization():
    l = Logger('test_module')
    assert l.logger.name == 'test_module'
    assert isinstance(l.logger.level, int)


def test_log_levels(caplog):
    l = Logger('test_mod2')
    with caplog.at_level(logging.DEBUG):
        l.debug('debug message')
        l.info('info')
        l.warning('warn')
        l.error('err')
        assert 'debug message' in caplog.text
