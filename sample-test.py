import logging
import os

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)
logging.debug('This message should appear on the console')
logging.info('So should this')
logging.warning('And this, too')


def inc(x):
    logging.warning('And this, too')
    print(os.getenv('IP_SET_ID_HTTP_FLOOD'))
    return x + 1


def test_answer():
    assert inc(3) == 4
