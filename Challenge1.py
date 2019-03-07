# Python for Network Engineers Challenge Lab #1 Solution
# Revision May 22 2018

# Shebang for Linux:
#!/usr/bin/env python
# Define the first function devices:
def devices():
	routers = ['router1', 'router2', 'router3']
	print routers
# Define the second function security:
def security():
	credentials = {'router1':'passw0rd1', 'router2': 'passw0rd1', 'router3': 'passw0rd1'}
	print credentials
#  Define the third function combined that uses the first two functions:
def combined():
	devices()
	security()
# Define the entry point:
if __name__ == "__main__":
	print "The routers are:"
	devices()

	print "The credentials are:"
	security()

	print "All data is"
	combined()


	
	
	import logging
import logsettings

import os
from queue import Queue
from threading import Thread, Lock

import dateutil.parser
import gaiaenv
import netcap
from environs import Env
import collections

env = Env()

logger = logging.getLogger(__name__)

NETCAP_URL = os.getenv('NETCAP_URL')
USER = os.getenv('USER')
PW = os.getenv('PW')
ADDOMAIN = os.getenv('ADDOMAIN')
MAX_NASH_TASKS = os.getenv('MAX_NASH_TASKS')
HISTORY = env.bool('HISTORY', True)
LOCAL = env.bool('LOCAL', False)
IDA_ENVIRONMENT = netcap.IDA_UAT
RED_ERROR_RATE = 1000 / (30 * 60)  # Over 1000 errors every 30 min
ORANGE_ERROR_RATE = 100 / (30 * 60)  # Over 100 errors every 30 min


class Metric:
    Uniquetuple = collections.namedtuple('Uniquetuple', 'DEVICE ROLE MOD DEVICE_STATISTICS_CATEGORY INSTANCE ID NAME '
                                                        'PORTS LAST_CLEARED_MONTH LAST_CLEARED_DAY LAST_CLEARED_HOUR '
                                                        'LAST_CLEARED_MIN LAST_CLEARED_SEC LAST_CLEARED_YEAR')

    def __init__(self, metric_dict):
        """
        A metric is a unique element on a network device that can be in an error condition.  The 'uniquetuple' defines
        each unique metric.  The diagnostic for a device may repeat the same metric multiple times and only one is
        needed.  The 'value' is the error counter for each unique metric that is compared to previous values.
        :param metric_dict: {'DEVICE': 'X', 'ROLE': 'X', 'MOD': 'X', 'DEVICE_STATISTICS_CATEGORY': 'X',
                            'INSTANCE': 'X', 'ID': 'X', 'NAME': 'X', 'PORTS': 'X', 'LAST_CLEARED_MONTH': 'X',
                            'LAST_CLEARED_DAY': 'X', 'LAST_CLEARED_HOUR': 'X', 'LAST_CLEARED_MIN': 'X',
                            'LAST_CLEARED_SEC': 'X', 'LAST_CLEARED_YEAR': 'X', 'VALUE': 'X'}
        """
        self.uniquetuple = Metric.Uniquetuple(metric_dict['DEVICE'], metric_dict['ROLE'], metric_dict['MOD'],
                                              metric_dict['DEVICE_STATISTICS_CATEGORY'], metric_dict['INSTANCE'],
                                              metric_dict['ID'], metric_dict['NAME'], metric_dict['PORTS'],
                                              metric_dict['LAST_CLEARED_MONTH'], metric_dict['LAST_CLEARED_DAY'],
                                              metric_dict['LAST_CLEARED_HOUR'], metric_dict['LAST_CLEARED_MIN'],
                                              metric_dict['LAST_CLEARED_SEC'], metric_dict['LAST_CLEARED_YEAR'])
        self.value = int(metric_dict['VALUE'])


class Metrics:

    def __init__(self, commandsetresponse):
        """
        Metrics takes the structured data response from the diagnostic command on the network device.  Metrics.metrics
        is a dictionary with a key of the uniquetuple that identifies the unique metric and a value which is the
        entire dict of the original metric.
        :param commandsetresponse: Diagnostic response from the network device as json (list of dicts)
        """
        self.metrics = {Metric(i).uniquetuple: Metric(i).value for i in commandsetresponse.parsed_message}
        self.executed_at = commandsetresponse.executed_at
        self.host = commandsetresponse.device


class Checker:

    def __init__(self, hosts):
        if LOCAL:
            user = USER
            pw = PW
        else:
            for credential in gaiaenv.GaiaEnv().services(name='netcap-api')[0].credentials:
                user = credential.name
                pw = credential.value
        logger.debug("Starting checker")
        self.netcap_session = netcap.Session(NETCAP_URL, ida=IDA_ENVIRONMENT, username=user, password=pw,
                                             ad_domain=ADDOMAIN)
        self.q = Queue()
        self.hosts = hosts
        self.start_threads()
        self.build_queue()

    def worker(self):
        while True:
            with Lock():
                host = self.q.get()
                self.q.put(host)
            try:
                self.host_check(host)
            except Exception as e:
                logger.warning('Application processing error',
                               extra={'n7k': host, 'app_error_code': 'A001', 'app_error_message': str(e)})
            self.q.task_done()

    def start_threads(self):
        for thread_num in range(int(MAX_NASH_TASKS)):
            logger.debug("Starting thread")
            thread = Thread(target=self.worker)
            thread.start()

    def build_queue(self):
        for host in self.hosts:
            self.q.put(host)

    def host_check(self, host):
        logger.debug('Fetching diagnostics', extra={'n7k': host})
        commandset = {'command': 'show hardware internal errors all'}
        current = Metrics(
            self.netcap_session.fetch(device=host, commandsets=[commandset], history=HISTORY).find(commandset))

        try:
            previous = Metrics(self.netcap_session.fetch(device=host, commandsets=[commandset],
                                                         end=current.executed_at).find(commandset))
            errors_detected = Checker.eval_metrics(host=host, current=current, previous=previous)
            for error_detected in errors_detected:
                logger.error('Error detected', extra=error_detected)
        except Exception as e:
            logger.warning('Application processing error',
                           extra={'n7k': host, 'app_error_code': 'A002', 'app_error_message': str(e)})
        logger.info('Completed error check', extra={'n7k': host})

    @staticmethod
    def eval_metrics(host, current, previous):
        """
        :param host: name of network device
        :param current: type Metrics for the device's current diagnostic
        :param previous: type Metrics for the device's previous diagnostic
        :return: list of dicts where each dict is a reportable device error
        """
        errors_detected = []
        for uniquetuple, value in current.metrics.items():
            error_type = Checker.eval_error_type(uniquetuple)
            error_rate = Checker.eval_error_rate(uniquetuple, current, previous)
            priority = Checker.eval_priority(error_rate)

            if error_type and priority:
                errors_detected.append(
                    {
                        'n7k': host,
                        'priority': priority, 'error_rate': '{:.4f}'.format(error_rate), 'error_type': error_type,
                        'device': uniquetuple.DEVICE, 'role': uniquetuple.ROLE, 'mod': uniquetuple.MOD,
                        'category': uniquetuple.DEVICE_STATISTICS_CATEGORY,
                        'instance': uniquetuple.INSTANCE, 'id': uniquetuple.ID, 'error_name': uniquetuple.NAME,
                        'ports': uniquetuple.PORTS, 'previous_value': previous.metrics.get(uniquetuple, 0),
                        'current_value': value, 'previous_time': previous.executed_at,
                        'current_time': current.executed_at,
                        'last_cleared': '{}-{}-{}'.format(uniquetuple.LAST_CLEARED_YEAR,
                                                          uniquetuple.LAST_CLEARED_MONTH,
                                                          uniquetuple.LAST_CLEARED_DAY)
                    }
                )
        return errors_detected

    @staticmethod
    def eval_error_type(uniquetuple):
        if uniquetuple.NAME == 'phy_bad_crc_count':
            return None
        elif uniquetuple.DEVICE == 'Naxos' \
                and 'ingress' in uniquetuple.NAME.lower() \
                and 'crc' in uniquetuple.NAME.lower():
            return None
        elif any(x in uniquetuple.NAME.lower() for x in ['crc', 'fcs', 'abort', 'wen']):
            return 'corrupted'
        elif any(x in uniquetuple.NAME.lower() for x in ['drop', 'fifo']):
            if any(x in uniquetuple.NAME.lower() for x in ['vsl', 'cbl']):
                return None
            else:
                return 'drops'
        elif any(x in uniquetuple.NAME.lower() for x in ['par', 'err', 'ecc']):
            if any(x in uniquetuple.NAME.lower() for x in ['nf', 'soe']):
                return None
            else:
                return 'memory'
        else:
            return None

    @staticmethod
    def eval_error_rate(uniquetuple, current, previous):
        previous_time = dateutil.parser.parse(previous.executed_at)
        current_time = dateutil.parser.parse(current.executed_at)
        delta_time = (current_time - previous_time).total_seconds()
        delta_errors = current.metrics[uniquetuple] - previous.metrics.get(uniquetuple, 0)
        error_rate = delta_errors / delta_time
        return error_rate

    @staticmethod
    def eval_priority(error_rate):
        if error_rate > RED_ERROR_RATE:
            return 'red'
        elif error_rate > ORANGE_ERROR_RATE:
            return 'orange'
        elif error_rate > 0:
            return 'yellow'
        else:
            return None


if __name__ == '__main__':
    with open('n7k_checker/n7k_all.txt') as f:
        n7ks = f.read().split()

    c = Checker(n7ks)

