"""Logger v1
"""
import os
import logging.config

import yaml

def setup_logging(
	default_path='log_config.yaml',
	default_level=logging.INFO,
	env_key='LOG_CFG'
):
	"""Setup logging configuration
	"""
	path = default_path
	value = os.getenv(env_key, None)
	if value:
		path = value
	if os.path.exists(path):
		with open(path, 'rt') as f:
			config = yaml.safe_load(f.read())
		logging.config.dictConfig(config)
		#~ f.close()
	else:
		logging.basicConfig(level=default_level)

def log_event(msg, isError=False):
	if isError:
		logging.error(msg)
		#~ logging.exception(msg)
	else:
		logging.info(msg)
