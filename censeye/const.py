from censys.search import CensysHosts

from .__version__ import __version__

DEFAULT_MAX_SEARCH_RESULTS = 45
USER_AGENT = CensysHosts.DEFAULT_USER_AGENT + f" censeye/{__version__}"
