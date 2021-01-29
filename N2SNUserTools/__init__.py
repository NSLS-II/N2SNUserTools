# flake8: noqa
from ._version import get_versions
__version__ = get_versions()['version']
del get_versions

from .utils import (n2sn_list_group_users_as_table,
                    n2sn_list_user_search_as_table)

from .ldap import ADObjects
from .unix import adquery
