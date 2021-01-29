import ssl
from getpass import getpass
from ldap3 import Server, Connection, Tls, NTLM, SASL, GSSAPI, SUBTREE
from ldap3.core.exceptions import (LDAPAuthMethodNotSupportedResult,
                                   LDAPPackageUnavailableError,
                                   LDAPInvalidCredentialsResult,
                                   LDAPNoSuchObjectResult)


from ldap3.extend.microsoft.addMembersToGroups \
    import ad_add_members_to_groups

from ldap3.extend.microsoft.removeMembersFromGroups \
    import ad_remove_members_from_groups


class ADObjects(object):
    _GROUP_ATTRIBUTES = ['sAMAccountName', 'distinguishedName',
                         'member', 'memberOf']
    _USER_ATTRIBUTES = ['sAMAccountName', 'distinguishedName', 'displayName',
                        'employeeID', 'mail', 'description']

    def __init__(self, server,
                 group_search=None,
                 user_search=None,
                 authenticate=False,
                 username=None):

        tls_conf = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1)
        self.server = Server(server, use_ssl=True, tls=tls_conf)
        self.authenticate = authenticate
        self.username = username
        self.user_prefix = 'BNL\\'
        self._group_search = group_search
        self._user_search = user_search

    def __enter__(self):
        if self.authenticate:
            _auth = False

            if self.username is None:
                # We have no username and GSSAPI, try
                # GSSAPI (Kerberos) first
                self.connection = Connection(self.server,
                                             authentication=SASL,
                                             sasl_mechanism=GSSAPI,
                                             auto_bind=False,
                                             raise_exceptions=True)
                try:
                    self.connection.bind()
                except LDAPAuthMethodNotSupportedResult:
                    _auth = False
                except LDAPPackageUnavailableError:
                    _auth = False
                else:
                    _auth = True

            if _auth is not True:
                # NTLM (Password Authentication)
                if self.username is None:
                    self.username = input("\nUsername : ")

                password = getpass("Password : ")

                self.connection = Connection(
                    self.server, user=self.user_prefix + self.username,
                    password=password, authentication=NTLM,
                    auto_bind=True, raise_exceptions=True)
                try:
                    self.connection.bind()
                except LDAPInvalidCredentialsResult:
                    _auth = False
                else:
                    _auth = True

            if _auth:
                whoami = self.connection.extend.standard.who_am_i()
                print('\nAuthenticated as : {}'.format(str(whoami)))
            else:
                raise RuntimeError("Unable to autheticate to server. "
                                   " Please check credentials") from None
        else:
            # Anonymous connection to LDAP server
            self.connection = Connection(self.server,
                                            auto_bind=True,
                                            raise_exceptions=False)

        return self

    def __exit__(self, type, value, traceback):
        self.connection.unbind()

    def _get_group(self, search_filter):
        self.connection.search(
            search_base=self._group_search,
            search_scope=SUBTREE,
            attributes=self._GROUP_ATTRIBUTES,
            search_filter=search_filter
        )

        # Make a dict of returned values

        rtn = list()
        for entry in self.connection.entries:
            rtn.append({key: entry[key].value
                        for key in self._GROUP_ATTRIBUTES})

        return rtn

    def _get_user(self, search_filter):
        self.connection.search(
            search_base=self._user_search,
            search_scope=SUBTREE,
            attributes=self._USER_ATTRIBUTES,
            search_filter=search_filter
        )

        # Make a dict of returned values

        rtn = list()
        for entry in self.connection.entries:
            rtn.append({key: entry[key].value
                        for key in self._USER_ATTRIBUTES})

        return rtn

    def get_user_by_id(self, id):
        return self._get_user('(employeeID={})'.format(id))

    def get_user_by_samaccountname(self, id):
        return self._get_user('(sAMAccountName={})'.format(id))

    def get_user_by_dn(self, id):
        return self._get_user('(distinguishedname={})'.format(id))

    def get_user_by_surname_and_givenname(self,
                                          surname, givenname,
                                          user_type):
        if user_type is None:
            user_type = '*'
        if surname is None:
            surname = '*'
        if givenname is None:
            givenname = '*'

        filter = '(&(sn={})(givenName={})(description={}))'.format(
            surname, givenname, user_type)

        return self._get_user(filter)

    def get_group_by_samaccountname(self, id):
        return self._get_group('(sAMAccountName={})'.format(id))

    def get_group_members(self, group_name):
        group = self.get_group_by_samaccountname(group_name)

        if len(group) == 0:
            return list()

        group = group[0]

        if group['member'] is None:
            return list()

        if type(group['member']) == str:
            members = [group['member']]
        else:
            members = group['member']

        dn_members = list()
        for member in members:
            user = self.get_user_by_dn(member)
            dn_members.append(user[0])

        return dn_members

    def add_user_to_group_by_dn(self, group_name, username):
        ad_add_members_to_groups(self.connection, username, group_name,
                                 fix=True, raise_error=True)

    def remove_user_from_group_by_dn(self, group_name, username):
        ad_remove_members_from_groups(self.connection, username, group_name,
                                      fix=True, raise_error=True)
