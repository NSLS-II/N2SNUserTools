import sys
import random
from os.path import expanduser, basename
import argparse
import yaml
from ldap3.core.exceptions import LDAPInsufficientAccessRightsResult

from .utils import (n2sn_list_group_users_as_table,
                    n2sn_list_user_search_as_table)
from .ldap import ADObjects

from . import __version__

sys.tracebacklimit = 0

config_files = [
    expanduser('~/.config/n2sn_tools.yml'),
    '/etc/n2sn_tools.yml'
]


def base_argparser(description, default_inst=True, auth=False):
    parser = argparse.ArgumentParser(
        prog=basename(sys.argv[0]),
        description=description
    )

    parser.add_argument('--version', action='version',
                        version=('%(prog)s v' + __version__))

    if default_inst:
        parser.add_argument(
            '-i', '--instrument', '--beamline', dest='instrument',
            action='store', help='Name of N2SN instrument',
            default=None
        )

    if auth:
        parser.add_argument(
            '-u', '--username', dest='username',
            action='store', help='Username to use for authentication',
            default=None
        )

    return parser


def read_config(parser, instrument=None, no_inst=False):
    config = None
    for fn in config_files:
        try:
            with open(fn) as f:
                config = yaml.load(f, Loader=yaml.SafeLoader)
        except IOError:
            pass
        else:
            break

    if config is None:
        raise RuntimeError("Unable to open a config file")

    if 'common' not in config:
        print(parser.error(
            "Section 'common' missing from config file."))

    if 'server_list' in config['common']:
        server = config['common']['server_list']
        server = server[random.randint(0, len(server) - 1)]
        config['common']['server'] = server

    if no_inst is False:
        if instrument is None:
            if 'default_instrument' not in config['common']:
                print(parser.error(
                    "'default_instrument' not defined in config file. "
                    "Please specify on command line"))

            instrument = config['common']['default_instrument']

        if instrument not in config['instruments']:
            print(parser.error("instrument '{}' is not "
                               "defined in the config file."
                               .format(instrument)))

        return config['common'], config['instruments'][instrument]

    else:
        return config['common'], None


def n2sn_list(desc, message, group_name):
    parser = base_argparser(
        'List current enabled users for an instrument', True
    )

    args = parser.parse_args()

    common_config, config = read_config(parser, args.instrument)

    print("\n{} for instrument {}\n"
          .format(message, config['name'].upper()))

    groups = config['rights']

    print(n2sn_list_group_users_as_table(
          common_config['server'],
          common_config['group_search'],
          common_config['user_search'],
          common_config.get('ldap_ca_cert', None),
          groups))


def n2sn_list_users():
    n2sn_list(
        'List current enabled users for an instrument',
        'Current users enabled',
        'user_group'
    )


def n2sn_change_user(operation):
    parser = base_argparser(
        'Add or remove attribute from user',
        auth=True)

    user_group = parser.add_mutually_exclusive_group()
    user_group.add_argument(
        '-l', '--login', dest='login', action='store',
        help='Login (username) of user',
    )
    user_group.add_argument(
        '-n', '--life-number', dest='life_number', action='store',
        help='Life number of guest number of user',
    )
    if operation == 'remove':
        user_group.add_argument(
           '--purge', dest='purge', action='store_true',
           help='Purge all users from right'
        )

    parser.add_argument('right', metavar='RIGHT', type=str,
                        help='Right to add')

    args = parser.parse_args()

    common_config, inst_config = read_config(parser, args.instrument)

    if operation != 'remove':
        args.purge = False

    if ((args.login is None) and
       (args.life_number is None) and
       (args.purge is False)):

        print(parser.error("You must specify the user by either"
                           " login (username) or life/guest number"))

    att_names = list(inst_config['rights'].keys())

    if args.right.lower() not in att_names:
        print(parser.error("You must specify a right from the options:"
                           " {}".format((', '.join(att_names)).upper())))

    right = args.right.lower()
    group_name = inst_config['rights'][right]

    with ADObjects(common_config['server'],
                   authenticate=True,
                   username=args.username,
                   ca_certs_file=common_config.get('ldap_ca_cert', None),
                   group_search=common_config['group_search'],
                   user_search=common_config['user_search']) as ad:

        # Get the beamlie group
        user = None

        group = ad.get_group_by_samaccountname(group_name)
        if len(group) != 1:
            raise RuntimeError("Unable to find correct group for users")

        if args.login is not None:
            user = ad.get_user_by_samaccountname(args.login)
            if len(user) == 0:
                raise RuntimeError("Unable to find user {}, please check."
                                   .format(args.login))
            if len(user) != 1:
                raise RuntimeError("Login (Username) {} is not unique. "
                                   "Please check.".format(args.login))

            user = user[0]

        if args.life_number is not None:
            user = ad.get_user_by_id(args.life_number)
            if len(user) == 0:
                raise RuntimeError("Unable to find user with life/guest"
                                   " number {}, please check."
                                   .format(args.life_number))
            if len(user) != 1:
                raise RuntimeError("Life/Guest number {} is not unique."
                                   " Please check."
                                   .format(args.life_number))

            user = user[0]

        if args.purge:
            user = ad.get_group_members(inst_config[group_name])

        group = group[0]

        if operation == "add":
            try:
                ad.add_user_to_group_by_dn(group['distinguishedName'],
                                           user['distinguishedName'])
            except LDAPInsufficientAccessRightsResult:
                raise RuntimeError("Error adding user to group, "
                                   "check you have the correct "
                                   "permission.") from None

            print("\nSuccessfully added right {} to user \"{}\""
                  " for instrument {}\n"
                  .format(right.upper(), user['displayName'],
                          inst_config['name'].upper()))

        if (operation == "remove") and (args.purge is False):
            try:
                ad.remove_user_from_group_by_dn(group['distinguishedName'],
                                                user['distinguishedName'])
            except LDAPInsufficientAccessRightsResult:
                raise RuntimeError("Error removing user from group, "
                                   "check you have the correct "
                                   "permission.") from None

            print("\nSuccessfully removed right {} from user \"{}\""
                  " for instrument {}\n"
                  .format(right.upper(), user['displayName'],
                          inst_config['name'].upper()))

        if (operation == "remove") and (args.purge is True):
            user_dn = [(u['distinguishedName'], u['displayName'])
                       for u in user]

            try:
                print('')
                for u in user_dn:
                    print("Removing user : {}".format(u[1]))
                    ad.remove_user_from_group_by_dn(
                        group['distinguishedName'], u[0]
                    )

            except LDAPInsufficientAccessRightsResult:
                raise RuntimeError("Error removing user from group, "
                                   "check you have the correct "
                                   "permission.") from None

            print("\nSuccessfully removed all users"
                  " for instrument {} with right '{}'\n"
                  .format(inst_config['name'].upper(),
                          right.upper()))


def n2sn_add_user():
    n2sn_change_user('add')


def n2sn_remove_user():
    n2sn_change_user('remove')


def n2sn_search_user():

    parser = base_argparser(
        'Add user to instrument users list',
        False
    )

    parser.add_argument(
        '--surname', dest='surname', action='store',
        help='Surname of user',
    )

    parser.add_argument(
        '--givenname', dest='givenname', action='store',
        help='Given name (forename) of user',
    )

    type_group = parser.add_mutually_exclusive_group()
    type_group.add_argument(
        '--guest', dest='type', action='store_const',
        const='LT',
        help='Limit to accounts that are NSLS-II guests'
    )
    type_group.add_argument(
        '--staff', dest='type', action='store_const',
        const='PS',
        help='Limit to accounts that are NSLS-II staff'
    )
    type_group.add_argument(
        '--cfn', dest='type', action='store_const',
        const='NC',
        help='Limit to accounts that are CFN staff'
    )
    type_group.add_argument(
        '--cfn-user', dest='type', action='store_const',
        const='XX',
        help='Limit to accounts that are CFN users'
    )

    args = parser.parse_args()

    common_config, inst_config = read_config(parser, no_inst=True)

    if ((args.surname is None) and
       (args.givenname is None) and
       (args.type is None)):

        # Thats a lot of users!
        print(parser.error("You must limit the search!"
                           " Do you really want ALL users?"))

    table = n2sn_list_user_search_as_table(
        common_config['server'],
        common_config['group_search'].strip('"'),
        common_config['user_search'].strip('"'),
        args.surname, args.givenname, args.type,
        ca_certs_file=common_config.get('ldap_ca_cert', None),
    )

    print(table)
