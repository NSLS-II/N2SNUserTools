from prettytable import PrettyTable
from .ldap import ADObjects
from .unix import adquery


table_order = ['displayName', 'sAMAccountName',
               'mail', 'description', 'employeeID']


def format_user_table(users):
    table = PrettyTable()
    table.field_names = ['Name', 'Login', 'E-Mail', 'Department',
                         'Life/Guest Number', 'Can Login']

    for user in users:
        row = [user[v] for v in table_order]
        try:
            result = adquery(user['sAMAccountName'])
        except OSError:
            row += ['ERROR']
        else:
            if result['zoneEnabled'] == 'true':
                row += ['Yes']
            else:
                row += ['']

        table.add_row(row)

    table.align['Name'] = 'l'
    table.align['Login'] = 'l'
    table.align['E-Mail'] = 'l'
    table.align['Code'] = 'c'
    table.align['Life Number'] = 'c'
    table.align['Can Login'] = 'c'

    return table


def n2sn_list_group_users_as_table(server, group_search, user_search,
                                   group):
    """List all users who are in the users group"""

    # Connect to LDAP to get group members

    with ADObjects(server, group_search, user_search,
                   authenticate=False) as ad:
        users = ad.get_group_members(group)

    return format_user_table(users)


def n2sn_list_user_search_as_table(server, group_search, user_search,
                                   surname, givenname, user_type):

    with ADObjects(server, group_search, user_search,
                   authenticate=False) as ad:
        users = ad.get_user_by_surname_and_givenname(
            surname, givenname, user_type
        )
    return format_user_table(users)
