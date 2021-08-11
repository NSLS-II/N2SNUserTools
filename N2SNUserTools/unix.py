import subprocess

adquery_cmd = '/usr/bin/adquery'
adquery_opts = ['enabled', 'unixname', 'samname', 'uid']
adquery_valid_tok = ['zoneEnabled', 'unixname', 'uid',
                     'samAccountName', 'accountLocked', 'accountDisabled']


def adquery(username):
    cmd = [adquery_cmd, 'user']
    cmd += ['--' + opt for opt in adquery_opts]
    cmd += [username]

    process = subprocess.run(cmd,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             universal_newlines=True)

    if process.returncode != 0:
        raise OSError("adquery call failed")

    # stdout = process.stdout.decode('UTF-8')
    stdout = process.stdout

    rtn = dict()
    for line in stdout.splitlines():
        tok = line.split(":")
        if tok[0] in adquery_valid_tok:
            rtn[tok[0]] = tok[1]

    return rtn
