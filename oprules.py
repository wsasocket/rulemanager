# rules set operations

import getopt
import os
import re
import shutil
import sys
from types import GeneratorType

RULES_DIR = r'D:\work\data\original'
TARGET_DIR = r'D:\work\data\qianxin'


def get_rules_list(path):
    with os.scandir(path) as it:
        for entry in it:
            if entry.is_file() and entry.name.endswith('.rules'):
                yield entry.name


class OperationFactory(object):
    def __init__(self, data_file):
        self.data = None
        self._load_data_file(data_file)
        self.err = list()

    def _load_data_file(self, file):
        pass

    def op(self, _line):
        return _line

    def patch(self, file):
        return None

    def log(self, _msg, _level=1):
        # define info 1,warn 2,error,3
        if _level == 3:
            self.err.append(_msg)
        print(_msg)


class RemoveUseless(OperationFactory):
    """ oprules.py -o RemoveUseless\n oprules.py --operate=RemoveUseless
            remove has no content rules,remove any to any rules,remove ip icmp rules"""

    def __init__(self, data_file):
        super().__init__(data_file)

    def op(self, _line):

        if _line.strip(' ').startswith('#') or len(_line.strip('\n\r')) == 0:
            return _line

        if 'content:' not in _line:
            self.log('No Content remove {}'.format(_line))
            return '# {}'.format(_line)

        r = re.search(r'alert (tcp|udp) (.*) any -> (.*) any ', _line)
        if r:
            self.log('any to any remove {}'.format(_line))
            return '# {}'.format(_line)

        r = re.search(r'alert (icmp|ip) ', _line)
        if r:
            self.log('icmp or  ip type remove {}'.format(_line))
            return '# {}'.format(_line)
        return _line


class PatchRules(OperationFactory):
    """ oprules.py -o PatchRules -p patchfile\n oprules.py --operate=PatchRules --patchfile=patchfile
            patch file indicate file:rules"""

    def __init__(self, data_file):
        super().__init__(data_file)

    def _load_data_file(self, file):
        self.data = dict()
        pattern = r'(.*?).rules:(.*)'
        with open(file) as fp:
            for line in fp:
                r = re.match(pattern, line)
                if r:
                    path = '{}.rules'.format(r.group(1).strip(' '))
                    filename = os.path.basename(path)
                    # abspath = os.path.abspath(path)
                    # print(filename)
                    # print(abspath)
                    rule = r.group(2).strip(' ')
                    if filename in self.data.keys():
                        self.data[filename].append(rule)
                    else:
                        self.data[filename] = [rule]

    def patch(self, file):
        if file in self.data.keys():
            for r in self.data[file]:
                yield '{}\n'.format(r)


class EnableRules(OperationFactory):
    """ oprules.py -o EnableRules -s sidfile -e enable/disable\n oprules.py --operate=EnableRules --sidfile=sidfile
    --enable=enable/disable enable or disable rules sid file and enable flag should be present """

    def __init__(self, data_file):
        super().__init__(data_file)
        # self._load_data_file(data_file)

    def op(self, _line):
        sid = None
        r = re.findall(r'sid:(\d+);', _line)
        _line = _line.strip(' \n\r')
        if len(r) == 1:
            sid = r[0]
        if sid and int(sid) in self.data['enable']:
            self.log("{} in enable".format(sid), 1)
            if _line.startswith('#'):
                # disable status
                self.log('[+] {}'.format(sid), 1)
                # disable -> enable
                _line = _line[1:]
                _line = _line.strip(' ')
            else:
                self.log('[=] {}'.format(sid), 1)

        if sid and int(sid) in self.data['disable']:
            self.log("{} in disable".format(sid), 1)
            if _line.startswith('alert'):
                self.log('[-] {}'.format(sid), 1)
                # enable -> disable
                _line = '# {}'.format(_line)
            else:
                self.log('[=] {}'.format(sid), 1)

        return '{}\n'.format(_line)

    def _load_data_file(self, file):
        pattern = r'(#)*\s*(\d+)'
        self.data = {'enable': list(), 'disable': list()}
        with open(file) as fp:
            for _line in fp:

                r = re.match(pattern, _line)
                if r:
                    print(r.group(0))
                    if r.group(1) is None:
                        self.data['enable'].append(int(r[2]))
                    if r.group(1) == '#':
                        self.data['disable'].append(int(r[2]))


class ChangePriority(OperationFactory):
    """ oprules.py -o ChangePriority -c classfile\n oprules.py --operate=ChangePriority --classfile=classfile
            according to classification change the priority of rules,classification should be present"""

    def __init__(self, data_file):
        super().__init__(data_file)

    def op(self, _line):
        pattern = r'classtype\s*:\s*([a-z\-]+);'
        if _line.startswith('#'):
            return _line
        r = re.search(pattern, _line)

        if r:
            if r[1] in self.data.keys():
                # replace and set priority value
                pass
            else:
                self.log('classtype: {} can not be found'.format(r[1]), 3)
        else:
            self.log('classtype can not be found:{}'.format(_line), 3)

        return _line

    def _load_data_file(self, file):
        """ Demo: config classification: successful-admin,Successful Administrator Privilege Gain,1"""
        pattern = r'config classification:(.*?),(.*?),(\d+)'
        self.data = dict()
        with open(file) as fp:
            for _line in fp:
                if _line.startswith('#'):
                    continue
                r = re.match(pattern, _line)
                if r:
                    self.data[r.group(1).strip(' ')] = int(r.group(3))


def process_rules(path, op_instance):
    files = get_rules_list(os.path.join(RULES_DIR, path))
    for f in files:
        tmp_file = open(os.path.join(RULES_DIR, 'tmp.rules'), 'w')
        with open(os.path.join(RULES_DIR, path, f), 'r') as fp:
            # print(f)
            for line in fp:
                if len(line) < 6:
                    continue
                tmp_file.write(op_instance.op(line))
        # print(type(op_instance.patch))
        if isinstance(op_instance.patch(f), GeneratorType):
            for line in op_instance.patch(f):
                tmp_file.write(line)
        tmp_file.close()
        shutil.move(os.path.join(RULES_DIR, 'tmp.rules'), os.path.join(TARGET_DIR, path, f))


if __name__ == '__main__':

    registered_op = [ChangePriority, EnableRules, PatchRules, RemoveUseless]
    registered_op_name = [n.__name__.lower() for n in registered_op]
    operator = None
    datafile = None
    op_index = -1

    try:
        opts, args = getopt.getopt(sys.argv[1:], "o:p:s:c:h",
                                   ["operate=", "patchfile=", "sidfile=", 'classfile=', 'help'])
        # ':' means need parameter or means toggle
        if len(opts) == 0:
            opts = [('-h', '')]
        for opt, arg in opts:
            if opt in ('-h', '--help'):
                for c in registered_op:
                    print(c.__doc__)
                sys.exit()
            if opt in ('-o', '--operate'):
                operator = arg.lower()
                if operator not in registered_op_name:
                    raise getopt.GetoptError('operate should in {}'.format(registered_op_name))
            if opt in ('-p', '--patchfile'):
                datafile = arg
                if not os.path.isfile(datafile):
                    raise getopt.GetoptError('patchfile "{}" should a file'.format(datafile))

            if opt in ('-s', '--sidfile'):
                datafile = arg
                if not os.path.isfile(datafile):
                    raise getopt.GetoptError('sidfile "{}" should a file'.format(datafile))
            if opt in ('-c', '--classfile'):
                datafile = arg
                if not os.path.isfile(datafile):
                    raise getopt.GetoptError('classfile "{}" should a file'.format(datafile))

        op_index = registered_op_name.index(operator)
        if operator == 'patchrules' and datafile is None:
            raise getopt.GetoptError('Operation patchrule need --patchfile or -p parameter')

        if operator == 'enablerules' and datafile is None:
            raise getopt.GetoptError('Operation enablerules need --sidfile or -p parameter')

        if operator == 'changepriority' and datafile is None:
            raise getopt.GetoptError('Operation changepriority need --classfile or -c parameter')

    except getopt.GetoptError as e:
        print(e)
        sys.exit(2)

    if op_index >= 0:
        _op_instance = registered_op[op_index](datafile)
        process_rules('ips_rule', _op_instance)
        process_rules('waf_rule', _op_instance)
