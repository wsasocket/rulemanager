'''所有数据结构的模型'''

import re
import os


class Rule(object):
    def __init__(self, line):
        self._line = line
        self._sid = 0
        self._rev = 0
        self._ref_cve = str()
        self._ref_url = str()
        self._classify = str()
        self._msg = str()
        self._enable = True
        if not self.parse_line(line):
            raise ValueError("Line data parse error:\n {}".format(line))

    def parse_line(self, rule_string):
        sid_pattern = r'sid\s*:\s*([\d]{1,10})\s*;'
        rev_pattern = r'rev\s*:\s*([\d]{1,3})\s*;'
        msg_pattern = r'msg\s*:\"(.*?)\"\s*;'
        class_pattern = r'classtype\s*:(.*?)\s*;'
        ref_cve_pattern = r'reference\s*:cve,([\d]{4}-[\d]{3,7})\s*;'
        ref_url_pattern = r'reference\s*:url,(.*?)\s*;'
        r = re.search(sid_pattern, rule_string)
        if r:
            self._sid = int(r.group(1))
        else:
            print('Can not get rules\'s sid:\n{}'.format(rule_string))
            raise ValueError("Line data parse can not get sid :\n ")

        if rule_string.startswith('#'):
            self._enable = False

        r = re.search(msg_pattern, rule_string)
        if r:
            self._msg = r.group(1)
        else:
            raise ValueError("Line data parse can not get msg :\n ")

        r = re.search(class_pattern, rule_string)
        if r:
            self._classify = r.group(1)
        else:
            raise ValueError("Line data parse can not get classify :\n ")

        r = re.search(rev_pattern, rule_string)
        if r:
            self._rev = int(r.group(1))

        r = re.search(ref_cve_pattern, rule_string)
        if r:
            self._ref_cve = 'CVE-{}'.format(r.group(1))

        r = re.search(ref_url_pattern, rule_string)
        if r:
            self._ref_url = 'https://{}'.format(r.group(1))

        return True

    @property
    def text(self):
        return self._line

    @property
    def revision(self):
        return self._rev

    @property
    def sid(self):
        return self._sid

    @property
    def enable(self):
        return self._enable

    @property
    def cve(self):
        return self._ref_cve

    @property
    def ref(self):
        return self._ref_url

    @property
    def msg(self):
        return self._msg

    @property
    def classify(self):
        return self._classify


class Classification(object):
    def __init__(self, filename):
        self._classification = list()
        self._filename = filename

    def load(self):
        with open(self._filename, 'r') as fp:
            for line in fp:
                line = line.strip('\n ')
                if line.startswith("#"):
                    continue
                else:
                    pattern = r'config classification:\s*(.*?),(.*?),([\d]{1,2})'
                    r = re.search(pattern, line)
                    if r:
                        self._classification.append({'priority': int(r.group(3)), 'name': r.group(2),
                                                     'describe': r.group(1)})

    @property
    def all_names(self):
        return [x['name'] for x in self._classification]

    def __iter__(self):
        if len(self._classification) == 0:
            return None
        for i in self._classification:
            yield i

    def __len__(self):
        return len(self._classification)

    def __getitem__(self, item):
        for i in self._classification:
            if i['name'] == item:
                return i


class Document(object):
    DOC_CREATE = 0
    DOC_MODIFY = 1
    DOC_LOAD = 2
    DOC_SAVE = 3

    def __init__(self, sid):
        self._sid = sid
        self._info_dict = {'Summary': '', 'Impact': '', 'Detailed Information': '',
                           'Attack Scenarios': '', 'Ease of Attack': '', 'False Positives': 'N/A',
                           'False Negatives': 'N/A', 'Corrective Action': '', 'Contributors': '',
                           'Additional References': '', 'Affected Systems': ''}
        self._info_dict_EN = {'EN Summary': '', 'EN Impact': '', 'EN Detailed Information': '',
                              'EN Attack Scenarios': '', 'EN Ease of Attack': '', 'EN False Positives': 'N/A',
                              'EN False Negatives': 'N/A', 'EN Corrective Action': '', 'EN Contributors': '',
                              'EN Additional References': '', 'EN Affected Systems': ''}
        self._status = -1
        self._doc_root = None

    def load_doc(self, root):
        self._doc_root = root
        filename = os.path.join(root, '{:d}.txt'.format(self._sid))
        longline = str()
        with open(filename, 'r', encoding='gb2312') as fp:
            for line in fp:
                longline += line.strip('\n ')
        longline = longline[:-2]
        part = longline.split('--')
        for k in self._info_dict.keys():
            for i in part:
                if i.startswith(k):
                    self._info_dict[k] = i[len(k) + 1:]
        for k in self._info_dict_EN.keys():
            for i in part:
                if i.startswith(k):
                    self._info_dict_EN[k] = i[len(k) + 1:]

        self._status = Document.DOC_LOAD

    def new_doc(self, root):
        self._doc_root = root
        self._status = Document.DOC_CREATE

    def modify_doc(self, key, value):
        if key == 'CN':
            self._info_dict = value
        if key == 'EN':
            self._info_dict_EN = value
        self._status = Document.DOC_MODIFY

    def save(self):
        filename = os.path.join(self._doc_root, '{:d}.txt'.format(self._sid))
        with open(filename, 'w') as fp :
            line = 'Rule:\n\n--\nSid:\n{}\n--\n'.format(self._sid)
            fp.write(line)
            for k in self._info_dict.keys():
                line = '{}\n{}\n--\n'.format(k, self._info_dict[k])
                fp.write(line)
            for k in self._info_dict_EN.keys():
                line = '{}\n{}\n--\n'.format(k, self._info_dict_EN[k])
                fp.write(line)
        self._status = Document.DOC_SAVE

    def __str__(self):
        line = 'Rule:\n\n--\nSid:\n{}\n--\n'.format(self._sid)
        for k in self._info_dict.keys():
            line += '{}\n{}\n--\n'.format(k, self._info_dict[k])
        for k in self._info_dict_EN.keys():
            line += '{}\n{}\n--\n'.format(k, self._info_dict_EN[k])
        return line

    @property
    def doc_CN(self):
        return self._info_dict

    @property
    def doc_EN(self):
        return self._info_dict_EN

    @property
    def sid(self):
        return self._sid

    @property
    def status(self):
        return self._status


class Version(object):
    def __init__(self, filename):
        self._content = str()
        self._filename = filename
        self._build_date = str()
        self._version = str()
        self._describe = str()
        self._rule_count = str()
        longline = str()
        with open(filename, 'r') as fp:
            for line in fp:
                longline += line.strip('\n ')
        longline = longline[:-2]
        items = longline.split('--')
        for i in items:
            k, v = i.split(':')
            if k == 'Version':
                self._version = v
            if k == 'Total number of signatures':
                self._rule_count = int(v)
            if k == 'Build Date':
                self._build_date = v
            if k == 'Description':
                self._describe = v

    def __str__(self):
        self._content = 'Version:\n{}\n--\nTotal number of signatures:\n{:d}\n--\nBuild Date:\n{}\n--\nDescription:' \
                        '\n{}\n--'.format(self._version, self._rule_count, self._build_date, self._describe)
        return self._content

    def dumpfile(self):
        with open(self._filename, 'w') as fp:
            fp.write(self._content)

    @property
    def build_date(self):
        return self._build_date

    @property
    def ver(self):
        return  self._version

    @property
    def describe(self):
        return self._describe

    @property
    def count(self):
        return self._rule_count

    @build_date.setter
    def build_date(self, date):
        self._build_date = date

    @ver.setter
    def ver(self, ver):
        self._version = ver

    @describe.setter
    def describe(self, describe):
        self._describe = describe

    @count.setter
    def count(self, count):
        self._rule_count = count


# class TagConfig(object):
#
#     def __init__(self, filename):
#         self._filename = filename
#         self._tags = list()
#
#     def load(self):
#         with open(self._filename, 'r') as fp:
#             for line in fp:
#                 line = line.strip('\n ')
#                 if line.startswith("#"):
#                     continue
#                 else:
#                     part = line.split(':')
#                     if len(part) == 3:
#                         self._tags.append({'id': int(part[0]), 'name': part[1], 'describe': part[2]})
#
#     def get_record_size(self):
#         return len(self._tags)
#
#     @property
#     def all_names(self):
#         return [x['name'] for x in self._tags]
#
#     def __getitem__(self, key):
#         if len(self._tags) == 0:
#             return None
#
#         if isinstance(key, int):
#             for i in self._tags:
#                 if i['id'] == key:
#                     return i
#
#     def __iter__(self):
#         if len(self._tags) == 0:
#             return None
#         for i in self._tags:
#             yield i
#
#     def __len__(self):
#         return len(self._tags)