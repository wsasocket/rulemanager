"""定义个个类型文件所需要的数据结构和基本属性及方法"""
import re


class DataFromFile(object):

    def __init__(self, filename):
        self.filename = filename

    def load(self):
        # open file and load data structs
        pass

    def get_record_size(self):
        # return record size
        pass


class Rule(object):
    def __init__(self, line):
        self._line = line
        self._sid = 0
        self._rev = 0
        self._ref_cve = str()
        self._ref_url = str()
        self._ref_bid = str()
        self._ref_nessus = str()
        self._classify = str()
        self._msg = str()
        self._enable = True
        self.parse_line(line)

    def parse_line(self, rule_string):
        sid_pattern = r'sid\s*:\s*([\d]{1,10})\s*;'
        rev_pattern = r'rev\s*:\s*([\d]{1,3})\s*;'
        msg_pattern = r'msg\s*:\"(.*?)\"\s*;'
        class_pattern = r'classtype\s*:(.*?)\s*;'
        ref_cve_pattern = r'reference\s*:cve,([\d]{4}-[\d]{3,7})\s*;'
        ref_url_pattern = r'reference\s*:url,(.*?)\s*;'
        ref_bid_pattern = r'reference\s*:bugtraq,([\d]{2,7})\s*;'
        ref_nessus_pattern = r'reference\s*:nessus,([\d]{2,7})\s*;'
        r = re.search(sid_pattern, rule_string)
        if r:
            self._sid = r.group(1)
        else:
            # print('Can not get rules\'s sid:\n{}'.format(rule_string))
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
            self._rev = r.group(1)

        r = re.search(ref_cve_pattern, rule_string)
        if r:
            self._ref_cve = 'CVE-{}'.format(r.group(1))

        r = re.search(ref_url_pattern, rule_string)
        if r:
            self._ref_url = 'https://{}'.format(r.group(1))

        r = re.search(ref_bid_pattern, rule_string)
        if r:
            self._ref_bid = r.group(1)

        r = re.search(ref_nessus_pattern, rule_string)
        if r:
            self._ref_nessus = r.group(1)
        return True

    @property
    def text(self):
        return self._line

    @property
    def revision(self):
        return int(self._rev)

    @property
    def sid(self):
        return int(self._sid)

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

    @property
    def bid(self):
        return self._ref_bid

    @property
    def nessus(self):
        return self._ref_nessus


class RuleSet(DataFromFile):
    '''ips 规则文件的基本定义、属性、方法'''

    def __init__(self, filename):
        super(RuleSet, self).__init__(filename)
        self._rule = list()
        self._load()

    def _load(self):
        with open(self.filename, 'r', encoding='utf-8') as fp:
            for line in fp:
                # if line.startswith("#") or len(line)<3:
                #     continue
                try:
                    r = Rule(line.strip('\n '))
                except ValueError:
                    continue
                else:
                    self._rule.append(r)

    def get_record_size(self):
        return len(self._rule)

    # def get_rules(self):
    #     if len(self._rule) == 0:
    #         return None
    #     for i in self._rule:
    #         yield i

    def __iter__(self):
        if len(self._rule) == 0:
            return None
        for i in self._rule:
            yield i

    def __getitem__(self, key):
        if isinstance(key, int):
            for i in self._rule:
                if key == i.sid:
                    return i
        raise KeyError('Only index with integer as sid ')


# class ClassificationName(object):
#     def __init__(self, line):
#         self._name = str()
#         self._describe = str()
#         self._priority = 0
#         if not self.parse_line(line):
#             raise ValueError("Line data parse error:\n {}".format(line))
#
#     def parse_line(self, line):
#         pattern = r'config classification:\s*(.*?),(.*?),([\d]{1,2})'
#         r = re.search(pattern, line)
#         if r:
#             self._name = r.group(1)
#             self._describe = r.group(2)
#             self._priority = int(r.group(3))
#             return True
#         return False
#
#     @property
#     def name(self):
#         return self._name
#
#     @property
#     def describe(self):
#         return self._describe
#
#     @property
#     def priority(self):
#         return self._priority


class ClassificationSet(DataFromFile):

    def __init__(self, filename):
        super(ClassificationSet, self).__init__(filename)
        self._classification = list()

    def load(self):

        with open(self.filename, 'r') as fp:
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

    def get_record_size(self):
        return len(self._classification)

    def get_classification(self):
        if len(self._classification) == 0:
            return None
        for i in self._classification:
            yield i


# class TagName(object):
#     def __init__(self, line):
#         self._name = str()
#         self._describe = str()
#         self._id = 0
#         if not self.parse_line(line):
#             raise ValueError("Line data parse error:\n {}".format(line))
#
#     def parse_line(self, line):
#         part = line.split(':')
#         if len(part) == 3:
#             self._id = int(part[0])
#             self._name = part[1]
#             self._describe = part[2]
#             return True
#         return False
#
#     @property
#     def name(self):
#         return self._name
#
#     @property
#     def describe(self):
#         return self._describe
#
#     @property
#     def id(self):
#         return self._id


class TagSet(DataFromFile):

    def __init__(self, filename):
        super(TagSet, self).__init__(filename)
        self._tags = list()
        self._tag_id = list()

    def load(self):

        with open(self.filename, 'r') as fp:
            for line in fp:
                line = line.strip('\n ')
                if line.startswith("#"):
                    continue
                else:
                    part = line.split(':')
                    if len(part) == 3:
                        self._tags.append({'id': int(part[0]), 'name': part[1], 'describe': part[2]})
                        self._tag_id.append(int(part[0]))

    def get_record_size(self):
        return len(self._tags)

    @property
    def tag_id(self):
        return self._tag_id

    def __getitem__(self, key):
        if len(self._tags) == 0:
            return None

        if isinstance(key, int):
            for i in self._tags:
                if i.id == key:
                    return i['id'], i['name'], i['describe']
        # if isinstance(key, str):
        #     for i in self._tags:
        #         if i.name == key:
        #             return i['id'], i['name'], i['describe']


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
        self._content = 'Version:\n{}\n--\nTotal number of signatures:\n{:d}\n--\nBuild Date:\n{}\n--\nDescription:\n{}\n--'.format(
            self._version, self._rule_count, self._build_date, self._describe)
        return self._content

    def dumpfile(self):
        with open(self._filename, 'w') as fp:
            fp.write(self._content)

    @property
    def build_date(self):
        return self._build_date

    @property
    def ver(self):
        return self._version

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

# class TagMap(object):
#     def __init__(self, filename):
#         self._content = dict()
#         with open(filename, 'r') as fp:
#             for line in fp:
#                 line = line.strip("\n ")
#                 k, v = line.split(':')
#                 self._content[int(k)] = [int(x) for x in v.split(',')]
#
#     def __getitem__(self, sid):
#         # 返回当前sid的tag列表
#         if isinstance(sid, int):
#             if sid in self._content.keys():
#                 return self._content[sid]
#             else:
#                 raise KeyError("Tag for Sid:{:d} NOT found".format(sid))
#         else:
#             raise KeyError("Sid should be integer")
#
#     def tag_exist(self, sid):
#         if not isinstance(sid, int):
#             raise KeyError("Sid should be integer")
#         if sid in self._content.keys():
#             return True
#         else:
#             return False
