from data_model import Rule, Version, Document
import os
import re


class RootDirScan(object):
    CLASSIFICATION = 'classification.config'
    TAG_CONFIG = 'tag.config'
    VERSION_CONFIG = 'ips_sigver.txt'
    DOC_ROOT = 'docs'
    TAG_ROOT = 'tags'

    def __init__(self, root):
        self._root = root
        self._status = {'tag_index': False, 'tag_config': False, 'classification': False, 'version': [],
                        'rules': [], 'current_ver': False, 'tag_root': False, 'doc_root': False}
        self._current_version = None
        version_pattern = r'^([\d].[\d].[\d]{1,2}.[\d]{1,2})$'
        with os.scandir(self._root) as it:
            for entry in it:
                if entry.is_file() and entry.name == RootDirScan.CLASSIFICATION:
                    self._status['classification'] = True
                if entry.is_file() and entry.name == RootDirScan.TAG_CONFIG:
                    self._status['tag_config'] = True
                if entry.is_file() and entry.name == RootDirScan.VERSION_CONFIG:
                    self._current_version = Version(os.path.join(self._root, entry.name))
                    self._status['current_ver'] = True
                if not entry.name.startswith('.') and entry.is_dir():
                    r = re.search(version_pattern, entry.name)
                    if r:
                        self._status['version'].append(r.group(1))
                    elif RootDirScan.TAG_ROOT == entry.name:
                        self._status['tag_root'] = True
                    elif RootDirScan.DOC_ROOT == entry.name:
                        self._status['doc_root'] = True

                self._status['version'].sort(reverse=True)
                if entry.is_file() and entry.name.endswith('.rules'):
                    self._status['rules'].append(entry.name)

        if self._status['tag_config'] and self._status['current_ver'] and self._status['classification'] and \
                self._status['doc_root'] and self._status['tag_root']:
            if len(self._status['rules']) == 0:
                raise ValueError("Not Found any rule file!")
            if len(self._status['version']) == 0:
                raise ValueError("Not Found any old version backup!")
        else:
            raise ValueError("Pls check all files and directories!")

    def get_rule_files(self):
        if len(self._status['rules']) == 0:
            return None
        # for i in self._status['rules']:
        #     yield i
        return self._status['rules']

    def get_version_list(self):
        return self._status['version']

    def get_current_version(self):
        return self._current_version

    def get_root(self):
        return self._root


class RuleManager(object):
    def __init__(self, root_manager):
        # self._root = root
        self._scanner = root_manager
        self._rules_set = dict()
        for f in self._scanner.get_rule_files():
            self._rules_set[f] = list()
            with open(os.path.join(self._scanner.get_root(), f), 'r') as fp:
                for line in fp:
                    line = line.strip('\n\r ')
                    try:
                        self._rules_set[f].append(Rule(line))
                    except ValueError:
                        continue

    def __getitem__(self, item):
        if isinstance(item, str):
            if item in self._rules_set.keys():
                return self._rules_set[item]
            else:
                raise KeyError('Key:\'{}\' Not in rule file list'.format(item))
        if isinstance(item, int):
            for fn in self._rules_set.keys():
                for r in self._rules_set[fn]:
                    if r.sid == item:
                        return r

    @property
    def size(self):
        count = 0
        for k, v in self._rules_set.items():
            count += len(v)
        return count

    def __iter__(self):
        for k, v in self._rules_set.items():
            for r in v:
                yield k, r


class DocumentManager(object):
    # NOT load all doc file into memory
    def __init__(self, doc_root):
        self._doc_root = doc_root
        self._doc_index = list()
        self._doc_list = list()
        self.scan_document()

    def scan_document(self):
        # get a doc list by sid
        doc_file_pattern = r'^([\d]{2,9})\.txt$'
        with os.scandir(self._doc_root) as it:
            for entry in it:
                if entry.is_file():
                    r = re.search(doc_file_pattern, entry.name)
                    if r:
                        self._doc_index.append(int(r.group(1)))

    def _get_by_sid(self, sid):

        if not isinstance(int(sid), int):
            raise KeyError("Sid should be integer")
        for i in self._doc_list:
            if i.sid == sid:
                return i

        d = Document(sid)
        if int(sid) in self._doc_index:
            d.load_doc(self._doc_root)
        else:
            d.new_doc(self._doc_root)
            self._doc_index.append(sid)
        self._doc_list.append(d)
        return d

    def doc_exist(self, sid):
        if not isinstance(sid, int):
            raise KeyError("Sid should be integer")
        # 触发清理内存的行为
        erase = list()
        for i, v in enumerate(self._doc_list):
            if v.status == Document.DOC_SAVE:
                erase.append(i)
        erase.sort(reverse=True)
        for i in erase:
            self._doc_list.pop(i)

        if sid in self._doc_index:
            return True
        else:
            return False

    @property
    def size(self):
        return len(self._doc_index)

    def __getitem__(self, item):
        return self._get_by_sid(item)

    @property
    def doc_list(self):
        return self._doc_index
