# cmp tow version rules
# get new delete and modify files
# cmp current version rules ,give suggest
import os
import re

NEW_VERSION_RULES = r'C:\Snort\rules2'
OLD_VERSION_RULES = r'C:\Snort\rules'
CURRENT_RULES = r'C:\Snort\rules3'
NEW_DICT = dict()
OLD_DICT = dict()
CURRENT_DICT = dict()


def get_rules_list(path):
    with os.scandir(path) as it:
        for entry in it:
            if entry.is_file() and entry.name.endswith('.rules'):
                yield entry.name


def isRules(line):
    P1 = r'sid:(\d+);'
    #     P2 = r'rev:\d+;';
    P3 = r'^alert'
    P4 = r'^#\s*alert'
    en = None
    r = re.search(P3, line)
    if not r:
        en = False
    r = re.search(P4, line)
    if not r:
        en = True
    if en is None:
        # 没有发现alert，说明不是规则
        return en, None
    r = re.findall(P1, line)
    if len(r) == 1:
        # 有alert sid，基本可以认定是规则
        return en, r[0]
    else:
        return None, None


if __name__ == '__main__':
    for f in get_rules_list(NEW_VERSION_RULES):
        # f仅仅是文件名，不带有目录信息
        new_file = os.path.join(NEW_VERSION_RULES, f)
        old_file = os.path.join(OLD_VERSION_RULES, f)
        NEW_DICT.clear()
        OLD_DICT.clear()
        # 获取相同文件中的 sid：isEnable对
        with open(new_file) as fp:
            for line in fp:
                en, sid = isRules(line)
                if sid and en:
                    NEW_DICT[sid] = en
        with open(old_file) as fp:
            for line in fp:
                en, sid = isRules(line)
                if sid and en:
                    OLD_DICT[sid] = en
        print("**File: {}**".format(f))
        new_sids = list()
        for k in NEW_DICT.keys():
            if k in OLD_DICT.keys() and OLD_DICT[k] == NEW_DICT[k]:
                # 相同无变化
                pass
            if k not in OLD_DICT.keys() and NEW_DICT[k]:
                # 发现新的在用规则
                print('- NEW RULES: {}'.format(k))
                new_sids.append(k)
            if k in OLD_DICT.keys() and not NEW_DICT[k]:
                # 旧的规则被禁止
                print('- DISABLE RULES: {}'.format(k))
            if k in OLD_DICT.keys() and NEW_DICT[k] and not OLD_DICT[k]:
                # 旧规则被重新启用（虽然可能性不大）
                print('- REENABLE RULES: {}'.format(k))
        # 打印出新增加的在用规则
        with open(new_file) as fp:
            for line in fp:
                en, sid = isRules(line)
                if sid in new_sids:
                    print('```\n{}```'.format(line))
