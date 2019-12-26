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
    """返回值是 _en，_sid，_rev。假设一个规则中必须存在alert，msg，sid，rev这四个参数
    参数不够不足以构成规则，根据是alert还是‘#’开头代表规则的使能状态"""
    pattern1 = r'sid:(\d+);'
    pattern2 = r'rev:(\d+);'
    pattern3 = r'^(#)*\s*alert'

    _en = None
    _sid = None
    _rev = None

    m = re.match(pattern3, line)
    if m:
        _en = True if m.group(1) is None else False

    r = re.search(pattern1, line)
    if r:
        _sid = r.group(1)

    r = re.search(pattern2, line)
    if r:
        _rev = r.group(1)
    return _en, _sid, _rev



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
                en, sid, rev = isRules(line)
                if sid and en:
                    NEW_DICT[sid] = (en, rev)
        with open(old_file) as fp:
            for line in fp:
                en, sid, rev = isRules(line)
                if sid and en:
                    OLD_DICT[sid] = (en, rev)
        print("**File: {}**".format(f))
        new_sids = list()
        update_sids = list()
        disable_sids = list()
        # 判断逻辑
        for k in NEW_DICT.keys():
            if k in OLD_DICT.keys():
                if OLD_DICT[k] == NEW_DICT[k]:
                    # 相同无变化
                    pass
                else:
                    # 可能存在 en 或者 rev 的变化
                    if OLD_DICT[k][0] and not NEW_DICT[k][0]:
                        # 使能变化,新的规则库中，规则被禁止
                        print('- DISABLE RULES: #{}'.format(k))
                        disable_sids.append(k)
                    if not OLD_DICT[k][0] and NEW_DICT[k][0]:
                        # 重新被启用
                        pass
                    if int(OLD_DICT[k][1]) != int(NEW_DICT[k][1]):
                        # 版本升级
                        update_sids.append(k)

            if k not in OLD_DICT.keys() and NEW_DICT[k][0]:
                # 发现新的在用规则
                print('- NEW RULES: {}'.format(k))
                new_sids.append(k)
        # 打印出新增加的在用规则
        with open(new_file) as fp:
            print('-----add new------')
            for line in fp:
                en, sid, rev = isRules(line)
                if sid in new_sids:
                    print('```\n{}```'.format(line))
            print('-----update------')
            for line in fp:
                en, sid, rev = isRules(line)
                if sid in update_sids:
                    print('```\n{}```'.format(line))



