from data_set import RootDirScan, DocumentManager, RuleManager

if __name__ == '__main__':
    init = RootDirScan('/Users/james/rules')
    print(init.get_current_version().ver)
    for i in init.get_version_list():
        print(i)
    rules = RuleManager(init)
    print(rules[16560].msg)
    print(rules.size)
    for f, r in rules:
        print(f, r.sid, r.msg)
