# checkout rules by sid
import os
import re

ROOT = r'd:\work\data\original'


def get_rules_list(path):
    for root, dirs, files in os.walk(path):
        for _file in files:
            if _file.endswith('.rules'):
                yield os.path.join(root, _file)


def checkout_list():
    return [1122, 13990, 17208, 19014, 21072, 21073, 27244, 27572, 32637, 39190, 39191, 41818, 41819, 42944, 46098, 46445, 47634, 48988, 49376, 532332, 600028, 600044, 620011, 620026]


if __name__ == "__main__":
    pattern = re.compile(r'sid:(\d+);')

    for f in get_rules_list(ROOT):
        with open(f) as fp:
            for line in fp:
                r = pattern.search(line)
                if not r:
                    continue
                if int(r.group(1)) in checkout_list():
                    _, tail = os.path.split(f)
                    print(f'{tail}:{line}')
