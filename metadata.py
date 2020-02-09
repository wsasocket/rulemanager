import re
from functools import reduce
r1 = r'alert tcp $EXTERNAL_NET $FILE_DATA_PORTS -> $HOME_NET any (msg:"BROWSER-IE Microsoft Internet Explorer JavaScript engine downgrade detected"; flow:to_client,established; file_data; content:"Jscript.Compact"; fast_pattern:only; content:"IE=EmulateIE8"; metadata:policy balanced-ips drop, policy max-detect-ips drop, policy security-ips drop, service ftp-data, service http, service imap, service pop3; classtype:policy-violation; sid:48699; rev:2;)'
def get_rules_from_file(filename):
    collection=set()
    with open(filename) as fp:
        for line in fp:
            for i in (x:=get_metadata(line)):
                collection.add(i)
    return collection

def get_metadata(rule):
    pattern = r'metadata\s*:(.*?);'
    rexp=re.compile(pattern)
    r=rexp.search(rule)
    content = str()
    if r:
        content = r.group(1)
    content = map(str.strip,content.split(','))
    return content

def collect_metadata_init(first,second):
    if first is None:
        context=dict()
        # context['key']=set()
        # context['value']=set()
        t = second.split(' ')
        if len(t) <2:
            print(f'kvpair parse error:{t}')
        else:
            if t[0] not in context.keys():
                context[t[0]]= set() 
            context[t[0]].add(' '.join(t[1:]))    
        return context
    if isinstance(first,dict):
        t = second.split(' ')
        if len(t) <2:
            print(f'kvpair parse error:{second}')
        else:
            if t[0] not in first.keys():
                first[t[0]] = set()  
            first[t[0]].add(' '.join(t[1:]))
        return first
    

if __name__ == "__main__":
    for k,v in (r:=reduce(collect_metadata_init,get_rules_from_file('all2.201.rules'),None)).items():
        print(k,v)
        
