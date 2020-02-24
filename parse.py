# 解析snort日志信息
import re
from functools import reduce
from csv import reader as csvReader
IDSFILE = r'c:\snort\log\alert.ids'
CSVFILE = r'C:\Users\Administrator\Documents\level.4.23.5.76533.csv'


def parseBlock(file):
    """拆分snort日志的报警文件，返回报警块的列表"""
    buffer = list()
    blocks = list()
    beginFlag = False

    with open(file) as fp:
        for line in fp:
            if line.startswith('[**]') or beginFlag:
                # 日志块的开始
                beginFlag = True
                buffer.append(line)
                if len(line) <= 2:
                    beginFlag = False
                    blocks.append(buffer.copy())
                    buffer.clear()
    return blocks


def parseAlert(blocks):
    """解析报警块的内容，返回需要的信息"""
    protocolPattern = r'(UDP|TCP|PROTO:(\d+)) TTL'
    ipportPattern = r'(\d+\.\d+\.\d+\.\d+(:\d+)*) -> (\d+\.\d+\.\d+\.\d+(:\d+)*)'
    sidPattern = r'\[\d+:(\d+):\d+\]'
    sid = None
    protocol = None
    ipport = None
    for block in blocks:
        if (r:= re.search(sidPattern, block)):
            sid = r.group(1)

        if (r:=re.search(ipportPattern, block)):
            ipport = r.group(0)

        if (r:= re.search(protocolPattern, block)):
            # if r.groups() == 2:
            #     pass
            # get protocol number
            protocol = r.group(1)
    return {'sid': sid, 'ipport': ipport, 'protocol': protocol}


def filterCSV(row):
    """过滤CSV数据中不符合要求的数据，比如表格头或者是数据错误的行，返回True/False
    这个函数是filter函数的回调函数，filter函数返回的是过滤后的列表"""
    colSid = 2
    colSrcIP = 6
    colSrcPort = 7
    colDstIP = 8
    colDstPort = 9
    colProtocol = 10
    ipPattern = r'(\d+\.\d+\.\d+\.\d+)'

    if re.search(ipPattern, row[colDstIP]) is None or re.search(ipPattern, row[colSrcIP]) is None:
        # raise Exception('Data Format Error ')
        return False
    else:
        return True


def buildCSVData(row):
    """解析CSV行数据，返回需要的信息"""
    colSid = 2
    colSrcIP = 6
    colSrcPort = 7
    colDstIP = 8
    colDstPort = 9
    colProtocol = 10
    sid = row[colSid]
    protocol = row[colProtocol]
    ipport = f'{row[colSrcIP]}:{row[colSrcPort]} -> {row[colDstIP]}:{row[colDstPort]}'
    return {'sid': sid, 'ipport': ipport, 'protocol': protocol}


def gatherInformationFromCSV(file):
    csv = open(file)
    data = csvReader(csv)
    return map(buildCSVData, filter(filterCSV, data))


def statisticsIpPorts(context, data):
    """统计函数，根据要求统计关心的数据。这个函数是reduce函数的回调函数，reduce函数返回汇总后的数据"""
    if context is None:
        ipports = set()
        ipports.add(data['ipport'])
        return ipports
    else:
        context.add(data['ipport'])
        return context


test1 = '''[**] [1:13287:13] OS-WINDOWS Microsoft Windows remote kernel tcp/ip igmp vulnerability exploit attempt [**]
[Classification: Attempted Administrator Privilege Gain] [Priority: 1] 
01/12-05:35:52.315751 1.21.46.170 -> 1.22.134.50
PROTO:002 TTL:255 TOS:0x0 ID:47142 IpLen:28 DgmLen:1060
IP Options (1) => RTRALT 
[Xref => http://technet.microsoft.com/en-us/security/bulletin/MS08-001][Xref => http://cve.mitre.org/cgi-bin/cvename.cgi?name=2007-0069]
'''
test2 = '''[**] [1:10064:11] SERVER-OTHER Peercast URL Parameter overflow attempt [**]
[Classification: Attempted User Privilege Gain] [Priority: 1] 
01/12-05:35:52.302680 1.21.77.46:21573 -> 1.22.80.191:7144
TCP TTL:255 TOS:0x0 ID:51433 IpLen:20 DgmLen:1090
***A**** Seq: 0xA12AD820  Ack: 0x2BD85887  Win: 0x3FFF  TcpLen: 20
[Xref => http://cve.mitre.org/cgi-bin/cvename.cgi?name=2006-1148][Xref => http://www.securityfocus.com/bid/17040]

'''
if __name__ == "__main__":
    blocks = parseBlock(IDSFILE)
    r = reduce(statisticsIpPorts, map(parseAlert, blocks), None)
    print(len(r))

    blocks = gatherInformationFromCSV(CSVFILE)
    r = reduce(statisticsIpPorts, blocks, None)
    print(len(r))
