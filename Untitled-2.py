import re
def robot_translater(line):
    chn={'Code Execution attempt':'代码执行企图',
         'compromise download': '可疑的下载','compromise fingerprinting': '可疑的操作指纹','configuration file download attempt': '配置文件下载',
         'outbound connection': '对外链接流量','process injection command':'进程注入命令','successful ping response':'成功的ping响应','outbound email attempt':'外联尝试email方式',
         'outbound POST attempt':'外联尝试POST方式','exfiltration attempt':'信息泄露企图','HTTP Response':'HTTP 响应','handshake beacon':'握手信标',
         'plugins download attempt':'插件下载企图','Runtime Detection':'检测到正在运行','inbound service request detected':'检测到内联方向服务请求',
         'outbound request detected':'检测到外联请求','outbound communication attempt':'尝试对外联系通信','connection attempt':'尝试连接',
         'system information disclosure':'系统信息泄露','heartbeat':'心跳数据','inbound payload download':'内联方向负载下载','outbound connection attempt':'对外尝试链接',
         'connection to malware sinkhole':'连接到恶意软件挖的坑','remote conn client-to-server':'客户端到服务器端的远程链接','upload file client-to-server':'客户端到服务器端的上传文件',
         'download file client-to-server':'客户端到服务器端的下载文件','execute file client-to-server':'客户端到服务器端的执行程序',
         'stack exhaustion DoS attempt':'栈耗尽型拒绝服务尝试','man-in-the-middle exploitation attempt':'中间人攻击利用尝试',
         'parameter denial of service attempt':'参数拒绝服务尝试','chunk parsing denial of service attempt':'块解析拒绝服务尝试',
         'handling denial of service attempt':'处理拒绝服务尝试','denial of service attempt':'拒绝服务尝试',
         'file attachment detected':'检测到文件附件','file download request':'文件下载请求',
         'file magic detected':'检测到文件特征码','remote code execution attempt':'尝试远程代码执行',
         'Malformed Function Code Execution':'畸形函数代码执行','Freed Memory Heap Corruption':'释放的内存堆损坏',
         'allows remote attackers to obtain potentially sensitive informationt':'允许远程攻击者获取潜在敏感信息的可能',
         'memory corruption attempt':'内存损坏尝试','bypass attempt':'绕过尝试',
         'privilege escalation attempt':'权限提升尝试','information disclosure attempt':'信息泄露尝试',
         'integer overflow attempt':'整数溢出企图','string overflow attempt':'字符串溢出企图',
         'buffer overflow attempt':'缓冲区溢出企图','heap overflow attempt':'堆溢出企图',
         'NULL Pointer Dereference attempt':'空指针取消引用尝试',
         'directory traversal attempt':'目录穿越企图','Command Execution attempt':'命令执行企图'
        }
    chn_pattern=dict()
    for p in chn.keys():
        chn_pattern[p] = re.compile(p,re.IGNORECASE)
    
    for k,v in chn_pattern.items():
        if v.search(line):
            return v.sub(chn[k],line)
    return line

if __name__ == "__main__":
    ll = 'FILE-OFFICE Microsoft Access arbitrary code execution attempt'
    # pattern = re.compile('Code Execution attempt',re.IGNORECASE)
    # m = pattern.search(ll)
    print(robot_translater(ll))