import psutil
import socket
import struct
from tqdm import tqdm
from functools import partial
from multiprocessing import Pool

# 网卡配置信息
# ip地址，mac地址，子网掩码，广播地址
net_if_addrs = psutil.net_if_addrs()

print(net_if_addrs['en0'][0][1])
print(net_if_addrs['en0'][0][2])

# python十进制转二进制，可指定位数
def int2bin(n, count=24):
    """returns the binary of integer n, using count number of digits"""
    return "".join([str((n >> y) & 1) for y in range(count-1, -1, -1)])


def get_my_ip():
    return net_if_addrs['lo0'][0][1]


def get_my_netmask():
    return net_if_addrs['lo0'][0][2]

# {'lo': [snicaddr(family=2, address='127.0.0.1', netmask='255.0.0.0', broadcast=None, ptp=None), snicaddr(family=10, address='::1', netmask='ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', broadcast=None, ptp=None), snicaddr(family=17, address='00:00:00:00:00:00', netmask=None, broadcast=None, ptp=None)],...}

# inet_ntoa转换32位打包的ipv4地址为ip地址的标准点号分隔字符串表示
# htonl 32位主机字节序转换成网络序
def int2ip(ip):
    return socket.inet_ntoa(struct.pack('I', socket.htonl(ip)))  # 先从网络字节序的数字转换为ip地址


# ntohl 32位网络序转换成主机字节序
# inet_aton 将32位字符串ipv4转为32位打包的二进制格式
def ip2int(ip_str):
    return socket.ntohl(struct.unpack("I", socket.inet_aton(str(ip_str)))[0])  # 先将ip地址字符串转换为整数值

def cal_ip_range(ip_str, netmask_str):  # 127.0.0.1  # 255.0.0.0
    ip_str_l = ip_str.split('.')
    netmask_str_l = netmask_str.split('.') # 子网掩码连续全1的是网络地址，后面的是主机地址

    print("ip:%s" % ip_str_l)
    print("netmask:%s" % netmask_str_l)

    # 网络地址 = IP地址和子网掩码进行与运算
    net_addr_l = []
    for i in range(len(ip_str_l)):
        net_addr_l.append(int(ip_str_l[i]) & int(netmask_str_l[i]))
    print("网络地址:")
    print(net_addr_l)

    # 根据netmask找最后几位是0，即有几位作为主机号，记作host_no_len
    host_no_len = 0
    flag = False
    for i in range(len(netmask_str_l) - 1, -1, -1):
        bin_t = int2bin(int(netmask_str_l[i]), count=8)
        if flag is True:
            break
        for i in range(len(bin_t)-1, -1, -1):
            if bin_t[i] == '0':
                host_no_len += 1
            else:
                flag = True
                break
    print("主机号位数：%d" % host_no_len)

    # 主机的个数 = 2^host_no_len - 2

    # 广播地址 = 网络地址部分不变，主机地址变为全1
    broadcast_l = net_addr_l.copy()  # 要加copy，否则，这两个值的改变是同步的

    host_no_len_t = host_no_len
    for i in range(len(broadcast_l)-1, -1, -1):
        if host_no_len_t <= 0:
            break
        if host_no_len_t <= 8:
            broadcast_l[i] += 2 ** host_no_len_t - 1
        else:
            broadcast_l[i] += 2 ** 8 - 1
        host_no_len_t -= 8

    print("广播地址broadcast_l:")
    print(broadcast_l)

    ip_start = str(net_addr_l[0])
    for i in range(len(net_addr_l) - 1):
        ip_start += "." + str(net_addr_l[i + 1])

    ip_end = str(broadcast_l[0])
    for i in range(len(broadcast_l) - 1):
        ip_end += "." + str(broadcast_l[i + 1])
    return ip_start, ip_end


def _check_host_state(ip_addr):
    current_ip = int2ip(ip_addr)
    try:
        # 创建一个新的通讯端点
        # IPv4, TCP, protocol default value is 0
        m_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # print(m_socket.gettimeout())
        m_socket.settimeout(400)
        m_socket.connect((current_ip, 135))
        m_socket.close()
        return "host open:%s" % current_ip
    except socket.error:
        return "host closed:%s" % current_ip


def single_process_check_host_states(ip_start_and_ip_end):
    print(ip_start_and_ip_end)
    ip_start, ip_end = ip_start_and_ip_end
    ip_start_int = ip2int(ip_start)
    ip_end_int = ip2int(ip_end)
    # print(ip_start_int, ip_end_int)

    sub_ans_list = []
    for i in range(ip_start_int, ip_end_int):
        ans = _check_host_state(i)
        # print(ans)
        sub_ans_list.append(ans)
    return sub_ans_list


def multi_process_check_host_states(ip_start, ip_end):
    n_processor = 256
    n_hosts_single = 2
    ip_list = [i for i in range(ip2int(ip_start) + 1, ip2int(ip_end))]
    # only to test
    # ip_list = [i for i in range(ip2int(ip_start) + 1, ip2int(ip_start) + 20)]
    sub_ips_list = [ip_list[i: i + n_hosts_single] for i in range(0, len(ip_list), n_hosts_single)]
    job = Pool(n_processor).imap(single_process_check_host_states, sub_ips_list)
    ans_list = list(tqdm(job, "Testing", len(sub_ips_list), unit="test one file part", ncols=60))
    ans_unfold = []
    for ans in ans_list:
        ans_unfold.extend(ans)
    with open("ans.txt", 'w') as f:
        f.write(str(ans_unfold))


def scan():

    # step1: get my ip
    my_ip_address = get_my_ip()

    # step2: get my netmask
    my_netmask = get_my_netmask()

    # step3: calculate the range in the net, ip_start, ip_end
    ip_start, ip_end = cal_ip_range(my_ip_address, my_netmask)
    print(ip_start, ip_end)

    # step4: check these hosts' states in that range and save the active ones
    multi_process_check_host_states(ip_start, ip_end)
    # single_process_check_host_states([ip_start, ip_end])


if __name__ == "__main__":
    scan()

