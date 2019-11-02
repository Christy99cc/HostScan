# 基于Socket的扫描程序

一个基于Socket的扫描程序，识别局域网内活跃主机。

1. 动态扫描，即不规定IP地址，直接通过本机IP地址和本机子网掩码编程自动计算整个局域网其他主机号，依次扫描

2. 使用多进程进行并行扫描

3. 相关设置

（1）socket的timeout设为400，超过这个时间就认为没有连接成功，即主机不活跃。

（2）进程数量设为256，每个进程扫描2个主机。

这两个参数分别对应multi_process_check_host_states函数里的n_processor = 256

n_hosts_single = 2，可以根据需要进行修改。

（3）网卡的设置：修改en0为当前使用的网卡。
