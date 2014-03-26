解析网络协议
==============

Version1
=========

解析IP协议
--------------------------
* `first.tcpdump`  为测试文件

  ``` bash
  sudo tcpdump -i wlp2s0 -nnvvXX -S 'host 115.29.172.134' -c1 -w 'first.tcpdump'
  ```

* erlang 环境中

  ``` erlang
  lc(parse_tcpdump, parse_ethernet, parse_ip).

  % return tuple
  parse_ip:ip_protocol_info("first.tcpdump").
  % print tuple
  parse_ip:parse_ip_protocol_info("first.tcpdump").
  ```

解析ICMP协议
-----------
* `icmp_xiaoyintong.tcpdump` 为request测试文件

  ``` bash
  sudo tcpdump -i wlp2s0 -nnvvXX -S 'host 115.29.172.134' -c1 -w 'icmp_xiaoyintong.tcpdump'
  ping www.xiaoyintong.com
  ```

  ``` erlang
  lc(parse_tcpdump, parse_ethernet, parse_ip, parse_icmp).

  % return tuple
  parse_icmp:icmp_protocol_info("icmp_xiaoyintong.tcpdump").
  % print tuple
  parse_icmp:print_icmp_protocol_info("icmp_xiaoyintong.tcpdump").
  ```

* `icmp_xiaoyintong_reply.tcpdump` 为reply测试文件

    ``` bash
    sudo tcpdump -i wlp2s0 -nnvvXX -S 'host 115.29.172.134 and icmp[icmptype]=icmp-echoreply' -c1 -w 'icmp_xiaoyintong_reply.tcpdump'
    ping www.xiaoyintong.com
    ```

    ``` erlang
  lc(parse_tcpdump, parse_ethernet, parse_ip, parse_icmp).

  % return tuple
  parse_icmp:icmp_protocol_info("icmp_xiaoyintong_reply.tcpdump").
  % print tuple
  parse_icmp:print_icmp_protocol_info("icmp_xiaoyintong_reply.tcpdump").
    ```

解析ARP协议
-----------
* `arp_request.tcpdump` 为request测试文件

  ``` bash
  sudo tcpdump -i wlp2s0 arp -c1 -w 'arp_request.tcpdump'
  ```

  ``` erlang
  lc(parse_tcpdump, parse_ip, parse_ethernet).

  % return tuple
  parse_arp:arp_info("arp_request.tcpdump").
  % print tuple
  parse_icmp:print_arp_info("arp_request.tcpdump").
  ```

Version2
==========

解析IP协议
--------------------------
* `dns_source`  为测试文件

  ``` bash
  cd version2
  ```

  ``` erlang
  lc(parse_ethernet, parse_helper, parse_ip).

  % normal list
  {ok, File_content} = file:read_file("dns_source").
  {ok, _, _, _, {data, IP_content}} = parse_ethernet:ethernet_proto_info(File_content).
  %% return tuple
  parse_ip:ip_proto_info(IP_content).
  %% print tuple
  parse_ip:print_ip_proto_info(IP_content).
  ```
  简单的方法
  ``` erlang
  lc(parse_ethernet, parse_helper, parse_ip).
  %% return tuple
  parse_ip:speed_ip_proto_info("dns_source").
  %% print tuple
  parse_ip:print_speed_ip_proto_info("dns_source").
  ```

解析UDP协议
-----------
* `dns_source` 为request测试文件

  ``` bash
  cd version2
  ```

  ``` erlang
  lc(parse_ethernet, parse_helper, parse_ip, parse_udp).

  % normal list
  {ok, File_content} = file:read_file("dns_source").
  {ok, _, _, _, {data, IP_content}} = parse_ethernet:ethernet_proto_info(File_content).
  {ok, _, _, _, {src, _, Raw_src_ip, dst, _, Raw_dst_ip}, {data, UDP_content}}
  = parse_ip:ip_proto_info(IP_content).
  %% return tuple
  parse_udp:udp_proto_info(UDP_content, Raw_src_ip, Raw_dst_ip).
  %% print tuple
  parse_udp:print_udp_proto_info(UDP_content, Raw_src_ip, Raw_dst_ip).
  ```
  简单的方法
  ``` erlang
  lc(parse_ethernet, parse_helper, parse_ip, parse_udp).
  %% return tuple
  parse_udp:speed_udp_proto_info("dns_source").
  %% print tuple
  parse_udp:print_speed_udp_proto_info("dns_source").
  ```
