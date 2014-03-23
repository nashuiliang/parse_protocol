解析网络协议
==============

解析IP协议
--------------------------
* `first.tcpdump`  为测试文件

  ``` bash
  sudo tcpdump -i wlp2s0 -nnvvXX -S 'host 115.29.172.134' -c1 -w 'first.tcpdump'
  ```

* erlang 环境中

  ``` erlang
  lc(parse_tcpdump, parse_ip).

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
  lc(parse_tcpdump, ip, icmp).

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
  lc(parse_tcpdump, ip, icmp).

  % return tuple
  parse_icmp:icmp_protocol_info("icmp_xiaoyintong_reply.tcpdump").
  % print tuple
  parse_icmp:print_icmp_protocol_info("icmp_xiaoyintong_reply.tcpdump").
    ```
