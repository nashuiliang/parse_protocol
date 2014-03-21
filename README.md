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
  c(parse).
  parse:start().
  ```

解析ICMP协议
-----------
*  ** `icmp_xiaoyintong.tcpdump` 为request测试文件

    ``` bash
    sudo tcpdump -i wlp2s0 -nnvvXX -S 'host 115.29.172.134' -c1 -w 'icmp_xiaoyintong.tcpdump'
    ping www.xiaoyintong.com
    ```

    ** erlang 环境中

    ``` erlang
    c(parse_icmp).
    parse_icmp:start().
    ```
* ** `icmp_xiaoyintong_reply.tcpdump` 为reply测试文件

    ``` bash
    sudo tcpdump -i wlp2s0 -nnvvXX -S 'host 115.29.172.134 and icmp[icmptype]=icmp-echoreply' -c1 -w 'icmp_xiaoyintong_reply.tcpdump'
    ping www.xiaoyintong.com
    ```

    ** erlang 环境中

    ``` erlang
    c(parse_icmp).
    parse_icmp:start_reply().
    ```
