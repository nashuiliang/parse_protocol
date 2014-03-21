解析网络协议
==============

generate unique session id
--------------------------
> 1. Perl Socket, threads
        `use IO::Socket; use threads;`
> 2. 调用socket 生成唯一的session id
> 3. 调用`uuidgen` 简单的成生uuid, 可以参看GO session 模块中关于session id的生成

save session message
--------------------
> 1. 使用redis 作为session内信息的存储

simple http web server
----------------------
> 1. perl HTTP server simple
    `use HTTP::Server::Simple::CGI;`

实现（demo）
----
> 1. 当用户未登录时，通过socket生成唯一的 简单的session id
> 2. 当用户登录时，设置用户session 信息和过期时间。
