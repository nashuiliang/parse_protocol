-module(parse_arp).
-import(parse_ethernet, [ethernet_info/1, mac_address/2, protocol_type/1]).
-import(parse_ip, [ip_address/1]).
-export([arp_info/1, print_arp_info/1]).

-define(Protocol_Arp_Code, 16#0806).

arp_info(File_name) ->
  {ok, _, _, {type, Type, _}, {data, Arp_info}} = ethernet_info(File_name),
  parse_arp_info(Type, Arp_info).

parse_arp_info(T, _) when T /= 16#0806 -> throw({error, "Not ARP protocol"});
parse_arp_info(_, Arp_info) ->
  {<<Hardware_type:16, Protocol_type:16, Hardware_size:8, Protocol_size:8, Opcode:16>>, Address}
    = split_binary(Arp_info, 8),

  {Sender_mac_addr, SM_arp_info} = split_binary(Address, 6),
  {Sender_ip_addr, IP_arp_info} = split_binary(SM_arp_info, 4),
  {Target_mac_addr, TM_arp_info} = split_binary(IP_arp_info, 6),
  {Target_ip_addr, _Data} = split_binary(TM_arp_info, 4),

  {ok,
   {arp_type, element(2, arp_type(Target_mac_addr)), arp_status, element(3, arp_status(Opcode))},
   {hardware, Hardware_type, element(3, hardware_type(Hardware_type))},
   {proto, Protocol_type, element(3, protocol_type(Protocol_type))},
   {hardware_size, Hardware_size},
   {proto_size, Protocol_size},
   {op_code, Opcode},
   {src_mac, element(2, mac_address(Sender_mac_addr, ":")), src_ip, element(2, ip_address(Sender_ip_addr))},
   {dst_mac, element(2, mac_address(Target_mac_addr, ":")), dst_ip, element(2, ip_address(Target_ip_addr))}
  }.

print_arp_info(File_name) ->
  {ok,
   {arp_type, Arp_type, arp_status, Arp_status}, {hardware, Hardware_type, Hardware_type_val},
   {proto, Protocol_type, Protocol_type_val}, {hardware_size, Hardware_size}, {proto_size, Protocol_size}, {op_code, Opcode},
   {src_mac, Src_mac, src_ip, Src_ip}, {dst_mac, Dst_mac, dst_ip, Dst_ip}
  } = arp_info(File_name),

  io:format("ARP (Address Resolution Protocol) [~s]~n", [Arp_type]),
  io:format("\tHardware type: 0x~4.16.0x [~s] [2 bytes]~n", [Hardware_type, "", Hardware_type_val]),
  io:format("\tProtocol type: 0x~4.16.0x [~s] [2 bytes]~n", [Protocol_type, "", Protocol_type_val]),
  io:format("\tHardware size: ~w [1 bytes]~n", [Hardware_size]),
  io:format("\tProtocol size: ~w [1 bytes]~n", [Protocol_size]),
  io:format("\tOptation code: ~w [~s] [2 bytes]~n", [Opcode, Arp_status]),
  io:format("\tSource MAC address: ~s [6 bytes]~n", [Src_mac]),
  io:format("\tSource IP address: ~s [4 bytes]~n", [Src_ip]),
  io:format("\tDestination MAC address: ~s [6 bytes]~n", [Dst_mac]),
  io:format("\tDestination IP address: ~s [4 bytes]~n", [Dst_ip]).


hardware_type(T) ->
  if
    T =:= 1 -> {ok, T, "Ethernet"};
    true -> {ok, T, ""}
  end.

arp_type(T) ->
  <<Val:48>> = T,
  if
    Val =:= 16#ffffffffffff -> {ok, "broadcast"};
    true -> {ok, "normal"}
  end.

arp_status(C) ->
  case C of
    1 -> {ok, C, "request"};
    2 -> {ok, C, "reply"}
  end.
