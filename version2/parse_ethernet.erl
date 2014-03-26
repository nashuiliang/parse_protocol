-module(parse_ethernet).
-export([ethernet_proto_info/1, print_ethernet_proto_info/1, speed_ethernet_proto_info/1, print_speed_ethernet_proto_info/1]).

speed_ethernet_proto_info(File_name) ->
  {ok, File_content} = file:read_file(File_name),
  ethernet_proto_info(File_content).

print_speed_ethernet_proto_info(File_name) ->
  {ok, File_content} = file:read_file(File_name),
  print_ethernet_proto_info(File_content).

ethernet_proto_info(Ethernet_info) ->
  {Dst_mac_addr, Ethernet_info_b_dst} = split_binary(Ethernet_info, 6),
  {Src_mac_addr, Ethernet_info_b_src} = split_binary(Ethernet_info_b_dst, 6),
  {<<Type:16>>, Data} = split_binary(Ethernet_info_b_src, 2),

  {ok, Destition} = mac_address(Dst_mac_addr, ":"),
  {ok, Source} = mac_address(Src_mac_addr, ":"),
  {ok, _, Type_val} = protocol_type(Type),
  {ok, {dst, Destition}, {src, Source}, {type, Type, Type_val}, {data, Data}}.

print_ethernet_proto_info(Ethernet_info) ->
  {ok, {dst, Destition}, {src, Source}, {type, Type, Type_val}, {data, Data}} =
    ethernet_proto_info(Ethernet_info),
  io:format("Ethernet II Protocol~n", []),
  io:format("\tDestination: ~s [6 bytes]~n", [Destition]),
  io:format("\tSource: ~s [6 bytes]~n", [Source]),
  io:format("\tType: ~s [0x~4.16.0x] [2 bytes]~n", [Type_val, Type, ""]),
  io:format("\tData: ~w~n", [Data]).


protocol_type(T) when T =< 16#05dc -> throw({error, "Not Ethernet II Protocol"});
protocol_type(T) ->
  case T of
    16#0800 -> {ok, T, "IP"};
    16#0806 -> {ok, T, "ARP"}
  end.

mac_address(Mac, Sp) ->
  <<Add1:8, Add2:8, Add3:8, Add4:8, Add5:8, Add6:8>> = Mac,
  raw_mac_address(Add1, Add2, Add3, Add4, Add5, Add6, Sp).

raw_mac_address(Add1, Add2, Add3, Add4, Add5, Add6, Sp) ->
  {ok, io_lib:format("~2.16.0x~s~2.16.0x~s~2.16.0x~s~2.16.0x~s~2.16.0x~s~2.16.0x",
                     [Add1, "", Sp, Add2, "", Sp, Add3, "", Sp, Add4, "", Sp, Add5, "", Sp, Add6, ""])}.
