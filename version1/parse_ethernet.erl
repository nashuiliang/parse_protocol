-module(parse_ethernet).
-import(parse_tcpdump, [get_raw_ethernet/1]).
-export([ethernet_info/1, print_ethernet_info/1, mac_address/2, raw_mac_address/7, protocol_type/1]).

print_ethernet_info(File_name) ->
  {ok, {dst, Destition}, {src, Source}, {type, Type, Type_val}, {data, Data}} =
    ethernet_info(File_name),
  io:format("Ethernet II Protocol~n", []),
  io:format("\tDestination: ~s [6 bytes]~n", [Destition]),
  io:format("\tSource: ~s [6 bytes]~n", [Source]),
  io:format("\tType: ~s [0x~4.16.0x] [2 bytes]~n", [Type_val, Type, ""]),
  io:format("\tData: ~w~n", [Data]).

ethernet_info(File_name) ->
  {ok, _, _, Ethernet_info} = get_raw_ethernet(File_name),
  {Dst, O_Ethernet_info} = split_binary(Ethernet_info, 6),
  {Src, _} = split_binary(O_Ethernet_info, 6),
  <<_: 48, Type:16, Data/binary>> = O_Ethernet_info,

  {ok, Destition} = mac_address(Dst, ":"),
  {ok, Source} = mac_address(Src, ":"),
  {ok, _, Type_val} = protocol_type(Type),

  {ok, {dst, Destition}, {src, Source}, {type, Type, Type_val}, {data, Data}}.
  %io:format("~s~n~s~n~s~n", [Destition, Source, Type_val]).

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
