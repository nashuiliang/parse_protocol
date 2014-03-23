-module(parse_ip).
-import(parse_ethernet, [ethernet_info/1]).
-export([ip_protocol_info/1, print_ip_protocol_info/1, header_checksum/1]).

-define(Protocol_ICMP, 1).
-define(Protocol_TCP, 6).
-define(Protocol_UDP, 17).

ip_protocol_info(File_name) ->
  {ok, _, _, _, {data, IP_content}} = ethernet_info(File_name),

  <<Version:4, Header_Length:4, TOS:8, Total_Length:16,
    Identification:16, Flags:3, Fragment_Offset:13,
    TTL:8, Protocol:8, Header_Checksum: 16,
    SourceIP1:8, SourceIP2:8, SourceIP3:8, SourceIP4:8,
    DestinationIP1:8, DestinationIP2:8, DestinationIP3:8, DestinationIP4:8,
  Temp_data/binary>> = IP_content,

  {_Info_Header_Checksum, _} = split_binary(IP_content, 20),
  {Data, _} = split_binary(Temp_data, (Total_Length - 20)),
  {ok, _, Protocol_Val} = protocol_type(Protocol),
  {ok, _, Check_Res, Check_Val} = header_checksum(_Info_Header_Checksum),

  {ok, {
      version, Version,
      header_length, Header_Length,
      tos, TOS,
      total_length, Total_Length
    }, {
      id, Identification,
      flags, Flags,
      fragment_offset, Fragment_Offset
    }, {
          {ttl, TTL},
          {proto, Protocol, proto_val, Protocol_Val},
          {raw_check_val, Header_Checksum, check_res, Check_Res, check_val, Check_Val}
    }, {
      src, io_lib:format("~w.~w.~w.~w", [SourceIP1, SourceIP2, SourceIP3, SourceIP4]),
      dst, io_lib:format("~w.~w.~w.~w", [DestinationIP1, DestinationIP2, DestinationIP3, DestinationIP4])
    }, {data, Data}
  }.

print_ip_protocol_info(File_name) ->
  {ok, {version, Version, header_length, Header_Length, tos, TOS, total_length, Total_Length },
      {id, Identification, flags, Flags, fragment_offset, Fragment_Offset },
      {{ttl, TTL}, {proto, Protocol, proto_val, Protocol_Val}, {raw_check_val, Header_Checksum, check_res, Check_Res, check_val, Check_Val} },
      { src, SouceIP, dst, DestinationIP}, {data, Data}
  } = ip_protocol_info(File_name),

  io:format("IP(internet protocol)~n"),
  io:format("Number 1 (32 bits): ~n", []),
  io:format("\tVerson: ~p [4 bits]~n", [Version]),
  io:format("\tHeader length: ~w [20 bytes] [4 bits]~n", [Header_Length]),
  io:format("\tTOS: ~w [0x~2.16.0x] [8 bits]~n", [TOS, TOS, ""]),
  io:format("\tTotal length ~w bytes [16 bits]~n", [Total_Length]),

  io:format("Number 2 (32 bits): ~n", []),
  io:format("\tIdentification: ~w [0x~4.16.0x] [16 bits]~n", [Identification, Identification, ""]),
  io:format("\tFlags: ~w [0x~2.16.0x] [3 bits]~n", [Flags, Flags, ""]),
  io:format("\tFragment offset: ~w [0x~4.16.0x] [13 bits]~n", [Fragment_Offset, Fragment_Offset, ""]),

  io:format("Number 3 (32 bits): ~n", []),
  io:format("\tTTL: ~w [0x~2.16.0x] [8 bits]~n", [TTL, TTL, ""]),
  io:format("\tProtocol: ~w [~s] [8 bits]~n", [Protocol, Protocol_Val]),

  io:format("\tHeader checksum: ~4.16.0x [0x~.16.0x][~s] [16 bits]~n",
            [Header_Checksum, "", Check_Res, "", Check_Val]),

  io:format("Number 4 (32 bits): ~n", []),
  io:format("\tSource: ~s [32 bits]~n", [SouceIP]),

  io:format("Number 5 (32 bits): ~n", []),
  io:format("\tDestination: ~s [32 bits]~n", [DestinationIP]),
  io:format("Data: ~w~n", [Data]).

protocol_type(P) ->
  case P of
    ?Protocol_ICMP -> {ok, P, "ICMP"};
    ?Protocol_TCP -> {ok, P, "TCP"};
    ?Protocol_UDP -> {ok, P, "UDP"}
  end.

is_correct_checksum(V)  when V =:= 16#ffff -> "correct";
is_correct_checksum(_) -> "incorrect".

header_checksum(Info) ->
  Sum = header_checksum(0, Info, 0, size(Info)),
  Check_Sum = (Sum band 16#ffff) + (Sum bsr 16),
  {ok, Info, Check_Sum, is_correct_checksum(Check_Sum)}.

header_checksum(Sum, _, N, Size) when N >= Size -> Sum;
header_checksum(Sum, Info, N, Size) when N =:= (Size - 2) ->
  {_, <<Val:16>>} = split_binary(Info, N),
  Sum + Val;
header_checksum(Sum, Info, N, Size) ->
  {_, <<Val:16, _/binary>>} = split_binary(Info, N),
  header_checksum(Sum + Val, Info, N + 2, Size).
