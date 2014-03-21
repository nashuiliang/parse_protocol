-module(parse_icmp).
-export([start/0, start_reply/0]).

-define(Protocol_ICMP, 1).
-define(Protocol_TCP, 6).
-define(Protocol_UDP, 17).

-define(ICMP_Filename, "icmp_xiaoyintong.tcpdump").
-define(ICMP_Reply_Filename, "icmp_xiaoyintong_reply.tcpdump").

start() ->
  {ok, File_Content} = file:read_file(?ICMP_Filename),
  parse(File_Content).

start_reply() ->
  {ok, File_Content} = file:read_file(?ICMP_Reply_Filename),
  parse(File_Content).


parse(Content) ->
  {ok, _, IP_Content} = get_ip_position(Content),
  {proto, Protocol, info, ICMP_Content} = parse_ip_protocol(IP_Content),
  parse_icmp_protocol(Protocol, ICMP_Content).

parse_icmp_protocol(Protocol, _) when Protocol /= ?Protocol_ICMP -> throw({protocol_error, "Not ICMP Protocol"});
parse_icmp_protocol(_, Content) ->
  <<Type:8, Code:8, Checksum:16,
    Identifier:16, Sequence_Number:16,
    Data/binary>> = Content,
  io:format("~nICMP(internet control message protocol)~n"),
  io:format("\tType: ~w [~s] [8 bits]~n", [Type, icmp_type(Type)]),
  io:format("\tCode: ~w [8 bits]~n", [Code]),

  Icmp_Checksum = icmp_checksum(Content),
  io:format("\tChecksum: ~.16X [~.16X] [~s] [16 bits]~n", [Checksum, "0x", Icmp_Checksum, "0x", is_correct_head_checksum(Icmp_Checksum)]),
  io:format("\tIdentifier: ~w [16 bits]~n", [Identifier]),
  io:format("\tSequence number: ~w [16 bits]~n", [Sequence_Number]),

  io:format("\tData length: ~w bytes~n", [size(Data)]),
  icmp_input_data(Data).

icmp_input_data(Data) ->
  io:format("\tData: "),
  icmp_input_data_iter_b(Data, 0, size(Data)),
  io:format("\tRaw Data: "),
  icmp_input_data_iter(Data, 0, size(Data)).

icmp_input_data_iter_b(Data, N, Size) when N =:= (Size - 1) ->
  {_, <<Val:8>>} = split_binary(Data, N),
  io:format("~.16X~n", [Val, ""]);
icmp_input_data_iter_b(Data, N, Size) ->
  {_, <<Val:8, _/binary>>} = split_binary(Data, N),
  io:format("~.16X", [Val, ""]),
  icmp_input_data_iter_b(Data, N + 1, Size).

icmp_input_data_iter(Data, N, Size) when N =:= (Size - 1) ->
  {_, <<Val1:4, Val2:4>>} = split_binary(Data, N),
  io:format("~c~c~n", [Val1, Val2]);
icmp_input_data_iter(Data, N, Size) ->
  {_, <<Val1:4, Val2:4, _/binary>>} = split_binary(Data, N),
  io:format("~c~c", [Val1, Val2]),
  icmp_input_data_iter(Data, N + 1, Size).


icmp_checksum(Content) ->
  Sum = icmp_checksum_iter(0, Content, 0, size(Content)),
  (Sum band 16#ffff) + (Sum bsr 16).

icmp_checksum_iter(Sum, Info, N, Size) when (N =:= (Size - 2)) or (N =:= (Size - 1)) ->
  {_, <<Val:16>>} = split_binary(Info, N),
  Val + Sum;
icmp_checksum_iter(Sum, Info, N, Size) ->
  {_, <<Val:16, _/binary>>} = split_binary(Info, N),
  icmp_checksum_iter(Val + Sum, Info, N + 2, Size).

icmp_type(T) ->
  case T of
    8 -> "echo message";
    0 -> "echo replay message"
  end.


parse_ip_protocol(Content) ->
  <<Version:4, Header_Length:4, TOS:8, Total_Length:16,
    Identification:16, Flags:3, Fragment_Offset:13,
    TTL:8, Protocol:8, Header_Checksum: 16,
    SourceIP1:8, SourceIP2:8, SourceIP3:8, SourceIP4:8,
    DestinationIP1:8, DestinationIP2:8, DestinationIP3:8, DestinationIP4,
  ICMP_Content/binary>> = Content,

  {_Info_Header_Checksum, _} = split_binary(Content, 20),

  io:format("Number 1 (32 bits): ~n", []),
  io:format("\tVerson: ~p [~s] [4 bits]~n", [Version, version(Version)]),
  io:format("\tHeader length: ~w [20 bytes] [4 bits]~n", [Header_Length]),
  io:format("\tTOS: ~w [~.16X] [8 bits]~n", [TOS, TOS, "0x"]),
  io:format("\tTotal length ~w bytes [16 bits]~n", [Total_Length]),

  io:format("Number 2 (32 bits): ~n", []),
  io:format("\tIdentification: ~w [~.16X] [16 bits]~n", [Identification, Identification, "0x"]),
  io:format("\tFlags: ~w [~.16X] [3 bits]~n", [Flags, Flags, "0x"]),
  io:format("\tFragment offset: ~w [~.16X] [13 bits]~n", [Fragment_Offset, Fragment_Offset, "0x"]),

  io:format("Number 3 (32 bits): ~n", []),
  io:format("\tTTL: ~w [~.16X] [8 bits]~n", [TTL, TTL, "0x"]),
  io:format("\tProtocol: ~w [~s] [8 bits]~n", [Protocol, protocol(Protocol)]),

  Sum_Header_Checksum = header_checksum(_Info_Header_Checksum),
  io:format("\tHeader checksum: ~.16X [~.16X][~s] [16 bits]~n",
            [Header_Checksum, "0x", Sum_Header_Checksum, "0x", is_correct_head_checksum(Sum_Header_Checksum)]),

  io:format("Number 4 (32 bits): ~n", []),
  io:format("\tSource: ~w.~w.~w.~w [32 bits]~n", [SourceIP1, SourceIP2, SourceIP3, SourceIP4]),

  io:format("Number 5 (32 bits): ~n", []),
  io:format("\tDestination: ~w.~w.~w.~w [32 bits]~n", [DestinationIP1, DestinationIP2, DestinationIP3, DestinationIP4]),

  {proto, Protocol, info, ICMP_Content}.

is_correct_head_checksum(V)  when V =:= 16#ffff -> "correct";
is_correct_head_checksum(_) -> "incorrect".

header_checksum(Info) ->
  Sum = header_checksum_iter(0, Info, 0, size(Info)),
  (Sum band 16#ffff) + (Sum bsr 16).

header_checksum_iter(Sum, _, N, Size) when N >= Size -> Sum;
header_checksum_iter(Sum, Info, N, _) when N =:= 18 ->
  {_, <<Val:16>>} = split_binary(Info, 18),
  Sum + Val;
header_checksum_iter(Sum, Info, N, Size) ->
  {_, <<Val:16, _/binary>>} = split_binary(Info, N),
  header_checksum_iter(Sum + Val, Info, N + 2, Size).

protocol(P) ->
  case P of
    ?Protocol_ICMP -> "ICMP";
    ?Protocol_TCP -> "TCP";
    ?Protocol_UDP -> "UDP"
  end.

version(V) ->
  case V of
    4 -> "IPV4";
    6 -> "IPV6"
  end.

get_ip_position(Content) ->
  case find_ip_position(Content, 0, size(Content)) of
    {no_match, Val} ->
      throw({no_match, Val});
    {ok, N, IP_Content} ->
      {ok, N, IP_Content}
  end.

find_ip_position(Content, N, Size) ->
  case is_ip_position(Content, N, Size) of
    {error, _} ->
      find_ip_position(Content, N + 1, Size);
    {no_match, Val} ->
      {no_match, Val};
    {ok, N, IP_Content} ->
      {ok, N, IP_Content}
  end.

is_ip_position(Content, N, Size) ->
  try find_ip_position_iter(Content, N, Size)
  catch
    error:_ -> {error, "match failed"}
  end.

find_ip_position_iter(_, N, Size) when N >= Size -> {no_match, "no match"};
find_ip_position_iter(Content, N, _) ->
  {_, <<8:8, 0:8, IP_Content/binary>>} = split_binary(Content, N),
  {ok, N, IP_Content}.
