-module(parse).
-export([start/0]).

start() ->
  {ok, File_Content} = file:read_file("first.tcpdump"),
  ContentSize = size(File_Content),
  find_ip_position(File_Content, 0, ContentSize).

find_ip_position(Content, N, Size) ->
  case is_ip_position(Content, N, Size) of
    {ok, IP_Content} ->
      handle(IP_Content);
    error ->
      find_ip_position(Content, N + 1, Size);
    no_match ->
      io:format("No Match~n")
  end.

handle(Content) ->
  <<Version:4, Header_Length:4, TOS:8, Total_Length:16,
    Identification:16, Flags:3, Fragment_Offset:13,
    TTL:8, Protocol:8, Header_Checksum: 16,
    SourceIP1:8, SourceIP2:8, SourceIP3:8, SourceIP4:8,
    DestinationIP1:8, DestinationIP2:8, DestinationIP3:8, DestinationIP4,
  _/binary>> = Content,

  {Info_Header_Checksum, _} = split_binary(Content, 20),

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

  Sum_Header_Checksum = header_checksum(Info_Header_Checksum),
  io:format("\tHeader checksum: ~.16X [~.16X][~s] [16 bits]~n",
            [Header_Checksum, "0x", Sum_Header_Checksum, "0x", is_correct_head_checksum(Sum_Header_Checksum)]),

  io:format("Number 4 (32 bits): ~n", []),
  io:format("\tSource: ~w.~w.~w.~w [32 bits]~n", [SourceIP1, SourceIP2, SourceIP3, SourceIP4]),

  io:format("Number 5 (32 bits): ~n", []),
  io:format("\tDestination: ~w.~w.~w.~w [32 bits]~n", [DestinationIP1, DestinationIP2, DestinationIP3, DestinationIP4]).

version(V) ->
  case V of
    4 -> "IPV4";
    6 -> "IPV6"
  end.


is_correct_head_checksum(I) when I =:= 16#ffff -> "correct";
is_correct_head_checksum(_) -> "incorrect".

header_checksum(Info) ->
  All_Sum = header_checksum_iter(Info, 0, 0),
  Small_Sum = All_Sum band 16#ffff,
  Large_Sum = All_Sum bsr 16,
  Small_Sum + Large_Sum.

header_checksum_iter(Info, Sum, 18) ->
  {_, <<Num:16>>} = split_binary(Info, 18),
  Sum + Num;
header_checksum_iter(Info, Sum, Count) ->
  {_, <<Num:16, _/binary>>} = split_binary(Info, Count),
  header_checksum_iter(Info, Sum + Num, Count + 2).

protocol(P) ->
  case P of
    6 -> "TCP";
    17 -> "UDP"
  end.

is_ip_position(Content, N, Size) ->
  try ip_position(Content, N, Size)
  catch
    throw:no_match -> no_match;
    _:_ -> error
  end.

ip_position(_, N, Size) when N > Size -> throw(no_match);
ip_position(Content, N, _) ->
  {_, <<8:8, 0:8, IP_Content/binary>>} = split_binary(Content, N),
  {ok, IP_Content}.
