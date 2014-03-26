-module(parse_helper).
-export([checksum/1]).

is_correct_checksum(V)  when V =:= 16#ffff -> "correct";
is_correct_checksum(_) -> "incorrect".

checksum(Info) ->
  Sum = checksum(0, Info, 0, size(Info)),
  Check_Sum = (Sum band 16#ffff) + (Sum bsr 16),
  {ok, Info, Check_Sum, is_correct_checksum(Check_Sum)}.

checksum(Sum, _, N, Size) when N >= Size -> Sum;
checksum(Sum, Info, N, Size) when N =:= (Size - 2) ->
  {_, <<Val:16>>} = split_binary(Info, N),
  Sum + Val;
checksum(Sum, Info, N, Size) ->
  {_, <<Val:16, _/binary>>} = split_binary(Info, N),
  checksum(Sum + Val, Info, N + 2, Size).
