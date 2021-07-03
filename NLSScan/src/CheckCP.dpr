program CheckCP;

{$APPTYPE CONSOLE}

uses
  Winapi.Windows, System.SysUtils, System.Generics.Collections;

var
  g_arrInstalledCodePages: TArray<Integer> = nil;
  g_arrSupportedCodePages: TArray<Integer> = nil;

function AddCodePage(const pCodePage: PChar; var arrInt: TArray<Integer>): Boolean;
var
  iCodePage, iCode: Integer;
begin
  Result := False;
  Val(pCodePage, iCodePage, iCode);
  if iCode = 0 then
  begin
    SetLength(arrInt, Length(arrInt) + 1);
    arrInt[Length(arrInt) - 1] := iCodePage;
    Result := True;
  end;
end;

function EnumInstalledCodePagesProc(pCodePage: PChar): Integer; stdcall;
begin
  Result := 0;
  if AddCodePage(pCodePage, g_arrInstalledCodePages) then
    Result := 1;
end;

function EnumSupportedCodePagesProc(pCodePage: PChar): Integer; stdcall;
begin
  Result := 0;
  if AddCodePage(pCodePage, g_arrSupportedCodePages) then
    Result := 1;
end;

begin
  // Get supported codepages
  EnumSystemCodePages(@EnumSupportedCodePagesProc, CP_SUPPORTED);
  TArray.Sort<Integer>(g_arrSupportedCodePages);

  // Get installed codepages
  EnumSystemCodePages(@EnumInstalledCodePagesProc, CP_INSTALLED);
  TArray.Sort<Integer>(g_arrInstalledCodePages);

  WriteLn('Number of CodePage supported: ', Length(g_arrSupportedCodePages));
  WriteLn('Number of CodePage installed: ', Length(g_arrInstalledCodePages), #13#10);

  var cp: Integer := 0;
  if Length(g_arrSupportedCodePages) = Length(g_arrInstalledCodePages) then
  begin
    Write('All CodePages = [ ');
    for cp in g_arrSupportedCodePages do
      Write(cp, ' ');
    WriteLn(']'#13#10);
  end
  else
  begin
    Write('Supported CodePages = [ ');
    for cp in g_arrSupportedCodePages do
      Write(cp, ' ');
    WriteLn(']'#13#10);

    Write('Installed CodePages = [ ');
    for cp in g_arrInstalledCodePages do
      Write(cp, ' ');
    WriteLn(']'#13#10);
  end;

  var str: string := '';
  var code: Integer := 0;
  var idx: Integer := 0;
  while True do
  begin
    Write('Enter the codepage number to check: ');
    ReadLn(str);
    if Trim(str) = '' then
      Break;

    Val(str, cp, code);
    if code = 0 then
    begin
      if TArray.BinarySearch<Integer>(g_arrInstalledCodePages, cp, idx) then
        WriteLn(cp, ' is in installed CodePages');

      if TArray.BinarySearch<Integer>(g_arrSupportedCodePages, cp, idx) then
        WriteLn(cp, ' is in supported CodePages')
      else
        WriteLn(cp, ' is not a valid CodePage')
    end
    else
      WriteLn('Input string is not a number');
  end;

  WriteLn(#13#10'Press Enter key to exit.');
  ReadLn;
end.

