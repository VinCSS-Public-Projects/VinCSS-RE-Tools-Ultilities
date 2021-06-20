program NLSScan;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  WinApi.Windows, WinApi.ShlObj, WinApi.ShellAPI,
  System.Types, System.SysUtils, System.IOUtils,
  System.Classes, System.Threading, System.Generics.Collections;

const
  // Console colors
  INTENSE = FOREGROUND_INTENSITY or BACKGROUND_INTENSITY;
  FOREGROUNDMASK = FOREGROUND_BLUE or FOREGROUND_GREEN or FOREGROUND_RED or FOREGROUND_INTENSITY;
  GREEN = FOREGROUND_GREEN or BACKGROUND_GREEN;
  red = FOREGROUND_RED or BACKGROUND_RED;
  LIGHTGREEN = GREEN or INTENSE;
  LIGHTRED = RED or INTENSE;

  NLS_MASK: string = 'C_*.nls';

type
  // Extract from FMX.Helpers.Win.pas
  // Need to disable and restore redirection before and after IO functions in every thread in Windows x64
  //
  TWow64DisableWow64FsRedirection = function(var Wow64FsEnableRedirection: Int64): LongBool; stdcall;
  TWow64RevertWow64FsRedirection = function(var Wow64FsEnableRedirection: Int64): LongBool; stdcall;

  TWow64Redirection = class
  strict private
    class var FOldValue: Int64;
    class var FDisableCount: Integer;
    class var FRedirectLoaded: Boolean;
    class var Wow64DisableWow64FsRedirection: TWow64DisableWow64FsRedirection;
    class var Wow64RevertWow64FsRedirection: TWow64RevertWow64FsRedirection;
    class function RedirectLoad: Boolean; static;
    class constructor Create;
  public
    class function Disable: Boolean; static;
    class function Restore: Boolean; static;
  end;

  PLogFile = ^TLogFile;
  TLogFile = record
  strict private
    FLogPath: string;
    FStream: TFileStream;
  public
    constructor Create(const strExeDir, strExeName: string);
    procedure Write(const strMsg: string);
    procedure Close;
    property LogPath: string read FLogPath;
  end;

  // Enum error codes
  TErrorCodes = (OPEN_FILE_ERROR, FILE_TOO_SMALL, FILENAME_NOT_CONTAIN_CODEPAGE, FILENAME_CODEPAGE_INVALID,
                 NLS_INVALID_HEADER_SIZE, INVALID_CODEPAGE, MISMATCH_TWO_CODEPAGE,
                 INVALID_MAX_CHAR_SIZE, INVALID_TABLE_OFFSET, INVALID_TABLE_DATA,
                 IS_PE_FILE, IS_DLL, IS_PE64);
  TErrorCodeSet = set of TErrorCodes;

  TNLSScanResult = record
    NLSErrCode: TErrorCodeSet;
    Win32ErrCode: DWORD;
    iCodePage: Integer;
    strPath: string;
  end;

const
  TErrorDescriptions: array[TErrorCodes] of string = (
    'File open error',
    'File size less than 28',
    'Filename does not contain a codepage number',
    'Filename codepage is invalid',
    'NLS header size is not equal 0xD',
    'NLS codepage is invalid',
    'Filename codepage and NLS codepage mismatch',
    'MaxCharSize is invalid, not equal 1 or 2',
    'Offset of Unicode Table is invalid',
    'End of Unicode Table is not at end of file',
    'File is a PE (Windows) Executable',
    'File is a Windows DLL file',
    'File is PE 64bit');

var
  g_strExePath, g_strExeDir, g_strExeName, g_strTempPath: string;
  g_bWin64: Boolean = False;
  g_arrCodePages: array of Integer = nil;

class constructor TWow64Redirection.Create;
begin
  inherited;

  FOldValue := 0;
  FDisableCount := 0;
  FRedirectLoaded := False;
  Wow64DisableWow64FsRedirection := nil;
  Wow64RevertWow64FsRedirection := nil;
end;

class function TWow64Redirection.RedirectLoad: Boolean;
var
  hKernel32: THandle;
begin
  if not FRedirectLoaded then
  begin
    hKernel32 := GetModuleHandle('kernel32.dll');
    if hKernel32 <> 0 then
    begin
      @Wow64DisableWow64FsRedirection := GetProcAddress(hKernel32, 'Wow64DisableWow64FsRedirection');
      @Wow64RevertWow64FsRedirection := GetProcAddress(hKernel32, 'Wow64RevertWow64FsRedirection');
    end
    else
    begin
      @Wow64DisableWow64FsRedirection := nil;
      @Wow64RevertWow64FsRedirection := nil;
    end;
    FRedirectLoaded := TRUE;
  end;
  Result := (@Wow64DisableWow64FsRedirection <> nil) and (@Wow64RevertWow64FsRedirection <> nil);
end;

class function TWow64Redirection.Disable: Boolean;
begin
  Result := RedirectLoad and ((FDisableCount > 0) or Wow64DisableWow64FsRedirection(FOldValue));
  if Result then
    Inc(FDisableCount);
end;

class function TWow64Redirection.Restore: Boolean;
begin
  Result := RedirectLoad and (FDisableCount > 0) and
    ((FDisableCount > 1) or Wow64RevertWow64FsRedirection(FOldValue));
  if Result then
    Dec(FDisableCount);
end;

constructor TLogFile.Create(const strExeDir, strExeName: string);
var
  strTmpDir, strDir, strName: string;
begin
  strTmpDir := g_strTempPath;
  if not DirectoryExists(strExeDir) then
    strDir := strTmpDir
  else
    strDir := strExeDir;

  strName := TPath.ChangeExtension(strExeName, '.log');
  FLogPath := TPath.Combine(strDir, strName);
  try
    FStream := TFile.Open(FLogPath, TFileMode.fmAppend);
  except
    FLogPath := TPath.Combine(strTmpDir, strName);
    FStream := TFile.Open(FLogPath, TFileMode.fmAppend);
  end;
end;

procedure TLogFile.Write(const strMsg: string);
var
  strAnsi: AnsiString;
begin
  strAnsi := AnsiString(strMsg);
  FStream.Write(strAnsi[1], Length(strAnsi));
end;

procedure TLogFile.Close;
begin
  FreeAndNil(FStream);
  FLogPath := '';
end;

function GetDirFromCSIDL(nCsidl: Integer): string;
var
  wszPath: array[0..MAX_PATH] of Char;
begin
  SHGetSpecialFolderPath(0, wszPath, nCsidl, False);
  SetString(Result, wszPath, StrLen(wszPath));
end;

procedure WriteTextColor(const strText: string; wColor: Word);
var
  hConsole: THandle;
  csbi: TConsoleScreenBufferInfo;
  oldAttr: Word;
begin
  hConsole := GetStdHandle(STD_OUTPUT_HANDLE);
  GetConsoleScreenBufferInfo(hConsole, csbi);
  oldAttr := csbi.wAttributes;
  SetConsoleTextAttribute(hConsole, wColor and FOREGROUNDMASK);
  WriteLn(strText);
  SetConsoleTextAttribute(hConsole, oldAttr);
end;

procedure WriteToLogAndConsole(const logFile: PLogFile; const strMsg: string;
                               bColor: Boolean = False; wColor: Word = LIGHTRED);
begin
  if bColor then
    WriteTextColor(strMsg, wColor)
  else
    WriteLn(strMsg);

  if logFile.LogPath <> '' then   // log file created
    logFile.Write(strMsg + #13#10);
end;

function ScanFile(const strPath: string; arrCodePages: array of Integer; bRedirect: Boolean): TNLSScanResult;
const
  MAX_SIZE_READ = 4096;
var
  hFile: THandle;
  dwFSize: DWORD;
  strFName: string;
  dosHdr: TImageDosHeader;
  ntHdr: TImageNtHeaders32;
  iPos, iCodePage, iRead, iFound: Integer;
  abBuf: array[0..MAX_SIZE_READ - 1] of Byte;
begin
  iCodePage := 0;
  Result.Win32ErrCode := 0;
  Result.NLSErrCode := [];
  Result.strPath := strPath;  // store for scan process result

  // First check if file name is C_xxxx.nls
  strFName := ExtractFileName(strPath);
  if (UpCase(strFName[1]) = 'C') and (strFName[2] = '_') then
  begin
    iPos := Pos('.', strFName);
    Val(Copy(strFName, 3, iPos - 3), iCodePage, iPos);
    if iPos <> 0 then
      Include(Result.NLSErrCode, FILENAME_NOT_CONTAIN_CODEPAGE)
    else if not TArray.BinarySearch<Integer>(arrCodePages, iCodePage, iFound) then
        Include(Result.NLSErrCode, FILENAME_CODEPAGE_INVALID);
  end
  else
    Include(Result.NLSErrCode, FILENAME_NOT_CONTAIN_CODEPAGE);

  if bRedirect then
    TWow64Redirection.Disable;

  hFile := FileOpen(strPath, fmOpenRead);
  if bRedirect then
    TWow64Redirection.Restore;

  if hFile = INVALID_HANDLE_VALUE then
  begin
    Result.Win32ErrCode := GetLastError;
    Include(Result.NLSErrCode, OPEN_FILE_ERROR);
    Exit;
  end;
  dwFSize := GetFileSize(hFile, nil);
  iRead := FileRead(hFile, abBuf, SizeOf(abBuf));
  FileClose(hFile);

  // Parse NLS file, see NLS.bt for more information
  //
  if iRead < 28 then
  begin
    Include(Result.NLSErrCode, FILE_TOO_SMALL);
    Exit;
  end;

  // 0xD = 13 * 2 = 26
  var wFirst: Word := 0;
  if (iRead > 2) then
  begin
    wFirst :=  PWord(@abBuf[0])^;
    if (wFirst <> $D) and (wFirst <> IMAGE_DOS_SIGNATURE) then
    begin
      Include(Result.NLSErrCode, NLS_INVALID_HEADER_SIZE);
      Exit;
    end;
  end;

  if (wFirst = $D) then   // Check NLS contents
  begin
    // Check two codepage
    if (iRead > 4) then
    begin
      if not TArray.BinarySearch<Integer>(arrCodePages, PWord(@abBuf[2])^, iFound) then
        Include(Result.NLSErrCode, INVALID_CODEPAGE);
      if (iCodePage <> 0) and (iCodePage <> PWord(@abBuf[2])^) then
        Include(Result.NLSErrCode, MISMATCH_TWO_CODEPAGE);
    end;
    Result.iCodePage := iCodePage;

    // Check max char size
    var wMaxCharSize: Word := 0;
    if (iRead > 6) then
      wMaxCharSize := PWord(@abBuf[4])^;
    if (wMaxCharSize > 2) or (wMaxCharSize = 0) then
      Include(Result.NLSErrCode, INVALID_MAX_CHAR_SIZE)
    else
    begin
      // Check offset to WC2MB table
      var wOfs: Word;
      var dwTableStartOfs, dwTableEndOfs: Cardinal;
      if (iRead > 28) then
      begin
        wOfs := PWord(@abBuf[26])^;
        dwTableStartOfs := 28 + wOfs * SizeOf(Word);
        dwTableEndOfs := dwTableStartOfs + 65536 * wMaxCharSize;
        if (dwTableStartOfs >= dwFSize) then
          Include(Result.NLSErrCode, INVALID_TABLE_OFFSET)
        else if (dwTableEndOfs > dwFSize + 4) or (dwTableEndOfs < dwFSize - 4) then
          Include(Result.NLSErrCode, INVALID_TABLE_DATA);
      end;
    end;
  end
  else  // Check PE file
  begin
    if iRead > SizeOf(dosHdr) then
    begin
      dosHdr := PImageDosHeader(@abBuf)^;
      if iRead > dosHdr._lfanew + SizeOf(ntHdr) then
      begin
        ntHdr := PImageNtHeaders32(PByte(@abBuf[0]) + dosHdr._lfanew)^;
        if ntHdr.Signature = IMAGE_NT_SIGNATURE then
          Include(Result.NLSErrCode, IS_PE_FILE);
        if (ntHdr.FileHeader.Characteristics and IMAGE_FILE_DLL) <> 0 then
          Include(Result.NLSErrCode, IS_DLL);
        if ntHdr.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC then
          Include(Result.NLSErrCode, IS_PE64);
      end;
    end;
  end;
end;

function GetFilesInDir(const strDir, strPattern: string; bRedirect: Boolean): TStringDynArray;
begin
  try
    if bRedirect then
      TWow64Redirection.Disable;
    Result := TDirectory.GetFiles(strDir, strPattern, TSearchOption.soAllDirectories);
  finally
    if bRedirect then
      TWow64Redirection.Restore;
  end;
end;

function FileExistsRedirect(const strPath: string; bRedirect: Boolean): Boolean;
begin
  try
    if bRedirect then
      TWow64Redirection.Disable;
    Result := FileExists(strPath);
  finally
    if bRedirect then
      TWow64Redirection.Restore;
  end;
end;

function EnumCodePagesProc(pCodePage: PChar): Integer; stdcall;
var
  iCodePage, iCode: Integer;
begin
  Val(pCodePage, iCodePage, iCode);
  if iCode = 0 then
  begin
    SetLength(g_arrCodePages, Length(g_arrCodePages) + 1);
    g_arrCodePages[Length(g_arrCodePages) - 1] := iCodePage;
  end;
  Result := 1;
end;

procedure Intro;
begin
  WriteTextColor('NLSScan - Scan and detect malwares, that fake Windows C_*.nls files', LIGHTGREEN);
  WriteTextColor('Written by HTC (TQN) - VinCSS(a member of Vingroup)', LIGHTGREEN);
  WriteTextColor('Version 0.1 - First release'#13#10, LIGHTGREEN);
  WriteTextColor('Usage: NLSScan [NLSFileName1] ...[NLSFileNameN]', LIGHTGREEN);
  WriteTextColor('If run withthout parameter, scan all C_*.nls files in Windows System directories'#13#10, LIGHTGREEN);

  WriteLn('Computer info: ' + TOSVersion.ToString);
  g_bWin64 := TOSVersion.Architecture = arIntelX64;
end;

procedure Scan;
var
  logFile: TLogFile;
  bScanWinDir: Boolean;
  tasks: array of ITask;
  dtStart, dtEnd: TDateTime;
  nParams, I, iNext: Integer;
  strSystem32, strSysWow64, strQuestion: string;
  arrErrCodes, arrBadFiles: array of TNLSScanResult;
  arrNlsSystem32, arrNlsSysWow64, arrInputFiles: TStringDynArray;
begin
  arrNlsSystem32 := nil;
  arrNlsSysWow64 := nil;
  arrInputFiles := nil;
  arrBadFiles := nil;

  nParams := ParamCount; // avoid call this function many times.
  bScanWinDir := nParams = 0;

  // Get supported codepages
  EnumSystemCodePages(@EnumCodePagesProc, CP_SUPPORTED);
  TArray.Sort<Integer>(g_arrCodePages);

  // Check Admin privilege
  if bScanWinDir then
  begin
    if not IsUserAnAdmin then
    begin
      strQuestion := 'Scanning of NLS file(s) in Windows directory requires Admin privilege.' + #13#10 +
                     'Run ' + g_strExeName + ' as Admin ?';
      if (MessageBox(GetConsoleWindow, PChar(strQuestion), 'Promote to Admin privilege', MB_YESNO) = IDYES) then
        ShellExecute(0, 'runas', PChar(g_strExePath), nil, PChar(g_strExeDir), SW_SHOWNORMAL);
      Halt(0); // exit app
    end;
  end;

  dtStart := Now; // start time of scanning

  if bScanWinDir then
  begin
    // Get System32 and SysWow64 path
    strSystem32 := GetDirFromCSIDL(CSIDL_SYSTEM);
    strSysWow64 := GetDirFromCSIDL(CSIDL_SYSTEMX86);

    // Get list of all C_*.nls files
    if g_bWin64 then
    begin
      Write(Format('Get %s files list in %s and %s directories...', [NLS_MASK, strSystem32, strSysWow64]));

      // run two tasks to get file path of all C_*.nls files
      SetLength(tasks, 2);
      tasks[0] := TTask.Create(procedure()
        begin
          arrNlsSystem32 := GetFilesInDir(strSystem32, NLS_MASK, True);
        end);

      tasks[1] := TTask.Create(procedure()
        begin
          arrNlsSysWow64 := GetFilesInDir(strSysWow64, NLS_MASK, True);
        end);

      tasks[0].Start;
      tasks[1].Start;
      TTask.WaitForAll(tasks);
      WriteLn('done.');

      if Length(arrNlsSysWow64) > 0 then
        WriteTextColor(Format('Warning: NLS files cannot be placed in %s directory. They could be malware !!!',
                       [strSysWow64]), LIGHTRED);
    end
    else
      arrNlsSystem32 := GetFilesInDir(strSystem32, NLS_MASK, False);

    // Concat and assign to the final array of input files
    arrInputFiles :=  arrNlsSysWow64 + arrNlsSystem32;

    // Free old dynamic arrays
    arrNlsSystem32 := nil;
    arrNlsSysWow64 := nil;
  end
  else
  begin
    // Scan from input files
    var strFile: string;
    iNext := 0;
    SetLength(arrInputFiles, nParams);
    for I := 1 to nParams do
    begin
      strFile := ParamStr(I);
      if FileExistsRedirect(strFile, g_bWin64) then
      begin
        arrInputFiles[iNext] := strFile;
        Inc(iNext);
      end
      else
        WriteLn('File not existed: ', strFile);
    end;
    SetLength(arrInputFiles, iNext);  // trim dynamic array
  end;

  var iTotalFiles: Integer := Length(arrInputFiles);
  if iTotalFiles = 0 then
  begin
    WriteLn('No files to scan');
    Exit;
  end;

  SetLength(arrErrCodes, iTotalFiles);
  SetLength(arrBadFiles, iTotalFiles);
  WriteLn(Format('Scanning %d files...', [iTotalFiles]));

  if g_bWin64 then
    // Scan on single, main thread
    for I := 0 to iTotalFiles - 1 do
      arrErrCodes[i] := ScanFile(arrInputFiles[I], g_arrCodePages, True)
  else
    // Run parallel only on Win x86 out because of Redirect error in parallel multithreads on Win x64,
    // FileOpen return file not found, I don't know why ??? :(
    // TODO: Fix this bug on Win x64
    TParallel.For(0, iTotalFiles - 1, procedure(idx: Integer)
      begin
        arrErrCodes[idx] := ScanFile(arrInputFiles[idx], g_arrCodePages, False);
      end);

  dtEnd := Now; // End time of scanning

  var totalOK: Integer := 0;
  var totalBad: Integer := 0;
  iNext := 0;
  for I := 0 to iTotalFiles - 1 do
  begin
    if (arrErrCodes[I].NLSErrCode = []) then
      // TODO: Need more check NLS files which are valid but placed at sub directories of Systems dir
      // and codepage in supported codepages but not in installed codepages
      Inc(totalOK)
    else
    begin
      Inc(totalBad);
      arrBadFiles[iNext] := arrErrCodes[I];
      Inc(iNext);
    end
  end;
  SetLength(arrBadFiles, iNext);  // trim dynamic array

  if bScanWinDir then
  begin
    logFile := TLogFile.Create(g_strExeDir, g_strExeName);
    WriteLn('Log file at ', logFile.LogPath);
    logFile.Write(Format('Scan begin at: %s - %s'#13#10, [DateToStr(dtStart), TimeToStr(dtStart)]));
  end;

  WriteToLogAndConsole(@logFile, Format('Total files OK: %d', [totalOK]));
  if totalBad > 0 then
    WriteToLogAndConsole(@logFile, Format('Total files bad: %d', [totalBad]), bScanWinDir)
  else
    WriteToLogAndConsole(@logFile, 'Total files bad: 0');

  // Process each bad file
  var bNeedReboot: Boolean := False;
  if totalBad > 0 then
  begin
    var bDelete: Boolean := False;
    if bScanWinDir then
    begin
      strQuestion := Format('Have %d bad NLS files. Do you want to copy it to TEMP directory %s and delete them?',
                            [totalBad, g_strTempPath]);
      if (MessageBox(GetConsoleWindow, PChar(strQuestion), 'Confirm copy and delete', MB_YESNO) = IDYES) then
        bDelete := True;
    end;

    var errCode: TErrorCodes;
    var strErrMsg: string;
    var strPath, strNewPath: string;
    for I := 0 to totalBad - 1 do
    begin
      strPath := arrBadFiles[I].strPath;
      WriteToLogAndConsole(@logFile, Format('File %s', [strPath]), bScanWinDir);

      strErrMsg := '';
      for errCode := Low(TErrorCodes) to High(TErrorCodes) do
        if errCode in arrBadFiles[I].NLSErrCode then
          strErrMsg := strErrMsg + #9 + TErrorDescriptions[errCode] + #13#10;

      WriteToLogAndConsole(@logFile, strErrMsg, bScanWinDir);

      // Ignore bad files which have error code is only OPEN_FILE_ERROR
      // Avoid delete valid Windows files
      if arrBadFiles[I].NLSErrCode = [OPEN_FILE_ERROR] then
        Continue;

      if bDelete then
      begin
        strNewPath := TPath.Combine(g_strTempPath, ExtractFileName(strPath));
        if CopyFile(PChar(strPath), PChar(strNewPath), False) then
          WriteToLogAndConsole(@logFile, Format('File copied to %s'#13#10, [strNewPath]), bScanWinDir);
        if not Winapi.Windows.DeleteFile(PChar(strPath)) then
        begin
          bNeedReboot := True;
          MoveFileEx(PChar(strPath), nil, MOVEFILE_DELAY_UNTIL_REBOOT);
          WriteToLogAndConsole(@logFile, Format('File %s will be deleted at next reboot'#13#10, [strPath]), bScanWinDir);
        end;
      end;
    end;
  end;

  if bNeedReboot then
    WriteLn('Some files could not be deleted. They will be deleted at next reboot.'#13#10'Please reboot Windows now.');

  if bScanWinDir then
  begin
    logFile.Write(Format('Scan end at: %s - %s'#13#10#13#10, [DateToStr(dtEnd), TimeToStr(dtEnd)]));
    logFile.Close;
  end;
end;

begin
  IsMultiThread := True;

  // Init global variables
  g_strExePath := ParamStr(0);
  g_strExeDir := ExtractFilePath(g_strExePath);
  g_strExeName := ExtractFileName(g_strExePath);
  g_strTempPath := TPath.GetTempPath;

  try
    Intro;
    Scan;
  except
    on E: Exception do
      WriteLn(E.ClassName, ': ', E.Message);
  end;

  Write(#13#10'Press Enter key to exit');
  ReadLn;
end.
