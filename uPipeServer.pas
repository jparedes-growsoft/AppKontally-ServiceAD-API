unit uPipeServer;

interface

uses
  Winapi.Windows, System.SysUtils, System.Classes;

type
  // FIX: callback ahora devuelve string (JSON)
  TOnPipeRequest = function(const Payload: string): string of object;

  TPipeServerThread = class(TThread)
  private
    FPipeName: string;
    FOnRequest: TOnPipeRequest;
    FStopEvent: THandle;
    function CreatePipeInstance: THandle;
    procedure HandleClient(hPipe: THandle);
  protected
    procedure Execute; override;
  public
    constructor Create(const APipeName: string; AOnRequest: TOnPipeRequest;
      AStopEvent: THandle);
  end;

implementation

{$WARN SYMBOL_PLATFORM OFF}
function ConvertStringSecurityDescriptorToSecurityDescriptorW
  (StringSecurityDescriptor: PWideChar; StringSDRevision: DWORD;
  var SecurityDescriptor: PSECURITY_DESCRIPTOR; SecurityDescriptorSize: PULONG)
  : BOOL; stdcall; external 'advapi32.dll';
{$WARN SYMBOL_PLATFORM ON}

type
  TConvertSidToStringSidW = function(Sid: Pointer; var StringSid: LPWSTR)
    : BOOL; stdcall;

function ConvertSidToStringSid_Str(Sid: Pointer): string;
var
  hAdvapi: HMODULE;
  Fn: TConvertSidToStringSidW;
  pStrSid: PWideChar;
begin
  Result := '';
  hAdvapi := GetModuleHandle('advapi32.dll');
  if hAdvapi = 0 then
    hAdvapi := LoadLibrary('advapi32.dll');
  if hAdvapi <> 0 then
  begin
    @Fn := GetProcAddress(hAdvapi, 'ConvertSidToStringSidW');
    if Assigned(Fn) then
    begin
      pStrSid := nil;
      if Fn(Sid, pStrSid) then
        try
          Result := pStrSid;
        finally
          if pStrSid <> nil then
            LocalFree(HLOCAL(pStrSid));
        end;
    end;
  end;
end;

function GetSidStringForAccount(const Account: string): string;
var
  SidSize, DomainSize: DWORD;
  peUse: SID_NAME_USE;
  pSid: Pointer;
  Domain: UnicodeString;
  ok: BOOL;
begin
  Result := '';
  SidSize := 0;
  DomainSize := 0;
  peUse := SidTypeInvalid;

  LookupAccountNameW(nil, PWideChar(Account), nil, SidSize, nil, DomainSize, peUse);
  if GetLastError <> ERROR_INSUFFICIENT_BUFFER then
    Exit;

  GetMem(pSid, SidSize);
  try
    SetLength(Domain, DomainSize);
    ok := LookupAccountNameW(nil, PWideChar(Account), pSid, SidSize,
      PWideChar(Domain), DomainSize, peUse);
    if not ok then
      Exit;

    Result := ConvertSidToStringSid_Str(pSid);
  finally
    FreeMem(pSid);
  end;
end;

function BuildPipeSA(out SA: SECURITY_ATTRIBUTES;
  out SD: PSECURITY_DESCRIPTOR): Boolean;
const
  SDDL_REVISION_1 = 1;
var
  SDDL: string;
  AppPoolSid: string;
begin
  SD := nil;

  // Permitir al AppPool específico conectarse al pipe
  AppPoolSid := GetSidStringForAccount('IIS AppPool\AppKontallyPool');
  if AppPoolSid = '' then
    Exit(False);

  // DACL: SYSTEM/Administrators = GA; AppPool = GR|GW
  SDDL := Format('D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;%s)', [AppPoolSid]);

  Result := ConvertStringSecurityDescriptorToSecurityDescriptorW
    (PWideChar(SDDL), SDDL_REVISION_1, SD, nil);
  if Result then
  begin
    SA.nLength := SizeOf(SA);
    SA.bInheritHandle := False;
    SA.lpSecurityDescriptor := SD;
  end;
end;

{ TPipeServerThread }

constructor TPipeServerThread.Create(const APipeName: string;
  AOnRequest: TOnPipeRequest; AStopEvent: THandle);
begin
  inherited Create(True); // suspendido
  FreeOnTerminate := False;
  FPipeName := APipeName; // ej: '\\.\pipe\AppKontallyAD'
  FOnRequest := AOnRequest;
  FStopEvent := AStopEvent;
end;

function TPipeServerThread.CreatePipeInstance: THandle;
const
  BUFSIZE = 64 * 1024;
var
  SA: SECURITY_ATTRIBUTES;
  SD: PSECURITY_DESCRIPTOR;
  HasSA: Boolean;
  pSA: PSecurityAttributes;
begin
  SD := nil;
  HasSA := BuildPipeSA(SA, SD);
  if HasSA then
    pSA := @SA
  else
    pSA := nil; // fallback a DACL por defecto

  Result := CreateNamedPipe(PChar(FPipeName), PIPE_ACCESS_DUPLEX,
    PIPE_TYPE_MESSAGE or PIPE_READMODE_MESSAGE or PIPE_WAIT,
    1, // una instancia
    BUFSIZE, // out buffer
    BUFSIZE, // in buffer
    0,       // default timeout
    pSA);

  if SD <> nil then
    LocalFree(HLOCAL(SD));
end;

procedure TPipeServerThread.HandleClient(hPipe: THandle);
var
  InBuf: TBytes;
  BytesRead, BytesWritten: DWORD;
  S: AnsiString;
  Line, Reply: string;
begin
  SetLength(InBuf, 64 * 1024);
  while not Terminated do
  begin
    if not ReadFile(hPipe, InBuf[0], Length(InBuf), BytesRead, nil) then
      Exit; // cliente cerró
    if BytesRead = 0 then
      Exit;

    SetString(S, PAnsiChar(@InBuf[0]), BytesRead);
    Line := Trim(string(S));

    // salida rápida si nos mandan "shutdown"
    if SameText(Line, '#shutdown') then
      Exit;

    // FIX PRINCIPAL: usar la respuesta del servicio
    Reply := '';
    if Assigned(FOnRequest) then
      Reply := FOnRequest(Line);

    // Solo usar fallback si no hay respuesta del callback
    if Reply = '' then
      Reply := 'OK: ' + Line;

    S := AnsiString(Reply + sLineBreak);
    WriteFile(hPipe, PAnsiChar(S)^, Length(S), BytesWritten, nil);
  end;
end;

procedure TPipeServerThread.Execute;
var
  hPipe: THandle;
begin
  while not Terminated do
  begin
    if (FStopEvent <> 0) and (WaitForSingleObject(FStopEvent, 0) = WAIT_OBJECT_0) then
      Break;

    hPipe := CreatePipeInstance;
    if hPipe = INVALID_HANDLE_VALUE then
    begin
      Sleep(300);
      Continue;
    end;

    if ConnectNamedPipe(hPipe, nil) or (GetLastError = ERROR_PIPE_CONNECTED) then
    begin
      try
        HandleClient(hPipe);
        FlushFileBuffers(hPipe);
      finally
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
      end;
    end
    else
    begin
      CloseHandle(hPipe);
      Sleep(200);
    end;
  end;
end;

end.
