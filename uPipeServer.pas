unit uPipeServer;

interface

uses
  Winapi.Windows, System.SysUtils, System.Classes;

type
  TOnPipeRequest = procedure(const Payload: string) of object;

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
function ConvertStringSecurityDescriptorToSecurityDescriptorW(
  StringSecurityDescriptor: PWideChar;
  StringSDRevision: DWORD;
  var SecurityDescriptor: PSECURITY_DESCRIPTOR;
  SecurityDescriptorSize: PULONG
): BOOL; stdcall; external 'advapi32.dll';
{$WARN SYMBOL_PLATFORM ON}

function BuildPipeSA(out SA: SECURITY_ATTRIBUTES; out SD: PSECURITY_DESCRIPTOR): Boolean;
const
  // SYSTEM y BUILTIN\Administrators: Full Access (GA)
  // Authenticated Users: Read + Write (GR|GW)
  PIPE_SDDL = 'D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)';
  SDDL_REVISION_1 = 1;
begin
  SD := nil;
  Result := ConvertStringSecurityDescriptorToSecurityDescriptorW(
              PWideChar(PIPE_SDDL),
              SDDL_REVISION_1,
              SD,
              nil);
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
  FPipeName := APipeName;   // '\\.\pipe\AppKontallyAD'
  FOnRequest := AOnRequest; // callback al servicio
  FStopEvent := AStopEvent; // evento de parada del servicio
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
  // DACL explícita para permitir conexiones desde la identidad del App Pool
  SD := nil;
  HasSA := BuildPipeSA(SA, SD);
  if HasSA then
    pSA := @SA
  else
    pSA := nil;

  Result := CreateNamedPipe(
    PChar(FPipeName),
    PIPE_ACCESS_DUPLEX,
    PIPE_TYPE_MESSAGE or PIPE_READMODE_MESSAGE or PIPE_WAIT,
    1,         // una instancia
    BUFSIZE,   // out buffer
    BUFSIZE,   // in buffer
    0,         // default timeout
    pSA
  );

  // Liberar SD asignado por advapi32
  if SD <> nil then
    LocalFree(HLOCAL(SD));
end;

procedure TPipeServerThread.HandleClient(hPipe: THandle);
var
  InBuf: TBytes;
  BytesRead: DWORD;
  S: AnsiString;
  Line: string;
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

    if Assigned(FOnRequest) then
      FOnRequest(Line);

    S := AnsiString('OK: ' + Line + sLineBreak);
    WriteFile(hPipe, PAnsiChar(S)^, Length(S), BytesRead, nil);
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

