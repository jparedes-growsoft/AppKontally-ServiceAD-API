unit uPipeServer;

interface

uses
  Winapi.Windows, System.SysUtils, System.Classes;

type
  // Callback que procesa la petición y devuelve JSON
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
    constructor Create(const APipeName: string; AOnRequest: TOnPipeRequest; AStopEvent: THandle);
  end;

implementation

{ =================== Helpers de seguridad (SDDL) =================== }

type
  PSECURITY_DESCRIPTOR = Pointer;

{$WARN SYMBOL_PLATFORM OFF}
function ConvertStringSecurityDescriptorToSecurityDescriptorW(
  StringSecurityDescriptor: PWideChar;
  StringSDRevision: DWORD;
  var SecurityDescriptor: PSECURITY_DESCRIPTOR;
  SecurityDescriptorSize: PCardinal
): BOOL; stdcall; external 'advapi32.dll';
{$WARN SYMBOL_PLATFORM ON}

type
  TConvertSidToStringSidW = function(Sid: Pointer; var StringSid: LPWSTR): BOOL; stdcall;

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
    ok := LookupAccountNameW(nil, PWideChar(Account), pSid, SidSize, PWideChar(Domain), DomainSize, peUse);
    if not ok then
      Exit;

    Result := ConvertSidToStringSid_Str(pSid);
  finally
    FreeMem(pSid);
  end;
end;

// Construye SECURITY_ATTRIBUTES con DACL explícita para el pipe.
// Concede:
//  - SYSTEM (SY) y Administrators (BA): Full (GA)
//  - Cuenta del App Pool por USUARIO ESPECÍFICO (tu SID real) : Read/Write (GR,GW)
//  - (Opcional) SID de "IIS AppPool\AppKontallyPool" si existe: Read/Write (GR,GW)
function BuildPipeSA(out SA: SECURITY_ATTRIBUTES; out SD: PSECURITY_DESCRIPTOR): Boolean;
const
  // **TU SID real (KONTALLY\svc_WebBrokerAD)**
  APPPOOL_USER_SID = 'S-1-5-21-215823904-480249424-3313816966-1123';
var
  SDDL: UnicodeString;
  AppPoolIdentitySid: string;
begin
  SD := nil;

  // Intentar también el SID de la identidad virtual del App Pool (si alguna vez vuelves a ApplicationPoolIdentity)
  AppPoolIdentitySid := GetSidStringForAccount('IIS AppPool\AppKontallyPool'); // puede venir vacío

  // DACL base: SYSTEM/BA Full
  SDDL := 'D:(A;;GA;;;SY)(A;;GA;;;BA)';

  // Acceso RW para el usuario específico del App Pool
  if APPPOOL_USER_SID <> '' then
    SDDL := SDDL + '(A;;GRGW;;;' + APPPOOL_USER_SID + ')';

  // Acceso RW para el SID de la identidad de AppPool (solo si resolvió)
  if AppPoolIdentitySid <> '' then
    SDDL := SDDL + '(A;;GRGW;;;' + AppPoolIdentitySid + ')';

  Result := ConvertStringSecurityDescriptorToSecurityDescriptorW(PWideChar(SDDL), 1 {SDDL_REVISION_1}, SD, nil);
  if Result then
  begin
    ZeroMemory(@SA, SizeOf(SA));
    SA.nLength := SizeOf(SA);
    SA.bInheritHandle := False;
    SA.lpSecurityDescriptor := SD;
  end;
end;

{ =================== Implementación del servidor de pipe =================== }

constructor TPipeServerThread.Create(const APipeName: string; AOnRequest: TOnPipeRequest; AStopEvent: THandle);
begin
  inherited Create(True); // Suspendido
  FreeOnTerminate := False;
  FPipeName := APipeName; // Ej: '\\.\pipe\AppKontallyAD'
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
    pSA := nil; // Fallback a DACL por defecto si fallara la construcción

  Result := CreateNamedPipe(
    PChar(FPipeName),
    PIPE_ACCESS_DUPLEX,
    PIPE_TYPE_MESSAGE or PIPE_READMODE_MESSAGE or PIPE_WAIT,
    1,       // una instancia (igual que antes)
    BUFSIZE, // out buffer
    BUFSIZE, // in buffer
    0,       // default timeout
    pSA
  );

  // La seguridad ya se aplicó al handle; liberar SD
  if SD <> nil then
    LocalFree(HLOCAL(SD));
end;

procedure TPipeServerThread.HandleClient(hPipe: THandle);
var
  InBuf: TBytes;
  BytesRead, BytesWritten: DWORD;
  Line, Reply: string;
  OutBytes: TBytes;
begin
  SetLength(InBuf, 64 * 1024);
  while not Terminated do
  begin
    if not ReadFile(hPipe, InBuf[0], Length(InBuf), BytesRead, nil) then
      Exit; // cliente cerró
    if BytesRead = 0 then
      Exit;

    // === UTF-8 puro: convierte el buffer recibido a Unicode correctamente ===
    Line := TEncoding.UTF8.GetString(InBuf, 0, BytesRead).Trim;

    // Cierre controlado
    if SameText(Line, '#shutdown') then
      Exit;

    // Procesar y responder (JSON)
    Reply := '';
    if Assigned(FOnRequest) then
      Reply := FOnRequest(Line);
    if Reply = '' then
      Reply := 'OK: ' + Line;

    // === UTF-8 puro: serializa la respuesta en UTF-8, sin pérdidas ni mapeos ANSI ===
    OutBytes := TEncoding.UTF8.GetBytes(Reply + sLineBreak);
    if not WriteFile(hPipe, OutBytes[0], Length(OutBytes), BytesWritten, nil) then
      Exit;
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

