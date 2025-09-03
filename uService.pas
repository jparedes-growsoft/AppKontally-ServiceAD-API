unit uService;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Classes, System.StrUtils,
  Vcl.Graphics, Vcl.Controls, Vcl.SvcMgr, Vcl.Dialogs, Winapi.WinSvc,
  Winapi.ShellAPI, System.NetEncoding, System.Win.Registry,
  System.IOUtils, System.JSON, ActiveX, ComObj,
  System.SyncObjs,
  // growsoft
  uPipeServer, uADSIUser, uLogSanitizer;

type
  TAppKontallyServiceManager = class(TService)
    procedure ServiceExecute(Sender: TService);
    procedure ServiceAfterInstall(Sender: TService);
    procedure ServiceStart(Sender: TService; var Started: Boolean);
    procedure ServiceStop(Sender: TService; var Stopped: Boolean);
    procedure ServicePause(Sender: TService; var Paused: Boolean);
    procedure ServiceContinue(Sender: TService; var Continued: Boolean);
  private
    FStopEvent: THandle;
    FLogPath: string;
    FLogCS: TCriticalSection;
    FPipeThread: TPipeServerThread;
  public
    function GetServiceController: TServiceController; override;

    // Devuelve JSON
    function ProcessRequest(const Request: string): string;

    procedure EscribirLog(const Mensaje: string);
    function JSONGetStr(const J: TJSONObject; const Name: string): string;
  end;

function CancelSynchronousIo(hThread: THandle): BOOL; stdcall;
  external kernel32 name 'CancelSynchronousIo';

var
  AppKontallyServiceManager: TAppKontallyServiceManager;

implementation

{$R *.dfm}

procedure ServiceController(CtrlCode: DWord); stdcall;
begin
  AppKontallyServiceManager.Controller(CtrlCode);
end;

procedure TAppKontallyServiceManager.EscribirLog(const Mensaje: string);
var
  FS: TFileStream;
  S: string;
  Bytes: TBytes;
begin
  if (FLogPath = '') or (FLogCS = nil) then
    Exit;
  try
    FLogCS.Acquire;
    try
      if TFile.Exists(FLogPath) then
        FS := TFileStream.Create(FLogPath, fmOpenReadWrite or fmShareDenyNone)
      else
        FS := TFileStream.Create(FLogPath, fmCreate or fmShareDenyNone);
      try
        FS.Seek(0, soEnd);
        S := FormatDateTime('yyyy-mm-dd hh:nn:ss.zzz', Now) + ' - ' + Mensaje + sLineBreak;
        Bytes := TEncoding.UTF8.GetBytes(S);
        FS.WriteBuffer(Bytes, Length(Bytes));
      finally
        FS.Free;
      end;
    finally
      FLogCS.Release;
    end;
  except
    // jamás romper por log
  end;
end;

function TAppKontallyServiceManager.GetServiceController: TServiceController;
begin
  Result := ServiceController;
end;

function TAppKontallyServiceManager.JSONGetStr(const J: TJSONObject;
  const Name: string): string;
var
  V: TJSONValue;
begin
  Result := '';
  if not Assigned(J) then Exit;
  V := J.GetValue(Name);
  if not Assigned(V) then Exit;

  if V is TJSONString then
    Result := TJSONString(V).Value
  else
    Result := V.Value;
end;

// ===== ProcessRequest (JSON IN -> JSON OUT) =====
function TAppKontallyServiceManager.ProcessRequest(const Request: string): string;
var
  JO: TJSONObject;
  Cmd: string;
  CleanReq: string;
  hr: HRESULT;
  needUninit: Boolean;

  function EscapeJsonString(const S: string): string;
  begin
    Result := S.Replace('\', '\\').Replace('"', '\"').Replace(#13#10, '\n')
      .Replace(#10, '\n').Replace(#13, '\n');
  end;

  // Helper robusto case-insensitive
  function JSONGetStrLocal(const J: TJSONObject; const Field: string): string;
  var
    V: TJSONValue;
    P: TJSONPair;
    i: Integer;
  begin
    Result := '';
    if not Assigned(J) then Exit;

    V := J.GetValue(Field);
    if not Assigned(V) then
      for i := 0 to J.Count - 1 do
      begin
        P := J.Pairs[i];
        if SameText(P.JsonString.Value, Field) then
        begin
          V := P.JsonValue;
          Break;
        end;
      end;

    if not Assigned(V) then Exit;

    if V is TJSONString then
      Result := TJSONString(V).Value
    else
      Result := V.Value;
  end;

  procedure FailLogAndExit(const ErrCode, Detail: string);
  begin
    EscribirLog(Format('ERROR: %s - %s', [ErrCode, Detail]));
    Result := Format('{"ok":false,"error":"%s","detail":"%s"}',
      [EscapeJsonString(ErrCode), EscapeJsonString(Detail)]);
  end;

  function BuildAppliedJSON(const JOIn: TJSONObject;
    const Keys: array of string): string;
  var
    JApplied: TJSONObject;
    k, v: string;
    i: Integer;
  begin
    JApplied := TJSONObject.Create;
    try
      for i := Low(Keys) to High(Keys) do
      begin
        k := Keys[i];
        v := JSONGetStrLocal(JOIn, k);
        if v <> '' then
          JApplied.AddPair(k, v);
      end;
      Result := JApplied.ToJSON;
    finally
      JApplied.Free;
    end;
  end;

var
  // comunes
  Name, Sam, Upn, Pwd, Ou, Group, Email: string;
  FirstName, LastName, Initials, Phone, Description, Title, Department, Company: string;
  DryRun: Boolean;
  DryRunVal: TJSONValue;
  sidStr, guidStr: string;

  // update
  DNUpdated: string;
  AppliedJSON: string;
begin
  // Limpieza y log de entrada (passwords redactadas por tu helper)
  CleanReq := Request.Replace(#0, '');
  EscribirLog('Pipe request: ' + RedactSecrets(CleanReq));

  JO := TJSONObject.ParseJSONValue(CleanReq) as TJSONObject;
  if JO = nil then
  begin
    Result := '{"ok":false,"error":"BAD_REQUEST","detail":"JSON inválido"}';
    EscribirLog('ERROR: JSON inválido');
    Exit;
  end;

  try
    Cmd := JSONGetStrLocal(JO, 'cmd');

    // dryRun por defecto TRUE si no viene
    DryRunVal := JO.GetValue('dryRun');
    if Assigned(DryRunVal) then
      DryRun := SameText(DryRunVal.Value, 'true')
    else
      DryRun := True;

    if SameText(Cmd, 'CreateUser') then
    begin
      // ===== CREATE =====
      Name := JSONGetStrLocal(JO, 'name');
      Sam := JSONGetStrLocal(JO, 'sam');
      Upn := JSONGetStrLocal(JO, 'upn');
      Pwd := JSONGetStrLocal(JO, 'password');
      Email := JSONGetStrLocal(JO, 'email');
      Ou := JSONGetStrLocal(JO, 'ou');
      Group := JSONGetStrLocal(JO, 'group');

      FirstName := JSONGetStrLocal(JO, 'firstName');
      LastName := JSONGetStrLocal(JO, 'lastName');
      Initials := JSONGetStrLocal(JO, 'initials');
      Phone := JSONGetStrLocal(JO, 'phone');
      Description := JSONGetStrLocal(JO, 'description');
      Title := JSONGetStrLocal(JO, 'title');
      Department := JSONGetStrLocal(JO, 'department');
      Company := JSONGetStrLocal(JO, 'company');

      if (Name = '') or (Sam = '') or (Upn = '') or (Pwd = '') or (Email = '') then
      begin
        Result := '{"ok":false,"error":"BAD_REQUEST","detail":"Faltan requeridos (name, sam, upn, password, email)"}';
        EscribirLog('CreateUser: parámetros incompletos (requiere email)');
        Exit;
      end;

      if DryRun then
      begin
        EscribirLog(Format('CreateUser(dryRun): Name=%s Sam=%s UPN=%s Email=%s OU=%s Group=%s',
          [Name, Sam, Upn, Email, Ou, Group]));
        Result := Format('{"ok":true,"action":"CreateUser","user":"%s","dryRun":true}',
          [EscapeJsonString(Sam)]);
        Exit;
      end;

      // COM init
      hr := CoInitializeEx(nil, COINIT_APARTMENTTHREADED);
      needUninit := (hr = S_OK) or (hr = S_FALSE);
      if Failed(hr) and (hr <> RPC_E_CHANGED_MODE) then
      begin
        FailLogAndExit('COM_INIT', Format('CoInitializeEx HRESULT=0x%.8x', [Cardinal(hr)]));
        Exit;
      end;

      try
        try
          CreateUserReal_ADSI(Name, Sam, Upn, Pwd, Email, Ou, Group, sidStr,
            guidStr, FirstName, LastName, Initials, Phone, Description, Title,
            Department, Company);

          EscribirLog(Format('CreateUser(REAL): creado %s en %s; agregado a %s; sid=%s; guid=%s',
            [Sam, Ou, Group, sidStr, guidStr]));

          Result := Format(
            '{"ok":true,"action":"CreateUser","user":"%s","sid":"%s","objectGuid":"%s","dryRun":false}',
            [EscapeJsonString(Sam), EscapeJsonString(sidStr), EscapeJsonString(guidStr)]
          );
        except
          on E: EOleException do
          begin
            EscribirLog(Format('CreateUser ERROR (EOleException): %s (HRESULT=0x%.8x)',
              [E.Message, Cardinal(EOleException(E).ErrorCode)]));
            Result := Format('{"ok":false,"error":"AD_ERROR","detail":"%s"}',
              [EscapeJsonString(E.Message)]);
          end;
          on E: Exception do
          begin
            EscribirLog('CreateUser ERROR: ' + E.ClassName + ': ' + E.Message);
            Result := Format('{"ok":false,"error":"INTERNAL_ERROR","detail":"%s"}',
              [EscapeJsonString(E.Message)]);
          end;
        end;
      finally
        if needUninit then
          CoUninitialize;
      end;
      Exit;
    end
    else
    if SameText(Cmd, 'UpdateUser') then
    begin
      // ===== UPDATE =====
      Sam := JSONGetStrLocal(JO, 'sam');
      Upn := JSONGetStrLocal(JO, 'upn');

      Email       := JSONGetStrLocal(JO, 'email');
      Name        := JSONGetStrLocal(JO, 'name');
      FirstName   := JSONGetStrLocal(JO, 'firstName');
      LastName    := JSONGetStrLocal(JO, 'lastName');
      Initials    := JSONGetStrLocal(JO, 'initials');
      Phone       := JSONGetStrLocal(JO, 'phone');
      Description := JSONGetStrLocal(JO, 'description');
      Title       := JSONGetStrLocal(JO, 'title');
      Department  := JSONGetStrLocal(JO, 'department');
      Company     := JSONGetStrLocal(JO, 'company');

      if (Sam = '') and (Upn = '') then
      begin
        Result := '{"ok":false,"error":"BAD_REQUEST","detail":"Se requiere sam o upn"}';
        EscribirLog('UpdateUser: faltan identificadores');
        Exit;
      end;

      // JSON de campos que vienen (para eco/applied)
      AppliedJSON := BuildAppliedJSON(JO,
        ['email','name','firstName','lastName','initials','phone','description','title','department','company']);

      if DryRun then
      begin
        EscribirLog(Format('UpdateUser(dryRun): sam=%s upn=%s applied=%s',
          [Sam, Upn, AppliedJSON]));
        Result := Format('{"ok":true,"action":"UpdateUser","sam":"%s","upn":"%s","dryRun":true,"applied":%s}',
          [EscapeJsonString(Sam), EscapeJsonString(Upn), AppliedJSON]);
        Exit;
      end;

      // COM init
      hr := CoInitializeEx(nil, COINIT_APARTMENTTHREADED);
      needUninit := (hr = S_OK) or (hr = S_FALSE);
      if Failed(hr) and (hr <> RPC_E_CHANGED_MODE) then
      begin
        FailLogAndExit('COM_INIT', Format('CoInitializeEx HRESULT=0x%.8x', [Cardinal(hr)]));
        Exit;
      end;

      try
        try
          UpdateUser_ADSI(Sam, Upn, Email, Name, FirstName, LastName, Initials, Phone,
            Description, Title, Department, Company, DNUpdated);

          EscribirLog(Format('UpdateUser(REAL): sam=%s upn=%s dn=%s applied=%s',
            [Sam, Upn, DNUpdated, AppliedJSON]));

          Result := Format(
            '{"ok":true,"action":"UpdateUser","sam":"%s","upn":"%s","dn":"%s","dryRun":false,"applied":%s}',
            [EscapeJsonString(Sam), EscapeJsonString(Upn),
             EscapeJsonString(DNUpdated), AppliedJSON]);
        except
          on E: EOleException do
          begin
            EscribirLog(Format('UpdateUser ERROR (EOleException): %s (HRESULT=0x%.8x)',
              [E.Message, Cardinal(EOleException(E).ErrorCode)]));
            Result := Format('{"ok":false,"error":"AD_ERROR","detail":"%s"}',
              [EscapeJsonString(E.Message)]);
          end;
          on E: Exception do
          begin
            EscribirLog('UpdateUser ERROR: ' + E.ClassName + ': ' + E.Message);
            Result := Format('{"ok":false,"error":"INTERNAL_ERROR","detail":"%s"}',
              [EscapeJsonString(E.Message)]);
          end;
        end;
      finally
        if needUninit then
          CoUninitialize;
      end;
      Exit;
    end
    else
    begin
      Result := '{"ok":false,"error":"UNSUPPORTED_CMD"}';
      EscribirLog('ERROR: cmd no soportado: ' + Cmd);
      Exit;
    end;

  finally
    JO.Free;
  end;
end;

procedure TAppKontallyServiceManager.ServiceAfterInstall(Sender: TService);
var
  Reg: TRegistry;
begin
  Reg := TRegistry.Create(KEY_READ or KEY_WRITE);
  try
    Reg.RootKey := HKEY_LOCAL_MACHINE;
    if Reg.OpenKey('SYSTEM\CurrentControlSet\Services\' + Name, False) then
    begin
      Reg.WriteString('Description',
        'Servicio de gestión automatizada de usuarios RDS-Users para aplicación AppKontally');
      Reg.CloseKey;
    end;
  finally
    Reg.Free;
  end;
end;

procedure TAppKontallyServiceManager.ServiceContinue(Sender: TService;
  var Continued: Boolean);
begin
  Continued := True;
end;

procedure TAppKontallyServiceManager.ServiceExecute(Sender: TService);
begin
  while not Terminated do
  begin
    ServiceThread.ProcessRequests(False);
    if WaitForSingleObject(FStopEvent, 1000) = WAIT_OBJECT_0 then
      Break;
    end;
  EscribirLog('ServiceExecute: loop finalizado.');
end;

procedure TAppKontallyServiceManager.ServicePause(Sender: TService;
  var Paused: Boolean);
begin
  Paused := True;
end;

procedure TAppKontallyServiceManager.ServiceStart(Sender: TService;
  var Started: Boolean);
var
  ProgramData, LogDir: string;
begin
  FStopEvent := CreateEvent(nil, True, False, nil);

  ProgramData := GetEnvironmentVariable('ProgramData');
  if ProgramData = '' then
    ProgramData := 'C:\ProgramData';
  LogDir := TPath.Combine(ProgramData, 'AppKontally\Logs');
  ForceDirectories(LogDir);
  FLogPath := TPath.Combine(LogDir, 'service.log');

  FLogCS := TCriticalSection.Create;

  ADSI_SetLogger(Self.EscribirLog);

  // FIX: el listener recibe función que devuelve JSON
  FPipeThread := TPipeServerThread.Create('\\.\pipe\AppKontallyAD',
    Self.ProcessRequest, FStopEvent);
  FPipeThread.FreeOnTerminate := False;
  FPipeThread.Start;

  Started := True;
  EscribirLog('ServiceStart: iniciado.');
end;

procedure TAppKontallyServiceManager.ServiceStop(Sender: TService;
  var Stopped: Boolean);
var
  hClient: THandle;
  Bytes: DWord;
  Msg: AnsiString;
  waitRes: DWord;
  PipeTerminated, AsyncTerminated: Boolean;
begin
  EscribirLog('ServiceStop: señalando stop...');

  PipeTerminated := True;
  AsyncTerminated := True;

  if FStopEvent <> 0 then
    SetEvent(FStopEvent);

  if Assigned(FPipeThread) then
  begin
    try
      if FPipeThread.Handle <> 0 then
        CancelSynchronousIo(FPipeThread.Handle);
    except
      // ignorar
    end;

    if WaitNamedPipe('\\.\pipe\AppKontallyAD', 150) then
    begin
      hClient := CreateFile('\\.\pipe\AppKontallyAD', GENERIC_READ or
        GENERIC_WRITE, 0, nil, OPEN_EXISTING, 0, 0);
      if hClient <> INVALID_HANDLE_VALUE then
      begin
        Msg := AnsiString('#shutdown' + sLineBreak);
        WriteFile(hClient, PAnsiChar(Msg)^, Length(Msg), Bytes, nil);
        CloseHandle(hClient);
      end;
    end;

    FPipeThread.Terminate;
    waitRes := WaitForSingleObject(FPipeThread.Handle, 5000);
    if waitRes = WAIT_TIMEOUT then
    begin
      PipeTerminated := False;
      EscribirLog('ServiceStop: WARNING - PipeThread no terminó en 5s (se continuará el apagado).');
    end
    else
    begin
      FreeAndNil(FPipeThread);
    end;
  end;

  if FStopEvent <> 0 then
  begin
    CloseHandle(FStopEvent);
    FStopEvent := 0;
  end;

  EscribirLog('ServiceStop: detenido limpio.');

  if (FLogCS <> nil) then
  begin
    if PipeTerminated and AsyncTerminated then
      FreeAndNil(FLogCS)
    else
    begin
      // dejar que el SO libere al terminar el proceso
    end;
  end;

  Stopped := True;
end;

end.
