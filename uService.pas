unit uService;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Classes,
  Vcl.Graphics, Vcl.Controls, Vcl.SvcMgr, Vcl.Dialogs, Winapi.WinSvc,
  Winapi.ShellAPI, System.NetEncoding, System.Win.Registry,
  System.IOUtils, System.JSON, ActiveX, ComObj,
  System.SyncObjs, // <-- NUEVO: para TCriticalSection
  // grosoft
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
    { Private declarations }
    FStopEvent: THandle;
    FPipe: THandle;
    FLogPath: string;
    FLogCS: TCriticalSection;
    // <-- cambiado de TRTLCriticalSection a TCriticalSection (objeto)
    FPipeThread: TPipeServerThread;
  public
    function GetServiceController: TServiceController; override;
    procedure ProcessRequest(const Request: string);
    procedure EscribirLog(const Mensaje: string);
    function JSONGetStr(const J: TJSONObject; const Name: string): string;
    { Public declarations }
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
  // Ruta preparada en ServiceStart
  if (FLogPath = '') or (FLogCS = nil) then
    Exit;

  // Protección total: aunque algo extraño pase, nunca propagamos excepción desde el logger
  try
    FLogCS.Acquire;
    try
      // Abrir/crear en modo append, compartido
      if TFile.Exists(FLogPath) then
        FS := TFileStream.Create(FLogPath, fmOpenReadWrite or fmShareDenyNone)
      else
        FS := TFileStream.Create(FLogPath, fmCreate or fmShareDenyNone);
      try
        FS.Seek(0, soEnd);
        S := FormatDateTime('yyyy-mm-dd hh:nn:ss.zzz', Now) + ' - ' + Mensaje +
          sLineBreak;
        Bytes := TEncoding.UTF8.GetBytes(S);
        FS.WriteBuffer(Bytes, Length(Bytes));
      finally
        FS.Free;
      end;
    finally
      FLogCS.Release;
    end;
  except
    // Silenciar cualquier problema de IO para no afectar al servicio
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
  if not Assigned(J) then
    Exit;
  V := J.GetValue(Name);
  if not Assigned(V) then
    Exit;

  if V is TJSONString then
    Result := TJSONString(V).Value
  else
    Result := V.Value; // fallback (por si viniera como otro tipo)
end;

procedure TAppKontallyServiceManager.ProcessRequest(const Request: string);
var
  JO: TJSONObject;
  Cmd, Name, Sam, Upn, Pwd, Ou, Group: string;
  DryRun: Boolean;
  CleanReq: string;
  DryRunVal: TJSONValue;
  hr: HRESULT;
  needUninit: Boolean;

  // Helper local para extraer strings de forma segura
  function JSONGetStrLocal(const J: TJSONObject; const Field: string): string;
  var
    V: TJSONValue;
  begin
    Result := '';
    if not Assigned(J) then
      Exit;
    V := J.GetValue(Field);
    if not Assigned(V) then
      Exit;

    if V is TJSONString then
      Result := TJSONString(V).Value
    else
      Result := V.Value; // fallback si viniera con otro tipo
  end;

begin
  // Limpieza de caracteres nulos que podrían romper el parser/log
  CleanReq := Request.Replace(#0, '');
  EscribirLog('Pipe request: ' + RedactSecrets(CleanReq));

  JO := TJSONObject.ParseJSONValue(CleanReq) as TJSONObject;
  if JO = nil then
  begin
    EscribirLog('ERROR: JSON inválido');
    Exit;
  end;

  try
    // Extracción robusta
    Cmd := JSONGetStrLocal(JO, 'cmd');
    Name := JSONGetStrLocal(JO, 'name');
    Sam := JSONGetStrLocal(JO, 'sam');
    Upn := JSONGetStrLocal(JO, 'upn');
    Pwd := JSONGetStrLocal(JO, 'password');
    Ou := JSONGetStrLocal(JO, 'ou');
    Group := JSONGetStrLocal(JO, 'group');

    // dryRun por defecto TRUE si no viene el campo
    DryRunVal := JO.GetValue('dryRun');
    if Assigned(DryRunVal) then
      DryRun := SameText(DryRunVal.Value, 'true')
    else
      DryRun := True;

    // Log de depuración (sin password)
    EscribirLog(Format('Parsed: cmd=%s; name=%s; sam=%s; upn=%s; dryRun=%s',
      [Cmd, Name, Sam, Upn, BoolToStr(DryRun, True)]));

    // Comando: CreateUser
    if SameText(Cmd, 'CreateUser') then
    begin
      // Validación mínima
      if (Name = '') or (Sam = '') or (Upn = '') or (Pwd = '') then
      begin
        EscribirLog('CreateUser: parámetros incompletos');
        Exit;
      end;

      if DryRun then
      begin
        EscribirLog
          (Format('CreateUser(dryRun): Name=%s Sam=%s UPN=%s OU=%s Group=%s',
          [Name, Sam, Upn, Ou, Group]));
        Exit;
      end;

      // --- Ejecución real (ADSI) ---
      hr := CoInitializeEx(nil, COINIT_APARTMENTTHREADED);
      needUninit := Succeeded(hr);
      if Failed(hr) and (hr <> RPC_E_CHANGED_MODE) then
      begin
        EscribirLog(Format('CreateUser: CoInitializeEx falló. HRESULT=0x%.8x',
          [Cardinal(hr)]));
        Exit;
      end;

      try
        try
          // Crear usuario y agregar al grupo (si Group no está vacío)
          CreateUserReal_ADSI(Name, Sam, Upn, Pwd, Ou, Group);
          EscribirLog(Format('CreateUser(REAL): creado %s en %s; agregado a %s',
            [Sam, Ou, Group]));
        except
          on E: EOleException do
            EscribirLog
              (Format('CreateUser ERROR (EOleException): %s (HRESULT=0x%.8x)',
              [E.Message, Cardinal(EOleException(E).ErrorCode)]));
          on E: Exception do
            EscribirLog('CreateUser ERROR: ' + E.ClassName + ': ' + E.Message);
        end;
      finally
        if needUninit then
          CoUninitialize;
      end;
    end
    else
    begin
      EscribirLog('ERROR: cmd no soportado: ' + Cmd);
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
    // Procesa mensajes del hilo del servicio (recomendado por VCL)
    ServiceThread.ProcessRequests(False);

    // Espera hasta 1s o hasta que el evento se señale
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
  // Evento de parada (manual-reset, no señalado)
  FStopEvent := CreateEvent(nil, True, False, nil);

  // Carpeta de logs bajo %ProgramData%\AppKontally\Logs
  ProgramData := GetEnvironmentVariable('ProgramData');
  if ProgramData = '' then
    ProgramData := 'C:\ProgramData';
  LogDir := TPath.Combine(ProgramData, 'AppKontally\Logs');
  ForceDirectories(LogDir);
  FLogPath := TPath.Combine(LogDir, 'service.log');

  // Critical Section para log (CREAR ANTES DE INICIAR HILOS)
  FLogCS := TCriticalSection.Create;

  ADSI_SetLogger(Self.EscribirLog);

  // Iniciar listener de Named Pipe (hilo dedicado, no bloqueante)
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

  // 1) Señalar el evento de parada (para que el hilo del pipe y otros bucles salgan)
  if FStopEvent <> 0 then
    SetEvent(FStopEvent);

  // 2) Detener el hilo del pipe: cancelar I/O y "despertarlo"
  if Assigned(FPipeThread) then
  begin
    try
      if FPipeThread.Handle <> 0 then
        CancelSynchronousIo(FPipeThread.Handle);
    except
      // no permitir que una excepción aquí rompa el stop
    end;

    // Despertar la instancia de pipe si está esperando
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

    // Pedimos terminar y esperamos con timeout
    FPipeThread.Terminate;
    waitRes := WaitForSingleObject(FPipeThread.Handle, 5000);
    if waitRes = WAIT_TIMEOUT then
    begin
      PipeTerminated := False;
      EscribirLog
        ('ServiceStop: WARNING - PipeThread no terminó en 5s (se continuará el apagado).');
      // no hacemos FreeAndNil para evitar liberar recursos de un hilo aún vivo
    end
    else
    begin
      FreeAndNil(FPipeThread);
    end;
  end;

  // 3) Detener el worker si lo activas más adelante -. FAsyncTasks

  // 4) Cerrar el handle del evento
  if FStopEvent <> 0 then
  begin
    CloseHandle(FStopEvent);
    FStopEvent := 0;
  end;

  // 5) Log final ANTES de destruir el critical section (si existe)
  EscribirLog('ServiceStop: detenido limpio.');

  // 6) Destruir el lock del logger SOLO si todos los hilos confirmaron salida
  if (FLogCS <> nil) then
  begin
    if PipeTerminated and AsyncTerminated then
    begin
      FreeAndNil(FLogCS);
    end
    else
    begin
      // Dejarlo sin liberar por seguridad (el proceso terminará y el SO limpiará recursos)
      // Esto evita la ventana de carrera que te producía el AV.
    end;
  end;

  Stopped := True;
end;

end.
