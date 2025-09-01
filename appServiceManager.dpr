program appServiceManager;

uses
  Vcl.SvcMgr,
  uService in 'uService.pas' {AppKontallyServiceManager: TService},
  uADSIUser in 'uADSIUser.pas',
  uLogSanitizer in '..\isapi\Shared\Utils\uLogSanitizer.pas',
  uPipeServer in 'uPipeServer.pas';

{$R *.RES}

begin
  if not Application.DelayInitialize or Application.Installing then
    Application.Initialize;
  Application.CreateForm(TAppKontallyServiceManager, AppKontallyServiceManager);
  Application.Run;
end.
