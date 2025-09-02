object AppKontallyServiceManager: TAppKontallyServiceManager
  DisplayName = 'AppKontallyServiceManager'
  AfterInstall = ServiceAfterInstall
  OnContinue = ServiceContinue
  OnExecute = ServiceExecute
  OnPause = ServicePause
  OnStart = ServiceStart
  OnStop = ServiceStop
  Height = 515
  Width = 752
  PixelsPerInch = 216
end
