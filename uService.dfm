object AppKontallyServiceManager: TAppKontallyServiceManager
  DisplayName = 'AppKontallyServiceManager'
  AfterInstall = ServiceAfterInstall
  OnContinue = ServiceContinue
  OnExecute = ServiceExecute
  OnPause = ServicePause
  OnStart = ServiceStart
  OnStop = ServiceStop
  Height = 229
  Width = 334
end
