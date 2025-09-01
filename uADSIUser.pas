unit uADSIUser;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  ActiveX,   // IDispatch
  ComObj,    // CreateOleObject, EOleException
  System.Variants; // OleVariant en las firmas

type
  // acepta métodos de objeto (Self.EscribirLog)
  TLogProc = procedure(const S: string) of object;

procedure ADSI_SetLogger(const AProc: TLogProc);

procedure CreateUserReal_ADSI(const FriendlyName, Sam, UPN, Password, OU_DN,
  GroupSam: string);
procedure EnableAdAccount(const UserObj: OleVariant);

implementation

const
  GROUP_CN_CONTAINER = 'CN=Users';
  DOMAIN_NETBIOS     = 'KONTALLY';

  ADS_UF_ACCOUNTDISABLE      = $0002;
  ADS_UF_PASSWD_NOTREQD      = $0020;
  ADS_UF_NORMAL_ACCOUNT      = $0200;
  ADS_UF_DONT_EXPIRE_PASSWD  = $10000;

  // GUID de IDispatch (por si la RTL no lo expone)
  IID_IDispatch: TGUID = '{00020400-0000-0000-C000-000000000046}';

var
  GLog: TLogProc = nil;

procedure ADSI_SetLogger(const AProc: TLogProc);
begin
  GLog := AProc;
end;

procedure _Log(const S: string);
begin
  if Assigned(GLog) then
    GLog('[uADSIUser] ' + S)
  else
    OutputDebugString(PChar('[uADSIUser] ' + S));
end;

function CoGetObject(const pszName: PWideChar; pBindOptions: Pointer;
  const iid: TGUID; out pv): HResult; stdcall; external 'ole32.dll';

function OleGetObject(const Name: WideString): IDispatch;
var
  hr: HResult;
begin
  Result := nil;
  hr := CoGetObject(PWideChar(Name), nil, IID_IDispatch, Result);
  if Failed(hr) then
    raise Exception.CreateFmt('CoGetObject failed (0x%.8x) for "%s"',
      [Cardinal(hr), Name]);
end;

function GetDomainDNFromOU(const OU_DN: string): string;
var
  p: Integer;
begin
  p := Pos('DC=', OU_DN);
  if p > 0 then
    Result := Copy(OU_DN, p, MaxInt)
  else
    Result := OU_DN;
end;

procedure EnableAdAccount(const UserObj: OleVariant);
var
  uac: Integer;
begin
  // Validación crítica para prevenir access violation
  if VarIsNull(UserObj) or VarIsEmpty(UserObj) then
    raise Exception.Create('EnableAdAccount: UserObj is null or empty');

  try
    uac := UserObj.Get('userAccountControl');
    uac := uac and (not ADS_UF_ACCOUNTDISABLE);
    uac := uac and (not ADS_UF_PASSWD_NOTREQD);
    UserObj.Put('userAccountControl', uac);
  except
    on E: EOleException do
      raise Exception.CreateFmt('EnableAdAccount failed (HRESULT=0x%.8x): %s',
        [Cardinal(E.ErrorCode), E.Message]);
    on E: Exception do
      raise Exception.CreateFmt('EnableAdAccount failed: %s', [E.Message]);
  end;
end;

// --- Password con fallback WinNT ---
procedure SetUserPassword_WithFallback(const DomainNetbios, Sam,
  Password: string; const LdapUserObj: OleVariant);
var
  WinNTUser: OleVariant;
begin
  // Validación crítica
  if VarIsNull(LdapUserObj) or VarIsEmpty(LdapUserObj) then
    raise Exception.Create('SetUserPassword_WithFallback: LdapUserObj is null');

  // 1) Intento por LDAP (IADsUser.SetPassword)
  try
    _Log('SetPassword via LDAP -> inicio');
    LdapUserObj.SetPassword(Password);
    _Log('SetPassword via LDAP -> ok');
    Exit;
  except
    on E: EOleException do
      _Log(Format('SetPassword via LDAP FALLÓ (HRESULT=0x%.8x): %s',
        [Cardinal(E.ErrorCode), E.Message]));
    on E: Exception do
      _Log('SetPassword via LDAP FALLÓ: ' + E.ClassName + ': ' + E.Message);
  end;

  // 2) Fallback por WinNT (SAM/RPC)
  WinNTUser := Null;
  try
    _Log(Format('SetPassword via WinNT -> WinNT://%s/%s,user',
      [DomainNetbios, Sam]));
    WinNTUser := OleGetObject(Format('WinNT://%s/%s,user',
      [DomainNetbios, Sam]));

    if VarIsNull(WinNTUser) or VarIsEmpty(WinNTUser) then
      raise Exception.Create('Failed to get WinNT user object');

    WinNTUser.SetPassword(Password);
    _Log('SetPassword via WinNT -> ok');
  except
    on E: EOleException do
      raise Exception.CreateFmt(
        'SetPassword via WinNT FALLÓ (HRESULT=0x%.8x): %s',
        [Cardinal(E.ErrorCode), E.Message]);
    on E: Exception do
      raise;
  end;
end;

// --- UAC con fallback WinNT (UserFlags + AccountDisabled) ---
procedure SetUserUAC_WithFallback(const DomainNetbios, Sam: string;
  const LdapUserObj: OleVariant; const DesiredUac: Integer);
var
  WinNTUser: OleVariant;
  Flags: Integer;
begin
  // Validación crítica
  if VarIsNull(LdapUserObj) or VarIsEmpty(LdapUserObj) then
    raise Exception.Create('SetUserUAC_WithFallback: LdapUserObj is null');

  // 1) Intento por LDAP
  try
    _Log(Format('Set UAC via LDAP -> 0x%.8x', [DesiredUac]));
    LdapUserObj.Put('userAccountControl', DesiredUac);
    _Log('Set UAC via LDAP -> ok');
    Exit;
  except
    on E: EOleException do
      _Log(Format('Set UAC via LDAP FALLÓ (HRESULT=0x%.8x): %s',
        [Cardinal(E.ErrorCode), E.Message]));
    on E: Exception do
      _Log('Set UAC via LDAP FALLÓ: ' + E.ClassName + ': ' + E.Message);
  end;

  // 2) Fallback por WinNT (propiedad UserFlags + AccountDisabled)
  WinNTUser := Null;
  try
    _Log(Format('Set UAC via WinNT (UserFlags) -> 0x%.8x', [DesiredUac]));
    WinNTUser := OleGetObject(Format('WinNT://%s/%s,user',
      [DomainNetbios, Sam]));

    if VarIsNull(WinNTUser) or VarIsEmpty(WinNTUser) then
      raise Exception.Create('Failed to get WinNT user object for UAC');

    try
      Flags := WinNTUser.Get('UserFlags');
    except
      Flags := 0;
    end;
    Flags := Flags or ADS_UF_NORMAL_ACCOUNT or ADS_UF_DONT_EXPIRE_PASSWD;
    Flags := Flags and (not ADS_UF_ACCOUNTDISABLE) and (not ADS_UF_PASSWD_NOTREQD);

    WinNTUser.Put('UserFlags', Flags);
    // Asegura explícitamente habilitación si la propiedad existe
    try
      WinNTUser.AccountDisabled := False;
    except
      // Ignorar si el proveedor no expone la propiedad
    end;
    WinNTUser.SetInfo;
    _Log('Set UAC via WinNT -> ok');
  except
    on E: EOleException do
      raise Exception.CreateFmt('Set UAC via WinNT FALLÓ (HRESULT=0x%.8x): %s',
        [Cardinal(E.ErrorCode), E.Message]);
    on E: Exception do
      raise;
  end;
end;

function FindGroupDNBySam(const GroupSam, DomainDN: string): string;
var
  Conn, Cmd, RS: OleVariant;
  Query: string;
begin
  Result := '';

  // Inicializar como Null explícitamente
  Conn := Null;
  Cmd := Null;
  RS := Null;

  try
    try
      Conn := CreateOleObject('ADODB.Connection');
      if VarIsNull(Conn) or VarIsEmpty(Conn) then
        raise Exception.Create('Failed to create ADODB.Connection');

      Conn.Provider := 'ADsDSOObject';
      Conn.Open('Active Directory Provider');

      Cmd := CreateOleObject('ADODB.Command');
      if VarIsNull(Cmd) or VarIsEmpty(Cmd) then
        raise Exception.Create('Failed to create ADODB.Command');

      Cmd.ActiveConnection := Conn;
      // Busca por sAMAccountName en todo el dominio
      Query := Format('<LDAP://%s>;(sAMAccountName=%s);distinguishedName;subtree',
        [DomainDN, GroupSam]);
      Cmd.CommandText := Query;

      RS := Cmd.Execute;
      if not VarIsNull(RS) and not VarIsEmpty(RS) and (not RS.EOF) then
        Result := RS.Fields['distinguishedName'].Value;
    except
      on E: EOleException do
        _Log(Format('FindGroupDNBySam failed (HRESULT=0x%.8x): %s',
          [Cardinal(E.ErrorCode), E.Message]));
      on E: Exception do
        _Log('FindGroupDNBySam failed: ' + E.Message);
    end;
  finally
    // Cleanup garantizado en orden inverso
    if not VarIsNull(RS) and not VarIsEmpty(RS) then
    begin
      try
        RS.Close;
      except
        // Ignorar errores de cleanup
      end;
    end;

    if not VarIsNull(Conn) and not VarIsEmpty(Conn) then
    begin
      try
        Conn.Close;
      except
        // Ignorar errores de cleanup
      end;
    end;
  end;
end;

procedure AddUserToGroup(const UserObj: OleVariant;
  const GroupSam, DomainDN: string);
var
  GroupPath, GroupDN: string;
  GroupObj: OleVariant;
begin
  if Trim(GroupSam) = '' then Exit;

  // Validación crítica
  if VarIsNull(UserObj) or VarIsEmpty(UserObj) then
    raise Exception.Create('AddUserToGroup: UserObj is null');

  // 1) Intento rápido: CN=Users
  GroupPath := Format('LDAP://CN=%s,%s,%s', [GroupSam, GROUP_CN_CONTAINER, DomainDN]);
  GroupObj := Null;
  try
    _Log('ADSI: Group.Add (CN=Users) -> ' + GroupPath);
    GroupObj := OleGetObject(GroupPath);
    if VarIsNull(GroupObj) or VarIsEmpty(GroupObj) then
      raise Exception.Create('Failed to get group object');

    GroupObj.Add(UserObj.ADsPath); // IADsGroup.Add
    _Log('ADSI: Group.Add (CN=Users) ok');
    Exit;
  except
    on E: EOleException do
      _Log(Format('ADSI: Group.Add (CN=Users) FALLÓ (HRESULT=0x%.8x): %s',
        [Cardinal(E.ErrorCode), E.Message]));
    on E: Exception do
      _Log('ADSI: Group.Add (CN=Users) FALLÓ: ' + E.ClassName + ': ' + E.Message);
  end;

  // 2) Fallback: buscar DN real
  GroupDN := FindGroupDNBySam(GroupSam, DomainDN);
  if GroupDN = '' then
    raise Exception.CreateFmt('No se encontró el grupo "%s" en el dominio.', [GroupSam]);

  GroupPath := 'LDAP://' + GroupDN;
  GroupObj := Null;
  try
    _Log('ADSI: Group.Add (DN real) -> ' + GroupPath);
    GroupObj := OleGetObject(GroupPath);
    if VarIsNull(GroupObj) or VarIsEmpty(GroupObj) then
      raise Exception.Create('Failed to get group object by DN');

    GroupObj.Add(UserObj.ADsPath);
    _Log('ADSI: Group.Add (DN real) ok');
  except
    on E: EOleException do
      raise Exception.CreateFmt('ADSI: Group.Add (DN real) FALLÓ (HRESULT=0x%.8x): %s',
        [Cardinal(E.ErrorCode), E.Message]);
    on E: Exception do
      raise;
  end;
end;

procedure CreateUserReal_ADSI(const FriendlyName, Sam, UPN, Password, OU_DN,
  GroupSam: string);
var
  OUObj, NewUser: OleVariant;
  CN, DomainDN: string;
  uac: Integer;
begin
  // Validación mínima
  if (Trim(FriendlyName) = '') or (Trim(Sam) = '') or (Trim(UPN) = '') or
     (Trim(Password) = '') or (Trim(OU_DN) = '') then
    raise Exception.Create('Parámetros insuficientes para crear el usuario.');

  // CN y DN del dominio
  CN := 'CN=' + FriendlyName;
  DomainDN := GetDomainDNFromOU(OU_DN);

  // Inicializar OleVariants como Null
  OUObj := Null;
  NewUser := Null;

  try
    // 1) Bind y Create
    _Log('ADSI: Bind OU -> LDAP://' + OU_DN);
    OUObj := OleGetObject('LDAP://' + OU_DN);
    if VarIsNull(OUObj) or VarIsEmpty(OUObj) then
      raise Exception.Create('Failed to bind to OU: ' + OU_DN);

    _Log('ADSI: Create user -> ' + CN);
    NewUser := OUObj.Create('user', CN);
    if VarIsNull(NewUser) or VarIsEmpty(NewUser) then
      raise Exception.Create('Failed to create user object in OU');

    // 2) Atributos mínimos
    _Log('ADSI: Put mínimos (sAM, UPN, displayName)');
    NewUser.Put('sAMAccountName', Sam);
    NewUser.Put('userPrincipalName', UPN);
    NewUser.Put('displayName', FriendlyName);

    // 3) Commit inicial
    _Log('ADSI: SetInfo -> post-minimos');
    NewUser.SetInfo;

    // 4) Password (LDAP -> WinNT fallback)
    SetUserPassword_WithFallback(DOMAIN_NETBIOS, Sam, Password, NewUser);

    _Log('ADSI: SetInfo -> post-SetPassword');
    NewUser.SetInfo;

    // 5) UAC normalize (cálculo)
    _Log('ADSI: userAccountControl normalize');
    try
      uac := NewUser.Get('userAccountControl');
    except
      uac := 0;
    end;

    uac := uac or ADS_UF_NORMAL_ACCOUNT or ADS_UF_DONT_EXPIRE_PASSWD;
    uac := uac and (not ADS_UF_ACCOUNTDISABLE) and (not ADS_UF_PASSWD_NOTREQD);

    // 6) Establecer UAC con fallback
    SetUserUAC_WithFallback(DOMAIN_NETBIOS, Sam, NewUser, uac);

    // 7) Commit final si se aplicó por LDAP (harmless si ya fue por WinNT)
    _Log('ADSI: SetInfo -> post-UAC');
    try
      NewUser.SetInfo;
    except
      // Si vino por WinNT, SetInfo LDAP puede no ser necesario; ignoramos error menor aquí.
      _Log('ADSI: SetInfo post-UAC ignorado (probablemente ya aplicado via WinNT)');
    end;

    // 8) Grupo
    if Trim(GroupSam) <> '' then
      AddUserToGroup(NewUser, GroupSam, DomainDN);

  except
    on E: EOleException do
      raise Exception.CreateFmt('CreateUserReal_ADSI failed (HRESULT=0x%.8x): %s',
        [Cardinal(E.ErrorCode), E.Message]);
    on E: Exception do
      raise Exception.CreateFmt('CreateUserReal_ADSI failed: %s', [E.Message]);
  end;
end;

end.
