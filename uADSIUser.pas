unit uADSIUser;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  ActiveX, // IDispatch
  ComObj, // CreateOleObject, EOleException
  System.Variants; // OleVariant en las firmas

type
  // acepta métodos de objeto (Self.EscribirLog)
  TLogProc = procedure(const S: string) of object;

procedure ADSI_SetLogger(const AProc: TLogProc);

// CREATE
procedure CreateUserReal_ADSI(const FriendlyName, Sam, UPN, Password, Email,
  OU_DN, GroupSam: string; out UserSid, ObjectGuid: string;
  const FirstName: string = ''; const LastName: string = '';
  const Initials: string = ''; const Phone: string = '';
  const Description: string = ''; const Title: string = '';
  const Department: string = ''; const Company: string = '');

// UPDATE: UpdateUser para aplicar campos opcionales
procedure UpdateUser_ADSI(const Sam, UPN: string;
  const Email, FriendlyName, FirstName, LastName, Initials, Phone, Description,
  Title, Department, Company: string; out DistinguishedName: string);

// GET
procedure GetUserInfo_ADSI(const Sam, UPN: string;
  out DistinguishedName, SamAccountName, UserPrincipalName, Mail, DisplayName,
  GivenName, Surname, Initials, TelephoneNumber, Description, Title_,
  Department, Company, ObjectSid, ObjectGuid: string; out Enabled: Boolean);

// RESET PASSWORD
procedure ResetPassword_ADSI(const Sam, UPN, NewPassword: string;
  const ForceChangeAtNextLogon: Boolean; out DistinguishedName: string);

procedure EnableAdAccount(const UserObj: OleVariant);

implementation

const
  GROUP_CN_CONTAINER = 'CN=Users';
  DOMAIN_NETBIOS = 'KONTALLY';

  ADS_UF_ACCOUNTDISABLE = $0002;
  ADS_UF_PASSWD_NOTREQD = $0020;
  ADS_UF_NORMAL_ACCOUNT = $0200;
  ADS_UF_DONT_EXPIRE_PASSWD = $10000;

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

function GetDefaultNamingContext: string;
var
  Root: OleVariant;
begin
  Result := '';
  try
    Root := OleGetObject('LDAP://RootDSE');
    if not VarIsNull(Root) and not VarIsEmpty(Root) then
      Result := Root.Get('defaultNamingContext');
  except
    on E: Exception do
      _Log('GetDefaultNamingContext failed: ' + E.Message);
  end;
end;

procedure EnableAdAccount(const UserObj: OleVariant);
var
  uac: Integer;
begin
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

// === Helpers SID/GUID ===
{$WARN SYMBOL_PLATFORM OFF}
function ConvertSidToStringSidW(Sid: Pointer; var StringSid: PWideChar): BOOL;
  stdcall; external 'advapi32.dll';
{$WARN SYMBOL_PLATFORM ON}

function VariantToBytes(const V: OleVariant): TBytes;
var
  L, H: Integer;
  PData: Pointer;
begin
  SetLength(Result, 0);
  if not VarIsArray(V) then
    Exit;
  L := VarArrayLowBound(V, 1);
  H := VarArrayHighBound(V, 1);
  SetLength(Result, H - L + 1);
  if Length(Result) = 0 then
    Exit;
  PData := VarArrayLock(V);
  try
    Move(PByte(PData)^, Result[0], Length(Result));
  finally
    VarArrayUnlock(V);
  end;
end;

function SidBytesToString(const B: TBytes): string;
var
  pSid: Pointer;
  pStr: PWideChar;
begin
  Result := '';
  if Length(B) = 0 then
    Exit;
  GetMem(pSid, Length(B));
  try
    Move(B[0], pSid^, Length(B));
    pStr := nil;
    if ConvertSidToStringSidW(pSid, pStr) then
      try
        Result := pStr;
      finally
        if pStr <> nil then
          LocalFree(HLOCAL(pStr));
      end;
  finally
    FreeMem(pSid);
  end;
end;

function GuidBytesToString(const B: TBytes): string;
var
  G: TGUID;
begin
  Result := '';
  if Length(B) <> SizeOf(TGUID) then
    Exit;
  Move(B[0], G, SizeOf(TGUID));
  Result := GUIDToString(G);
end;

// --- Password con fallback WinNT ---
procedure SetUserPassword_WithFallback(const DomainNetbios, Sam,
  Password: string; const LdapUserObj: OleVariant);
var
  WinNTUser: OleVariant;
begin
  if VarIsNull(LdapUserObj) or VarIsEmpty(LdapUserObj) then
    raise Exception.Create('SetUserPassword_WithFallback: LdapUserObj is null');

  // 1) Intento por LDAP
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

  // 2) Fallback WinNT
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
      raise Exception.CreateFmt
        ('SetPassword via WinNT FALLÓ (HRESULT=0x%.8x): %s',
        [Cardinal(E.ErrorCode), E.Message]);
    on E: Exception do
      raise;
  end;
end;

// --- UAC con fallback WinNT ---
procedure SetUserUAC_WithFallback(const DomainNetbios, Sam: string;
  const LdapUserObj: OleVariant; const DesiredUac: Integer);
var
  WinNTUser: OleVariant;
  Flags: Integer;
begin
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

  // 2) Fallback por WinNT
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
    Flags := Flags and (not ADS_UF_ACCOUNTDISABLE) and
      (not ADS_UF_PASSWD_NOTREQD);

    WinNTUser.Put('UserFlags', Flags);
    try
      WinNTUser.AccountDisabled := False;
    except
      // algunos proveedores no exponen la propiedad
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
  Conn := Null;
  Cmd := Null;
  RS := Null;

  try
    try
      Conn := CreateOleObject('ADODB.Connection');
      Conn.Provider := 'ADsDSOObject';
      Conn.Open('Active Directory Provider');

      Cmd := CreateOleObject('ADODB.Command');
      Cmd.ActiveConnection := Conn;

      Query := Format
        ('<LDAP://%s>;(sAMAccountName=%s);distinguishedName;subtree',
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
    if not VarIsNull(RS) and not VarIsEmpty(RS) then
      try
        RS.Close;
      except
      end;
    if not VarIsNull(Conn) and not VarIsEmpty(Conn) then
      try
        Conn.Close;
      except
      end;
  end;
end;

procedure AddUserToGroup(const UserObj: OleVariant;
  const GroupSam, DomainDN: string);
var
  GroupPath, GroupDN: string;
  GroupObj: OleVariant;
begin
  if Trim(GroupSam) = '' then
    Exit;

  if VarIsNull(UserObj) or VarIsEmpty(UserObj) then
    raise Exception.Create('AddUserToGroup: UserObj is null');

  // 1) Intento rápido: CN=Users
  GroupPath := Format('LDAP://CN=%s,%s,%s', [GroupSam, GROUP_CN_CONTAINER,
    DomainDN]);
  GroupObj := Null;
  try
    _Log('ADSI: Group.Add (CN=Users) -> ' + GroupPath);
    GroupObj := OleGetObject(GroupPath);
    if VarIsNull(GroupObj) or VarIsEmpty(GroupObj) then
      raise Exception.Create('Failed to get group object');

    GroupObj.Add(UserObj.ADsPath);
    _Log('ADSI: Group.Add (CN=Users) ok');
    Exit;
  except
    on E: EOleException do
      _Log(Format('ADSI: Group.Add (CN=Users) FALLÓ (HRESULT=0x%.8x): %s',
        [Cardinal(E.ErrorCode), E.Message]));
    on E: Exception do
      _Log('ADSI: Group.Add (CN=Users) FALLÓ: ' + E.ClassName + ': ' +
        E.Message);
  end;

  // 2) Fallback: buscar DN real
  GroupDN := FindGroupDNBySam(GroupSam, DomainDN);
  if GroupDN = '' then
    raise Exception.CreateFmt('No se encontró el grupo "%s" en el dominio.',
      [GroupSam]);

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
      raise Exception.CreateFmt
        ('ADSI: Group.Add (DN real) FALLÓ (HRESULT=0x%.8x): %s',
        [Cardinal(E.ErrorCode), E.Message]);
    on E: Exception do
      raise;
  end;
end;

// === Crear usuario + devolver SID y objectGUID ===
procedure CreateUserReal_ADSI(const FriendlyName, Sam, UPN, Password, Email,
  OU_DN, GroupSam: string; out UserSid, ObjectGuid: string;
  const FirstName: string = ''; const LastName: string = '';
  const Initials: string = ''; const Phone: string = '';
  const Description: string = ''; const Title: string = '';
  const Department: string = ''; const Company: string = '');
var
  OUObj, NewUser: OleVariant;
  CN, DomainDN: string;
  uac: Integer;
  V: OleVariant;
  B: TBytes;
begin
  UserSid := '';
  ObjectGuid := '';

  if (Trim(FriendlyName) = '') or (Trim(Sam) = '') or (Trim(UPN) = '') or
    (Trim(Password) = '') or (Trim(Email) = '') or (Trim(OU_DN) = '') then
    raise Exception.Create
      ('Parámetros insuficientes (falta uno de: name, sam, upn, password, email, ou).');

  CN := 'CN=' + FriendlyName;
  DomainDN := GetDomainDNFromOU(OU_DN);

  OUObj := Null;
  NewUser := Null;

  try
    // 1) Bind OU y crear objeto usuario
    _Log('ADSI: Bind OU -> LDAP://' + OU_DN);
    OUObj := OleGetObject('LDAP://' + OU_DN);
    if VarIsNull(OUObj) or VarIsEmpty(OUObj) then
      raise Exception.Create('Failed to bind to OU: ' + OU_DN);

    _Log('ADSI: Create user -> ' + CN);
    NewUser := OUObj.Create('user', CN);
    if VarIsNull(NewUser) or VarIsEmpty(NewUser) then
      raise Exception.Create('Failed to create user object in OU');

    // 2) Atributos mínimos + identidad
    _Log('ADSI: Put mínimos + identidad');
    NewUser.Put('sAMAccountName', Sam);
    NewUser.Put('userPrincipalName', UPN);
    NewUser.Put('displayName', FriendlyName);
    NewUser.Put('mail', Email);

    if Trim(FirstName) <> '' then
      NewUser.Put('givenName', FirstName);
    if Trim(LastName) <> '' then
      NewUser.Put('sn', LastName);
    if Trim(Initials) <> '' then
      NewUser.Put('initials', Initials);

    // 3) Commit inicial
    _Log('ADSI: SetInfo -> post-minimos');
    NewUser.SetInfo;

    // 4) Password (LDAP -> WinNT fallback)
    SetUserPassword_WithFallback(DOMAIN_NETBIOS, Sam, Password, NewUser);
    _Log('ADSI: SetInfo -> post-SetPassword');
    NewUser.SetInfo;

    // 5) Opcionales adicionales
    if Trim(Phone) <> '' then
      NewUser.Put('telephoneNumber', Phone);
    if Trim(Description) <> '' then
      NewUser.Put('description', Description);
    if Trim(Title) <> '' then
      NewUser.Put('title', Title);
    if Trim(Department) <> '' then
      NewUser.Put('department', Department);
    if Trim(Company) <> '' then
      NewUser.Put('company', Company);

    // 6) Commit de opcionales
    _Log('ADSI: SetInfo -> post-opcionales');
    try
      NewUser.SetInfo;
    except
      _Log('ADSI: SetInfo post-opcionales ignorado si no hay cambios');
    end;

    // 7) Normalizar UAC (habilitado + no expira)
    _Log('ADSI: userAccountControl normalize');
    try
      uac := NewUser.Get('userAccountControl');
    except
      uac := 0;
    end;
    uac := uac or ADS_UF_NORMAL_ACCOUNT or ADS_UF_DONT_EXPIRE_PASSWD;
    uac := uac and (not ADS_UF_ACCOUNTDISABLE) and (not ADS_UF_PASSWD_NOTREQD);
    SetUserUAC_WithFallback(DOMAIN_NETBIOS, Sam, NewUser, uac);

    // 8) Commit final (si aplica por LDAP)
    _Log('ADSI: SetInfo -> post-UAC');
    try
      NewUser.SetInfo;
    except
      _Log('ADSI: SetInfo post-UAC ignorado (posible vía WinNT)');
    end;

    // 9) Grupo predeterminado (si viene)
    if Trim(GroupSam) <> '' then
      AddUserToGroup(NewUser, GroupSam, DomainDN);

    // 10) Capturar SID y GUID
    try
      V := NewUser.Get('objectSid');
      B := VariantToBytes(V);
      UserSid := SidBytesToString(B);
      _Log('ADSI: objectSid -> ' + UserSid);
    except
      _Log('ADSI: objectSid lectura falló');
    end;

    try
      V := NewUser.Get('objectGUID');
      B := VariantToBytes(V);
      ObjectGuid := GuidBytesToString(B);
      _Log('ADSI: objectGUID -> ' + ObjectGuid);
    except
      _Log('ADSI: objectGUID lectura falló');
    end;

  except
    on E: EOleException do
      raise Exception.CreateFmt
        ('CreateUserReal_ADSI failed (HRESULT=0x%.8x): %s',
        [Cardinal(E.ErrorCode), E.Message]);
    on E: Exception do
      raise Exception.CreateFmt('CreateUserReal_ADSI failed: %s', [E.Message]);
  end;
end;

// === Buscar DN de usuario por sam o upn ===
function FindUserDN(const Sam, UPN, DomainDN: string): string;
var
  Conn, Cmd, RS: OleVariant;
  Query: string;
begin
  Result := '';
  Conn := Null;
  Cmd := Null;
  RS := Null;

  try
    try
      Conn := CreateOleObject('ADODB.Connection');
      Conn.Provider := 'ADsDSOObject';
      Conn.Open('Active Directory Provider');

      Cmd := CreateOleObject('ADODB.Command');
      Cmd.ActiveConnection := Conn;

      if Trim(Sam) <> '' then
        Query := Format
          ('<LDAP://%s>;(sAMAccountName=%s);distinguishedName;subtree',
          [DomainDN, Sam])
      else
        Query := Format
          ('<LDAP://%s>;(userPrincipalName=%s);distinguishedName;subtree',
          [DomainDN, UPN]);

      Cmd.CommandText := Query;

      RS := Cmd.Execute;
      if not VarIsNull(RS) and not VarIsEmpty(RS) and (not RS.EOF) then
        Result := RS.Fields['distinguishedName'].Value;
    except
      on E: EOleException do
        _Log(Format('FindUserDN failed (HRESULT=0x%.8x): %s',
          [Cardinal(E.ErrorCode), E.Message]));
      on E: Exception do
        _Log('FindUserDN failed: ' + E.Message);
    end;
  finally
    if not VarIsNull(RS) and not VarIsEmpty(RS) then
      try
        RS.Close;
      except
      end;
    if not VarIsNull(Conn) and not VarIsEmpty(Conn) then
      try
        Conn.Close;
      except
      end;
  end;
end;

// === Update de atributos básicos (sin password) ===
procedure UpdateUser_ADSI(const Sam, UPN: string;
  const Email, FriendlyName, FirstName, LastName, Initials, Phone, Description,
  Title, Department, Company: string; out DistinguishedName: string);
var
  DomainDN, UserDN: string;
  UserObj: OleVariant;
begin
  DistinguishedName := '';

  if (Trim(Sam) = '') and (Trim(UPN) = '') then
    raise Exception.Create('UpdateUser_ADSI: se requiere sam o upn');

  DomainDN := GetDefaultNamingContext;
  if DomainDN = '' then
    raise Exception.Create
      ('UpdateUser_ADSI: no se pudo obtener defaultNamingContext');

  UserDN := FindUserDN(Sam, UPN, DomainDN);
  if UserDN = '' then
    raise Exception.Create('UpdateUser_ADSI: usuario no encontrado');

  _Log('ADSI: Bind user -> LDAP://' + UserDN);
  UserObj := OleGetObject('LDAP://' + UserDN);
  if VarIsNull(UserObj) or VarIsEmpty(UserObj) then
    raise Exception.Create('UpdateUser_ADSI: fallo bind de usuario');

  // Setear sólo campos con valor
  if Trim(Email) <> '' then
    UserObj.Put('mail', Email);
  if Trim(FriendlyName) <> '' then
  begin
    UserObj.Put('displayName', FriendlyName);
    // si quieres reflejar en CN, se requiere mover el objeto (Renombrar CN) -> fuera de alcance aquí
  end;
  if Trim(FirstName) <> '' then
    UserObj.Put('givenName', FirstName);
  if Trim(LastName) <> '' then
    UserObj.Put('sn', LastName);
  if Trim(Initials) <> '' then
    UserObj.Put('initials', Initials);
  if Trim(Phone) <> '' then
    UserObj.Put('telephoneNumber', Phone);
  if Trim(Description) <> '' then
    UserObj.Put('description', Description);
  if Trim(Title) <> '' then
    UserObj.Put('title', Title);
  if Trim(Department) <> '' then
    UserObj.Put('department', Department);
  if Trim(Company) <> '' then
    UserObj.Put('company', Company);

  _Log('ADSI: SetInfo -> update');
  UserObj.SetInfo;

  DistinguishedName := UserDN;
end;

procedure GetUserInfo_ADSI(const Sam, UPN: string;
  out DistinguishedName, SamAccountName, UserPrincipalName, Mail, DisplayName,
  GivenName, Surname, Initials, TelephoneNumber, Description, Title_,
  Department, Company, ObjectSid, ObjectGuid: string; out Enabled: Boolean);
var
  DomainDN, UserDN: string;
  UserObj: OleVariant;
  V: OleVariant;
  B: TBytes;
  uac: Integer;

  function ReadStrAttr(const Attr: string): string;
  begin
    Result := '';
    try
      V := UserObj.Get(Attr);
      if not VarIsNull(V) and not VarIsEmpty(V) then
        Result := VarToStr(V);
    except
      // ignorar atributos no presentes
    end;
  end;

begin
  // Inicializar outs
  DistinguishedName := '';
  SamAccountName := '';
  UserPrincipalName := '';
  Mail := '';
  DisplayName := '';
  GivenName := '';
  Surname := '';
  Initials := '';
  TelephoneNumber := '';
  Description := '';
  Title_ := '';
  Department := '';
  Company := '';
  ObjectSid := '';
  ObjectGuid := '';
  Enabled := False;

  if (Trim(Sam) = '') and (Trim(UPN) = '') then
    raise Exception.Create('GetUserInfo_ADSI: se requiere sam o upn');

  DomainDN := GetDefaultNamingContext;
  if DomainDN = '' then
    raise Exception.Create
      ('GetUserInfo_ADSI: no se pudo obtener defaultNamingContext');

  // 1) Resolver DN por sam/upn
  UserDN := FindUserDN(Sam, UPN, DomainDN);
  if UserDN = '' then
    raise Exception.Create('GetUserInfo_ADSI: usuario no encontrado');

  _Log('ADSI: Bind user -> LDAP://' + UserDN);
  UserObj := OleGetObject('LDAP://' + UserDN);

  // 2) Leer atributos estándar (solo lectura)
  DistinguishedName := UserDN;
  SamAccountName := ReadStrAttr('sAMAccountName');
  UserPrincipalName := ReadStrAttr('userPrincipalName');
  Mail := ReadStrAttr('mail');
  DisplayName := ReadStrAttr('displayName');
  GivenName := ReadStrAttr('givenName');
  Surname := ReadStrAttr('sn');
  Initials := ReadStrAttr('initials');
  TelephoneNumber := ReadStrAttr('telephoneNumber');
  Description := ReadStrAttr('description');
  Title_ := ReadStrAttr('title');
  Department := ReadStrAttr('department');
  Company := ReadStrAttr('company');

  // 3) SID
  try
    V := UserObj.Get('objectSid');
    B := VariantToBytes(V);
    ObjectSid := SidBytesToString(B);
  except
    _Log('ADSI: objectSid lectura fallida');
  end;

  // 4) GUID
  try
    V := UserObj.Get('objectGUID');
    B := VariantToBytes(V);
    ObjectGuid := GuidBytesToString(B);
  except
    _Log('ADSI: objectGUID lectura fallida');
  end;

  // 5) Enabled (por UAC)
  Enabled := True;
  try
    V := UserObj.Get('userAccountControl');
    if not VarIsNull(V) and not VarIsEmpty(V) then
    begin
      uac := Integer(V);
      Enabled := (uac and ADS_UF_ACCOUNTDISABLE) = 0;
    end;
  except
    _Log('ADSI: userAccountControl lectura fallida');
  end;
end;

procedure ResetPassword_ADSI(const Sam, UPN, NewPassword: string;
  const ForceChangeAtNextLogon: Boolean; out DistinguishedName: string);
var
  DomainDN, DN, SamEff: string;
  LdapUser: OleVariant;
begin
  DistinguishedName := '';

  if (Trim(Sam) = '') and (Trim(UPN) = '') then
    raise Exception.Create('ResetPassword_ADSI: se requiere sam o upn');

  if Trim(NewPassword) = '' then
    raise Exception.Create('ResetPassword_ADSI: password vacío');

  DomainDN := GetDefaultNamingContext;
  if DomainDN = '' then
    raise Exception.Create
      ('ResetPassword_ADSI: no se pudo obtener defaultNamingContext');

  DN := FindUserDN(Sam, UPN, DomainDN);
  if DN = '' then
    raise Exception.Create('ResetPassword_ADSI: usuario no encontrado');

  DistinguishedName := DN;

  if Trim(Sam) <> '' then
    _Log('ADSI: ResetPassword for sam=' + Sam)
  else
    _Log('ADSI: ResetPassword for upn=' + UPN);

  // Abrir objeto LDAP del usuario
  LdapUser := OleGetObject('LDAP://' + DN);
  if VarIsNull(LdapUser) or VarIsEmpty(LdapUser) then
    raise Exception.Create
      ('ResetPassword_ADSI: no se pudo abrir objeto LDAP del usuario');

  // Asegurar sAMAccountName para el fallback WinNT si vino sólo UPN
  if Trim(Sam) <> '' then
    SamEff := Sam
  else
  begin
    try
      SamEff := LdapUser.Get('sAMAccountName');
    except
      SamEff := '';
    end;
  end;

  // 1) Cambiar la contraseña (intenta LDAP y cae a WinNT con DOMAIN_NETBIOS)
  SetUserPassword_WithFallback(DOMAIN_NETBIOS, SamEff, NewPassword, LdapUser);

  // 2) *** Desbloquear la cuenta en la MISMA operación ***
  // - Si el DC expone UnlockAccount, lo invocamos.
  // - En todos, limpiar lockoutTime = 0 y confirmar con SetInfo.
  try
    _Log('ADSI: unlock -> intento');
    try
      LdapUser.UnlockAccount; // puede no existir en algunos DC
      _Log('ADSI: UnlockAccount método OK');
    except
      _Log('ADSI: UnlockAccount método no disponible/permitido, continúo con lockoutTime=0');
    end;

    try
      LdapUser.Put('lockoutTime', 0); // clear lockout
      _Log('ADSI: lockoutTime=0 seteado');
    except
      on E: EOleException do
        _Log(Format('ADSI: lockoutTime FALL (HRESULT=0x%.8x): %s',
          [Cardinal(E.ErrorCode), E.Message]));
      on E: Exception do
        _Log('ADSI: lockoutTime FALL: ' + E.ClassName + ': ' + E.Message);
    end;

    try
      LdapUser.SetInfo; // persistir el unlock
      _Log('ADSI: unlock -> SetInfo OK');
    except
      on E: EOleException do
        _Log(Format('ADSI: unlock SetInfo FALL (HRESULT=0x%.8x): %s',
          [Cardinal(E.ErrorCode), E.Message]));
      on E: Exception do
        _Log('ADSI: unlock SetInfo FALL: ' + E.ClassName + ': ' + E.Message);
    end;
  except
    on E: Exception do
      _Log('ADSI: unlock WARN: ' + E.ClassName + ': ' + E.Message);
  end;

  // 3) Forzar cambio en el próximo logon si aplica
  if ForceChangeAtNextLogon then
  begin
    try
      _Log('ADSI: Set pwdLastSet=0');
      LdapUser.Put('pwdLastSet', 0);
      LdapUser.SetInfo;
      _Log('ADSI: pwdLastSet aplicado');
    except
      on E: EOleException do
        _Log(Format('ADSI: pwdLastSet via LDAP FALL (HRESULT=0x%.8x): %s',
          [Cardinal(E.ErrorCode), E.Message]));
      on E: Exception do
        _Log('ADSI: pwdLastSet via LDAP FALL: ' + E.ClassName + ': ' +
          E.Message);
    end;
  end;
end;

end.
