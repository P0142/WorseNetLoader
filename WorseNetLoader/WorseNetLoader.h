#pragma once

// ===================================================================================
// Preprocessor Macros and Constants
// ===================================================================================
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)


// ===================================================================================
// Enums
// ===================================================================================
typedef enum _BindingFlags {
    BindingFlags_Default = 0,
    BindingFlags_IgnoreCase = 1,
    BindingFlags_DeclaredOnly = 2,
    BindingFlags_Instance = 4,
    BindingFlags_Static = 8,
    BindingFlags_Public = 16,
    BindingFlags_NonPublic = 32,
    BindingFlags_FlattenHierarchy = 64,
    BindingFlags_InvokeMethod = 256,
    BindingFlags_CreateInstance = 512,
    BindingFlags_GetField = 1024,
    BindingFlags_SetField = 2048,
    BindingFlags_GetProperty = 4096,
    BindingFlags_SetProperty = 8192,
    BindingFlags_PutDispProperty = 16384,
    BindingFlags_PutRefDispProperty = 32768,
    BindingFlags_ExactBinding = 65536,
    BindingFlags_SuppressChangeType = 131072,
    BindingFlags_OptionalParamBinding = 262144,
    BindingFlags_IgnoreReturn = 16777216
} BindingFlags;


// ===================================================================================
// Win32 and Native API Function Pointers
// ===================================================================================

// WinHTTP
typedef HINTERNET(WINAPI* pWinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET(WINAPI* pWinHttpConnect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
typedef HINTERNET(WINAPI* pWinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
typedef BOOL(WINAPI* pWinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL(WINAPI* pWinHttpReceiveResponse)(HINTERNET, LPVOID);
typedef BOOL(WINAPI* pWinHttpReadData)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* pWinHttpCloseHandle)(HINTERNET);
typedef BOOL(WINAPI* pWinHttpCrackUrl)(LPCWSTR, DWORD, DWORD, LPURL_COMPONENTS);

// Misc. Kernel32 Functions
typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
typedef BOOL(WINAPI* pFreeLibrary)(HMODULE);

// Other Functions
typedef HRESULT(WINAPI* pCLRCreateInstance)(REFCLSID clsid, REFIID riid, LPVOID* ppInterface);


// ===================================================================================
// ETW Structures
// ===================================================================================
typedef struct _EVENT_DESCRIPTOR {
    USHORT Id;
    UCHAR Version;
    UCHAR Channel;
    UCHAR Level;
    UCHAR Opcode;
    USHORT Task;
    ULONGLONG Keyword;
} EVENT_DESCRIPTOR, * PEVENT_DESCRIPTOR;

typedef struct _EVENT_DATA_DESCRIPTOR {
    ULONGLONG Ptr;
    ULONG Size;
    union {
        ULONG Reserved;
        struct {
            UCHAR Type;
            UCHAR Reserved1;
            USHORT Reserved2;
        };
    };
} EVENT_DATA_DESCRIPTOR, * PEVENT_DATA_DESCRIPTOR;


// ===================================================================================
// CLR / .NET Hosting Interfaces (ICLRMetaHost, ICLRRuntimeInfo, etc.)
// ===================================================================================
static GUID gCLSID_CLRMetaHost = {
  0x9280188d, 0xe8e, 0x4867, {0xb3, 0xc, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde} };

static GUID gIID_ICLRMetaHost = {
  0xD332DB9E, 0xB9B3, 0x4125, {0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16} };

static GUID gIID_ICLRRuntimeInfo = {
  0xBD39D1D2, 0xBA2F, 0x486a, {0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91} };

static GUID gCLSID_CorRuntimeHost = {
  0xcb2f6723, 0xab3a, 0x11d2, {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e} };

static GUID gIID_ICorRuntimeHost = {
  0xcb2f6722, 0xab3a, 0x11d2, {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e} };

static GUID gIID_AppDomain = {
  0x05F696DC, 0x2B29, 0x3663, {0xAD, 0x8B, 0xC4,0x38, 0x9C, 0xF2, 0xA7, 0x13} };

GUID        gIID_IUnknown;
GUID        gIID_IDispatch;

//GUID required to load .NET assemblies
//GUID        xCLSID_CLRMetaHost;
//GUID        xIID_ICLRMetaHost;
//GUID        xIID_ICLRRuntimeInfo;
//GUID        xCLSID_CorRuntimeHost;
//GUID        xIID_ICorRuntimeHost;
//GUID        xIID_AppDomain;

typedef struct _ICLRMetaHost            ICLRMetaHost;
typedef struct _ICLRRuntimeInfo         ICLRRuntimeInfo;
typedef struct _ICorRuntimeHost         ICorRuntimeHost;
typedef struct _ICorConfiguration       ICorConfiguration;
typedef struct _IGCThreadControl        IGCThreadControl;
typedef struct _IGCHostControl          IGCHostControl;
typedef struct _IDebuggerThreadControl  IDebuggerThreadControl;
typedef struct _AppDomain               IAppDomain;
typedef struct _Assembly                IAssembly;
typedef struct _Type                    IType;
typedef struct _Binder                  IBinder;
typedef struct _MethodInfo              IMethodInfo;

typedef void* HDOMAINENUM;

typedef HRESULT(__stdcall* CLRCreateInstanceFnPtr)(
    REFCLSID clsid,
    REFIID riid,
    LPVOID* ppInterface);

typedef HRESULT(__stdcall* CreateInterfaceFnPtr)(
    REFCLSID clsid,
    REFIID riid,
    LPVOID* ppInterface);

typedef HRESULT(__stdcall* CallbackThreadSetFnPtr)(void);

typedef HRESULT(__stdcall* CallbackThreadUnsetFnPtr)(void);

typedef void(__stdcall* RuntimeLoadedCallbackFnPtr)(
    ICLRRuntimeInfo* pRuntimeInfo,
    CallbackThreadSetFnPtr pfnCallbackThreadSet,
    CallbackThreadUnsetFnPtr pfnCallbackThreadUnset);

#undef DUMMY_METHOD
#define DUMMY_METHOD(x) HRESULT ( STDMETHODCALLTYPE *dummy_##x )(IBinder *This)

typedef struct _BinderVtbl {
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(
        IBinder* This,
        /* [in] */ REFIID riid,
        /* [iid_is][out] */ void** ppvObject);

    ULONG(STDMETHODCALLTYPE* AddRef)(
        IBinder* This);

    ULONG(STDMETHODCALLTYPE* Release)(
        IBinder* This);

    DUMMY_METHOD(GetTypeInfoCount);
    DUMMY_METHOD(GetTypeInfo);
    DUMMY_METHOD(GetIDsOfNames);
    DUMMY_METHOD(Invoke);
    DUMMY_METHOD(ToString);
    DUMMY_METHOD(Equals);
    DUMMY_METHOD(GetHashCode);
    DUMMY_METHOD(GetType);
    DUMMY_METHOD(BindToMethod);
    DUMMY_METHOD(BindToField);
    DUMMY_METHOD(SelectMethod);
    DUMMY_METHOD(SelectProperty);
    DUMMY_METHOD(ChangeType);
    DUMMY_METHOD(ReorderArgumentArray);
} BinderVtbl;

typedef struct _Binder {
    BinderVtbl* lpVtbl;
} Binder;

#undef DUMMY_METHOD
#define DUMMY_METHOD(x) HRESULT ( STDMETHODCALLTYPE *dummy_##x )(IAppDomain *This)

typedef struct _AppDomainVtbl {
    BEGIN_INTERFACE

        HRESULT(STDMETHODCALLTYPE* QueryInterface)(
            IAppDomain* This,
            /* [in] */ REFIID riid,
            /* [iid_is][out] */ void** ppvObject);

    ULONG(STDMETHODCALLTYPE* AddRef)(
        IAppDomain* This);

    ULONG(STDMETHODCALLTYPE* Release)(
        IAppDomain* This);

    DUMMY_METHOD(GetTypeInfoCount);
    DUMMY_METHOD(GetTypeInfo);
    DUMMY_METHOD(GetIDsOfNames);
    DUMMY_METHOD(Invoke);

    DUMMY_METHOD(ToString);
    DUMMY_METHOD(Equals);
    DUMMY_METHOD(GetHashCode);
    DUMMY_METHOD(GetType);
    DUMMY_METHOD(InitializeLifetimeService);
    DUMMY_METHOD(GetLifetimeService);
    DUMMY_METHOD(Evidence);
    DUMMY_METHOD(add_DomainUnload);
    DUMMY_METHOD(remove_DomainUnload);
    DUMMY_METHOD(add_AssemblyLoad);
    DUMMY_METHOD(remove_AssemblyLoad);
    DUMMY_METHOD(add_ProcessExit);
    DUMMY_METHOD(remove_ProcessExit);
    DUMMY_METHOD(add_TypeResolve);
    DUMMY_METHOD(remove_TypeResolve);
    DUMMY_METHOD(add_ResourceResolve);
    DUMMY_METHOD(remove_ResourceResolve);
    DUMMY_METHOD(add_AssemblyResolve);
    DUMMY_METHOD(remove_AssemblyResolve);
    DUMMY_METHOD(add_UnhandledException);
    DUMMY_METHOD(remove_UnhandledException);
    DUMMY_METHOD(DefineDynamicAssembly);
    DUMMY_METHOD(DefineDynamicAssembly_2);
    DUMMY_METHOD(DefineDynamicAssembly_3);
    DUMMY_METHOD(DefineDynamicAssembly_4);
    DUMMY_METHOD(DefineDynamicAssembly_5);
    DUMMY_METHOD(DefineDynamicAssembly_6);
    DUMMY_METHOD(DefineDynamicAssembly_7);
    DUMMY_METHOD(DefineDynamicAssembly_8);
    DUMMY_METHOD(DefineDynamicAssembly_9);
    DUMMY_METHOD(CreateInstance);
    DUMMY_METHOD(CreateInstanceFrom);
    DUMMY_METHOD(CreateInstance_2);
    DUMMY_METHOD(CreateInstanceFrom_2);
    DUMMY_METHOD(CreateInstance_3);
    DUMMY_METHOD(CreateInstanceFrom_3);
    DUMMY_METHOD(Load);
    DUMMY_METHOD(Load_2);

    HRESULT(STDMETHODCALLTYPE* Load_3)(
        IAppDomain* This,
        SAFEARRAY* rawAssembly,
        IAssembly** pRetVal);

    DUMMY_METHOD(Load_4);
    DUMMY_METHOD(Load_5);
    DUMMY_METHOD(Load_6);
    DUMMY_METHOD(Load_7);
    DUMMY_METHOD(ExecuteAssembly);
    DUMMY_METHOD(ExecuteAssembly_2);
    DUMMY_METHOD(ExecuteAssembly_3);
    DUMMY_METHOD(FriendlyName);
    DUMMY_METHOD(BaseDirectory);
    DUMMY_METHOD(RelativeSearchPath);
    DUMMY_METHOD(ShadowCopyFiles);
    DUMMY_METHOD(GetAssemblies);
    DUMMY_METHOD(AppendPrivatePath);
    DUMMY_METHOD(ClearPrivatePath);
    DUMMY_METHOD(SetShadowCopyPath);
    DUMMY_METHOD(ClearShadowCopyPath);
    DUMMY_METHOD(SetCachePath);
    DUMMY_METHOD(SetData);
    DUMMY_METHOD(GetData);
    DUMMY_METHOD(SetAppDomainPolicy);
    DUMMY_METHOD(SetThreadPrincipal);
    DUMMY_METHOD(SetPrincipalPolicy);
    DUMMY_METHOD(DoCallBack);
    DUMMY_METHOD(DynamicDirectory);

    END_INTERFACE
} AppDomainVtbl;

typedef struct _AppDomain {
    AppDomainVtbl* lpVtbl;
} AppDomain;

#undef DUMMY_METHOD
#define DUMMY_METHOD(x) HRESULT ( STDMETHODCALLTYPE *dummy_##x )(IAssembly *This)

typedef struct _AssemblyVtbl {
    BEGIN_INTERFACE

        HRESULT(STDMETHODCALLTYPE* QueryInterface)(
            IAssembly* This,
            REFIID riid,
            void** ppvObject);

    ULONG(STDMETHODCALLTYPE* AddRef)(
        IAssembly* This);

    ULONG(STDMETHODCALLTYPE* Release)(
        IAssembly* This);

    DUMMY_METHOD(GetTypeInfoCount);
    DUMMY_METHOD(GetTypeInfo);
    DUMMY_METHOD(GetIDsOfNames);

    DUMMY_METHOD(Invoke);
    DUMMY_METHOD(ToString);
    DUMMY_METHOD(Equals);
    DUMMY_METHOD(GetHashCode);
    DUMMY_METHOD(GetType);
    DUMMY_METHOD(CodeBase);
    DUMMY_METHOD(EscapedCodeBase);
    DUMMY_METHOD(GetName);
    DUMMY_METHOD(GetName_2);
    DUMMY_METHOD(FullName);

    HRESULT(STDMETHODCALLTYPE* EntryPoint)(
        IAssembly* This,
        IMethodInfo** pRetVal);

    HRESULT(STDMETHODCALLTYPE* GetType_2)(
        IAssembly* This,
        BSTR        name,
        IType** pRetVal);

    DUMMY_METHOD(GetType_3);
    DUMMY_METHOD(GetExportedTypes);
    DUMMY_METHOD(GetTypes);
    DUMMY_METHOD(GetManifestResourceStream);
    DUMMY_METHOD(GetManifestResourceStream_2);
    DUMMY_METHOD(GetFile);
    DUMMY_METHOD(GetFiles);
    DUMMY_METHOD(GetFiles_2);
    DUMMY_METHOD(GetManifestResourceNames);
    DUMMY_METHOD(GetManifestResourceInfo);
    DUMMY_METHOD(Location);
    DUMMY_METHOD(Evidence);
    DUMMY_METHOD(GetCustomAttributes);
    DUMMY_METHOD(GetCustomAttributes_2);
    DUMMY_METHOD(IsDefined);
    DUMMY_METHOD(GetObjectData);
    DUMMY_METHOD(add_ModuleResolve);
    DUMMY_METHOD(remove_ModuleResolve);
    DUMMY_METHOD(GetType_4);
    DUMMY_METHOD(GetSatelliteAssembly);
    DUMMY_METHOD(GetSatelliteAssembly_2);
    DUMMY_METHOD(LoadModule);
    DUMMY_METHOD(LoadModule_2);
    DUMMY_METHOD(CreateInstance);
    DUMMY_METHOD(CreateInstance_2);
    DUMMY_METHOD(CreateInstance_3);
    DUMMY_METHOD(GetLoadedModules);
    DUMMY_METHOD(GetLoadedModules_2);
    DUMMY_METHOD(GetModules);
    DUMMY_METHOD(GetModules_2);
    DUMMY_METHOD(GetModule);
    DUMMY_METHOD(GetReferencedAssemblies);
    DUMMY_METHOD(GlobalAssemblyCache);

    END_INTERFACE
} AssemblyVtbl;

typedef struct _Assembly {
    AssemblyVtbl* lpVtbl;
} Assembly;

#undef DUMMY_METHOD
#define DUMMY_METHOD(x) HRESULT ( STDMETHODCALLTYPE *dummy_##x )(IType *This)

typedef struct _TypeVtbl {
    BEGIN_INTERFACE

        HRESULT(STDMETHODCALLTYPE* QueryInterface)(
            IType* This,
            REFIID riid,
            void** ppvObject);

    ULONG(STDMETHODCALLTYPE* AddRef)(
        IType* This);

    ULONG(STDMETHODCALLTYPE* Release)(
        IType* This);

    DUMMY_METHOD(GetTypeInfoCount);
    DUMMY_METHOD(GetTypeInfo);
    DUMMY_METHOD(GetIDsOfNames);
    DUMMY_METHOD(Invoke);

    DUMMY_METHOD(ToString);
    DUMMY_METHOD(Equals);
    DUMMY_METHOD(GetHashCode);
    DUMMY_METHOD(GetType);
    DUMMY_METHOD(MemberType);
    DUMMY_METHOD(name);
    DUMMY_METHOD(DeclaringType);
    DUMMY_METHOD(ReflectedType);
    DUMMY_METHOD(GetCustomAttributes);
    DUMMY_METHOD(GetCustomAttributes_2);
    DUMMY_METHOD(IsDefined);
    DUMMY_METHOD(Guid);
    DUMMY_METHOD(Module);
    DUMMY_METHOD(Assembly);
    DUMMY_METHOD(TypeHandle);
    DUMMY_METHOD(FullName);
    DUMMY_METHOD(Namespace);
    DUMMY_METHOD(AssemblyQualifiedName);
    DUMMY_METHOD(GetArrayRank);
    DUMMY_METHOD(BaseType);
    DUMMY_METHOD(GetConstructors);
    DUMMY_METHOD(GetInterface);
    DUMMY_METHOD(GetInterfaces);
    DUMMY_METHOD(FindInterfaces);
    DUMMY_METHOD(GetEvent);
    DUMMY_METHOD(GetEvents);
    DUMMY_METHOD(GetEvents_2);
    DUMMY_METHOD(GetNestedTypes);
    DUMMY_METHOD(GetNestedType);
    DUMMY_METHOD(GetMember);
    DUMMY_METHOD(GetDefaultMembers);
    DUMMY_METHOD(FindMembers);
    DUMMY_METHOD(GetElementType);
    DUMMY_METHOD(IsSubclassOf);
    DUMMY_METHOD(IsInstanceOfType);
    DUMMY_METHOD(IsAssignableFrom);
    DUMMY_METHOD(GetInterfaceMap);
    DUMMY_METHOD(GetMethod);
    DUMMY_METHOD(GetMethod_2);
    DUMMY_METHOD(GetMethods);
    DUMMY_METHOD(GetField);
    DUMMY_METHOD(GetFields);
    DUMMY_METHOD(GetProperty);
    DUMMY_METHOD(GetProperty_2);
    DUMMY_METHOD(GetProperties);
    DUMMY_METHOD(GetMember_2);
    DUMMY_METHOD(GetMembers);
    DUMMY_METHOD(InvokeMember);
    DUMMY_METHOD(UnderlyingSystemType);
    DUMMY_METHOD(InvokeMember_2);

    HRESULT(STDMETHODCALLTYPE* InvokeMember_3)(
        IType* This,
        BSTR         name,
        BindingFlags invokeAttr,
        IBinder* Binder,
        VARIANT      Target,
        SAFEARRAY* args,
        VARIANT* pRetVal);

    DUMMY_METHOD(GetConstructor);
    DUMMY_METHOD(GetConstructor_2);
    DUMMY_METHOD(GetConstructor_3);
    DUMMY_METHOD(GetConstructors_2);
    DUMMY_METHOD(TypeInitializer);
    DUMMY_METHOD(GetMethod_3);
    DUMMY_METHOD(GetMethod_4);
    DUMMY_METHOD(GetMethod_5);
    DUMMY_METHOD(GetMethod_6);
    DUMMY_METHOD(GetMethods_2);
    DUMMY_METHOD(GetField_2);
    DUMMY_METHOD(GetFields_2);
    DUMMY_METHOD(GetInterface_2);
    DUMMY_METHOD(GetEvent_2);
    DUMMY_METHOD(GetProperty_3);
    DUMMY_METHOD(GetProperty_4);
    DUMMY_METHOD(GetProperty_5);
    DUMMY_METHOD(GetProperty_6);
    DUMMY_METHOD(GetProperty_7);
    DUMMY_METHOD(GetProperties_2);
    DUMMY_METHOD(GetNestedTypes_2);
    DUMMY_METHOD(GetNestedType_2);
    DUMMY_METHOD(GetMember_3);
    DUMMY_METHOD(GetMembers_2);
    DUMMY_METHOD(Attributes);
    DUMMY_METHOD(IsNotPublic);
    DUMMY_METHOD(IsPublic);
    DUMMY_METHOD(IsNestedPublic);
    DUMMY_METHOD(IsNestedPrivate);
    DUMMY_METHOD(IsNestedFamily);
    DUMMY_METHOD(IsNestedAssembly);
    DUMMY_METHOD(IsNestedFamANDAssem);
    DUMMY_METHOD(IsNestedFamORAssem);
    DUMMY_METHOD(IsAutoLayout);
    DUMMY_METHOD(IsLayoutSequential);
    DUMMY_METHOD(IsExplicitLayout);
    DUMMY_METHOD(IsClass);
    DUMMY_METHOD(IsInterface);
    DUMMY_METHOD(IsValueType);
    DUMMY_METHOD(IsAbstract);
    DUMMY_METHOD(IsSealed);
    DUMMY_METHOD(IsEnum);
    DUMMY_METHOD(IsSpecialName);
    DUMMY_METHOD(IsImport);
    DUMMY_METHOD(IsSerializable);
    DUMMY_METHOD(IsAnsiClass);
    DUMMY_METHOD(IsUnicodeClass);
    DUMMY_METHOD(IsAutoClass);
    DUMMY_METHOD(IsArray);
    DUMMY_METHOD(IsByRef);
    DUMMY_METHOD(IsPointer);
    DUMMY_METHOD(IsPrimitive);
    DUMMY_METHOD(IsCOMObject);
    DUMMY_METHOD(HasElementType);
    DUMMY_METHOD(IsContextful);
    DUMMY_METHOD(IsMarshalByRef);
    DUMMY_METHOD(Equals_2);

    END_INTERFACE
} TypeVtbl;

typedef struct ICLRRuntimeInfoVtbl
{
    BEGIN_INTERFACE

        HRESULT(STDMETHODCALLTYPE* QueryInterface)(
            ICLRRuntimeInfo* This,
            /* [in] */ REFIID riid,
            /* [iid_is][out] */
            __RPC__deref_out  void** ppvObject);

    ULONG(STDMETHODCALLTYPE* AddRef)(
        ICLRRuntimeInfo* This);

    ULONG(STDMETHODCALLTYPE* Release)(
        ICLRRuntimeInfo* This);

    HRESULT(STDMETHODCALLTYPE* GetVersionString)(
        ICLRRuntimeInfo* This,
        LPWSTR pwzBuffer,
        DWORD* pcchBuffer);

    HRESULT(STDMETHODCALLTYPE* GetRuntimeDirectory)(
        ICLRRuntimeInfo* This,
        /* [size_is][out] */
        __out_ecount_full(*pcchBuffer)  LPWSTR pwzBuffer,
        /* [out][in] */ DWORD* pcchBuffer);

    HRESULT(STDMETHODCALLTYPE* IsLoaded)(
        ICLRRuntimeInfo* This,
        /* [in] */ HANDLE hndProcess,
        /* [retval][out] */ BOOL* pbLoaded);

    HRESULT(STDMETHODCALLTYPE* LoadErrorString)(
        ICLRRuntimeInfo* This,
        /* [in] */ UINT iResourceID,
        /* [size_is][out] */
        __out_ecount_full(*pcchBuffer)  LPWSTR pwzBuffer,
        /* [out][in] */ DWORD* pcchBuffer,
        /* [lcid][in] */ LONG iLocaleID);

    HRESULT(STDMETHODCALLTYPE* LoadLibrary)(
        ICLRRuntimeInfo* This,
        /* [in] */ LPCWSTR pwzDllName,
        /* [retval][out] */ HMODULE* phndModule);

    HRESULT(STDMETHODCALLTYPE* GetProcAddress)(
        ICLRRuntimeInfo* This,
        /* [in] */ LPCSTR pszProcName,
        /* [retval][out] */ LPVOID* ppProc);

    HRESULT(STDMETHODCALLTYPE* GetInterface)(
        ICLRRuntimeInfo* This,
        /* [in] */ REFCLSID rclsid,
        /* [in] */ REFIID riid,
        /* [retval][iid_is][out] */ LPVOID* ppUnk);

    HRESULT(STDMETHODCALLTYPE* IsLoadable)(
        ICLRRuntimeInfo* This,
        /* [retval][out] */ BOOL* pbLoadable);

    HRESULT(STDMETHODCALLTYPE* SetDefaultStartupFlags)(
        ICLRRuntimeInfo* This,
        /* [in] */ DWORD dwStartupFlags,
        /* [in] */ LPCWSTR pwzHostConfigFile);

    HRESULT(STDMETHODCALLTYPE* GetDefaultStartupFlags)(
        ICLRRuntimeInfo* This,
        DWORD* pdwStartupFlags,
        LPWSTR pwzHostConfigFile,
        DWORD* pcchHostConfigFile);

    HRESULT(STDMETHODCALLTYPE* BindAsLegacyV2Runtime)(
        ICLRRuntimeInfo* This);

    HRESULT(STDMETHODCALLTYPE* IsStarted)(
        ICLRRuntimeInfo* This,
        /* [out] */ BOOL* pbStarted,
        /* [out] */ DWORD* pdwStartupFlags);

    END_INTERFACE
} ICLRRuntimeInfoVtbl;

typedef struct _ICLRRuntimeInfo {
    ICLRRuntimeInfoVtbl* lpVtbl;
} ICLRRuntimeInfo;

typedef struct _Type {
    TypeVtbl* lpVtbl;
} Type;

typedef struct ICLRMetaHostVtbl
{
    BEGIN_INTERFACE

        HRESULT(STDMETHODCALLTYPE* QueryInterface)(
            ICLRMetaHost* This,
            /* [in] */ REFIID riid,
            /* [iid_is][out] */
            __RPC__deref_out  void** ppvObject);

    ULONG(STDMETHODCALLTYPE* AddRef)(
        ICLRMetaHost* This);

    ULONG(STDMETHODCALLTYPE* Release)(
        ICLRMetaHost* This);

    HRESULT(STDMETHODCALLTYPE* GetRuntime)(
        ICLRMetaHost* This,
        /* [in] */ LPCWSTR pwzVersion,
        /* [in] */ REFIID riid,
        /* [retval][iid_is][out] */ LPVOID* ppRuntime);

    HRESULT(STDMETHODCALLTYPE* GetVersionFromFile)(
        ICLRMetaHost* This,
        /* [in] */ LPCWSTR pwzFilePath,
        /* [size_is][out] */
        __out_ecount_full(*pcchBuffer)  LPWSTR pwzBuffer,
        /* [out][in] */ DWORD* pcchBuffer);

    HRESULT(STDMETHODCALLTYPE* EnumerateInstalledRuntimes)(
        ICLRMetaHost* This,
        /* [retval][out] */ IEnumUnknown** ppEnumerator);

    HRESULT(STDMETHODCALLTYPE* EnumerateLoadedRuntimes)(
        ICLRMetaHost* This,
        /* [in] */ HANDLE hndProcess,
        /* [retval][out] */ IEnumUnknown** ppEnumerator);

    HRESULT(STDMETHODCALLTYPE* RequestRuntimeLoadedNotification)(
        ICLRMetaHost* This,
        /* [in] */ RuntimeLoadedCallbackFnPtr pCallbackFunction);

    HRESULT(STDMETHODCALLTYPE* QueryLegacyV2RuntimeBinding)(
        ICLRMetaHost* This,
        /* [in] */ REFIID riid,
        /* [retval][iid_is][out] */ LPVOID* ppUnk);

    HRESULT(STDMETHODCALLTYPE* ExitProcess)(
        ICLRMetaHost* This,
        /* [in] */ INT32 iExitCode);

    END_INTERFACE
} ICLRMetaHostVtbl;

typedef struct _ICLRMetaHost
{
    ICLRMetaHostVtbl* lpVtbl;
} ICLRMetaHost;

typedef struct ICorRuntimeHostVtbl
{
    BEGIN_INTERFACE

        HRESULT(STDMETHODCALLTYPE* QueryInterface)(
            ICorRuntimeHost* This,
            /* [in] */ REFIID riid,
            /* [iid_is][out] */
            __RPC__deref_out  void** ppvObject);

    ULONG(STDMETHODCALLTYPE* AddRef)(
        ICorRuntimeHost* This);

    ULONG(STDMETHODCALLTYPE* Release)(
        ICorRuntimeHost* This);

    HRESULT(STDMETHODCALLTYPE* CreateLogicalThreadState)(
        ICorRuntimeHost* This);

    HRESULT(STDMETHODCALLTYPE* DeleteLogicalThreadState)(
        ICorRuntimeHost* This);

    HRESULT(STDMETHODCALLTYPE* SwitchInLogicalThreadState)(
        ICorRuntimeHost* This,
        /* [in] */ DWORD* pFiberCookie);

    HRESULT(STDMETHODCALLTYPE* SwitchOutLogicalThreadState)(
        ICorRuntimeHost* This,
        /* [out] */ DWORD** pFiberCookie);

    HRESULT(STDMETHODCALLTYPE* LocksHeldByLogicalThread)(
        ICorRuntimeHost* This,
        /* [out] */ DWORD* pCount);

    HRESULT(STDMETHODCALLTYPE* MapFile)(
        ICorRuntimeHost* This,
        /* [in] */ HANDLE hFile,
        /* [out] */ HMODULE* hMapAddress);

    HRESULT(STDMETHODCALLTYPE* GetConfiguration)(
        ICorRuntimeHost* This,
        /* [out] */ ICorConfiguration** pConfiguration);

    HRESULT(STDMETHODCALLTYPE* Start)(
        ICorRuntimeHost* This);

    HRESULT(STDMETHODCALLTYPE* Stop)(
        ICorRuntimeHost* This);

    HRESULT(STDMETHODCALLTYPE* CreateDomain)(
        ICorRuntimeHost* This,
        /* [in] */ LPCWSTR pwzFriendlyName,
        /* [in] */ IUnknown* pIdentityArray,
        /* [out] */ IUnknown** pAppDomain);

    HRESULT(STDMETHODCALLTYPE* GetDefaultDomain)(
        ICorRuntimeHost* This,
        /* [out] */ IUnknown** pAppDomain);

    HRESULT(STDMETHODCALLTYPE* EnumDomains)(
        ICorRuntimeHost* This,
        /* [out] */ HDOMAINENUM* hEnum);

    HRESULT(STDMETHODCALLTYPE* NextDomain)(
        ICorRuntimeHost* This,
        /* [in] */ HDOMAINENUM hEnum,
        /* [out] */ IUnknown** pAppDomain);

    HRESULT(STDMETHODCALLTYPE* CloseEnum)(
        ICorRuntimeHost* This,
        /* [in] */ HDOMAINENUM hEnum);

    HRESULT(STDMETHODCALLTYPE* CreateDomainEx)(
        ICorRuntimeHost* This,
        /* [in] */ LPCWSTR pwzFriendlyName,
        /* [in] */ IUnknown* pSetup,
        /* [in] */ IUnknown* pEvidence,
        /* [out] */ IUnknown** pAppDomain);

    HRESULT(STDMETHODCALLTYPE* CreateDomainSetup)(
        ICorRuntimeHost* This,
        /* [out] */ IUnknown** pAppDomainSetup);

    HRESULT(STDMETHODCALLTYPE* CreateEvidence)(
        ICorRuntimeHost* This,
        /* [out] */ IUnknown** pEvidence);

    HRESULT(STDMETHODCALLTYPE* UnloadDomain)(
        ICorRuntimeHost* This,
        /* [in] */ IUnknown* pAppDomain);

    HRESULT(STDMETHODCALLTYPE* CurrentDomain)(
        ICorRuntimeHost* This,
        /* [out] */ IUnknown** pAppDomain);

    END_INTERFACE
} ICorRuntimeHostVtbl;

typedef struct _ICorRuntimeHost {
    ICorRuntimeHostVtbl* lpVtbl;
} ICorRuntimeHost;

#undef DUMMY_METHOD
#define DUMMY_METHOD(x) HRESULT ( STDMETHODCALLTYPE *dummy_##x )(IMethodInfo *This)

typedef struct _MethodInfoVtbl {
    BEGIN_INTERFACE

        HRESULT(STDMETHODCALLTYPE* QueryInterface)(
            IMethodInfo* This,
            /* [in] */ REFIID riid,
            /* [iid_is][out] */
            __RPC__deref_out  void** ppvObject);

    ULONG(STDMETHODCALLTYPE* AddRef)(
        IMethodInfo* This);

    ULONG(STDMETHODCALLTYPE* Release)(
        IMethodInfo* This);

    DUMMY_METHOD(GetTypeInfoCount);
    DUMMY_METHOD(GetTypeInfo);
    DUMMY_METHOD(GetIDsOfNames);
    DUMMY_METHOD(Invoke);

    DUMMY_METHOD(ToString);
    DUMMY_METHOD(Equals);
    DUMMY_METHOD(GetHashCode);
    DUMMY_METHOD(GetType);
    DUMMY_METHOD(MemberType);
    DUMMY_METHOD(name);
    DUMMY_METHOD(DeclaringType);
    DUMMY_METHOD(ReflectedType);
    DUMMY_METHOD(GetCustomAttributes);
    DUMMY_METHOD(GetCustomAttributes_2);
    DUMMY_METHOD(IsDefined);

    HRESULT(STDMETHODCALLTYPE* GetParameters)(
        IMethodInfo* This,
        SAFEARRAY** pRetVal);

    DUMMY_METHOD(GetMethodImplementationFlags);
    DUMMY_METHOD(MethodHandle);
    DUMMY_METHOD(Attributes);
    DUMMY_METHOD(CallingConvention);
    DUMMY_METHOD(Invoke_2);
    DUMMY_METHOD(IsPublic);
    DUMMY_METHOD(IsPrivate);
    DUMMY_METHOD(IsFamily);
    DUMMY_METHOD(IsAssembly);
    DUMMY_METHOD(IsFamilyAndAssembly);
    DUMMY_METHOD(IsFamilyOrAssembly);
    DUMMY_METHOD(IsStatic);
    DUMMY_METHOD(IsFinal);
    DUMMY_METHOD(IsVirtual);
    DUMMY_METHOD(IsHideBySig);
    DUMMY_METHOD(IsAbstract);
    DUMMY_METHOD(IsSpecialName);
    DUMMY_METHOD(IsConstructor);

    HRESULT(STDMETHODCALLTYPE* Invoke_3)(
        IMethodInfo* This,
        VARIANT     obj,
        SAFEARRAY* parameters,
        VARIANT* ret);

    DUMMY_METHOD(returnType);
    DUMMY_METHOD(ReturnTypeCustomAttributes);
    DUMMY_METHOD(GetBaseDefinition);

    END_INTERFACE
} MethodInfoVtbl;

typedef struct _MethodInfo {
    MethodInfoVtbl* lpVtbl;
} MethodInfo;







