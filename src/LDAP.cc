#include <string.h>
#include <stdlib.h>

#include <v8.h>
#include <node.h>
#include <node_buffer.h>
#include <node_object_wrap.h>
#include <unistd.h>
#include <errno.h>

#include <ldap.h>

#ifdef __FreeBSD__
#include <uuid.h>
#define uuid_to_string(uu, uuid) {              \
    uint32_t status;                            \
    uuid_to_string(uu, &uuid, &status);         \
  }
#endif

#ifdef __linux__
#include <uuid/uuid.h>
#define uuid_to_string(uu, uuid) {              \
    uuid = (char *)malloc(33);                  \
    uuid_unparse_lower(*uu, (char *)uuid);      \
  }
#endif

#ifdef __APPLE__
#include <uuid/uuid.h>
#define uuid_to_string(uu, uuid) {              \
    uuid = (char *)malloc(33);                  \
    uuid_unparse_lower(*uu, (char *)uuid);      \
  }
#endif

#ifdef LJSDEBUG
#define LJSDEB(msg, ...) fprintf(stderr, msg, __FILE__, __LINE__, ##__VA_ARGS__);
#else
#define LJSDEB(msg, ...)
#endif

using namespace node;
using namespace v8;

static Persistent<ObjectTemplate> cookie_template;

static Persistent<Function> ldapConstructor;

struct timeval ldap_tv = { 0, 0 }; // static struct used to make ldap_result non-blocking

typedef enum {
  LDAP_SYNC_REFRESH,
  LDAP_SYNC_PERSIST
} ldap_syncphase;


#define REQ_FUN_ARG(I, VAR)                                             \
  if (args.Length() <= (I) || !args[I]->IsFunction())                   \
    return ThrowException(Exception::TypeError(                         \
                                               String::New("Argument " #I " must be a function"))); \
  Local<Function> VAR = Local<Function>::Cast(args[I]);

#define THROW(msg)                                              \
  return ThrowException(Exception::Error(String::New(msg)));

#define GETOBJ(r)                                                       \
  LDAPConnection * c = ObjectWrap::Unwrap<LDAPConnection>(args.This());

#define ENFORCE_ARG_LENGTH(n, m)                \
  if (args.Length() < n) THROW(m);

#define ENFORCE_ARG_STR(n)                                      \
  if (!args[n]->IsString()) THROW("Argument must be string");

#define ENFORCE_ARG_ARRAY(n)                                    \
  if (!args[n]->IsArray()) THROW("Argument must be an array");

#define ENFORCE_ARG_NUMBER(n)                                   \
  if (!args[n]->IsNumber()) THROW("Argument must be numeric");

#define ENFORCE_ARG_BOOL(n)                                     \
  if (!args[n]->IsBoolean()) THROW("Argument must be boolean");

#define ENFORCE_ARG_FUNC(n)                                             \
  if (!args[n]->IsFunction()) THROW("Argument must be a function");

#define ARG_STR(v,a) String::Utf8Value v(args[a]);

#define ARG_INT(v,a) int v = args[a]->Int32Value();

#define ARG_BOOL(v,a) int v = args[a]->BooleanValue();

#define ARG_ARRAY(v, a) Local<Array> v = Local<Array>::Cast(args[a]);

#define RETURN_INT(i) return scope.Close(Integer::New(i));

#define NODE_METHOD(n) static Handle<Value> n(const Arguments& args)

#define EMIT(c, num, args) {                                    \
    Local<Value> emit_v = c->handle_->Get(emit_symbol);         \
    assert(emit_v->IsFunction());                               \
    Local<Function> emit = Local<Function>::Cast(emit_v);       \
    TryCatch tc;                                                \
    emit->Call(c->handle_, num, args);                          \
    if (tc.HasCaught()) {                                       \
      FatalException(tc);                                       \
    }                                                           \
  }

#define EMITSEARCHRESULT(c, argv) {                                     \
  TryCatch tc;                                                          \
  c->searchresult_cb->Call(Context::GetCurrent()->Global(), 5, argv);   \
    if (tc.HasCaught()) {                                               \
      FatalException(tc);                                               \
    }                                                                   \
  }                                                                     \

#define EMITRESULT(c, argv) {                                           \
  TryCatch tc;                                                          \
  c->result_cb->Call(Context::GetCurrent()->Global(), 3, argv);         \
    if (tc.HasCaught()) {                                               \
      FatalException(tc);                                               \
    }                                                                   \
  }                                                                     \

#define EMITERROR(c, argv) {                                            \
  TryCatch tc;                                                          \
  c->error_cb->Call(Context::GetCurrent()->Global(), 1, argv);          \
    if (tc.HasCaught()) {                                               \
      FatalException(tc);                                               \
    }                                                                   \
  }                                                                     \

#define EMITSYNCREFRESHDONE(c, argv) {                                   \
  TryCatch tc;                                                           \
  c->syncrefreshdone_cb->Call(Context::GetCurrent()->Global(), 1, argv); \
    if (tc.HasCaught()) {                                                \
      FatalException(tc);                                                \
    }                                                                    \
  }                                                                      \

#define EMITSYNCREFRESH(c, argv) {                                       \
  TryCatch tc;                                                           \
  c->syncrefresh_cb->Call(Context::GetCurrent()->Global(), 2, argv);     \
    if (tc.HasCaught()) {                                                \
      FatalException(tc);                                                \
    }                                                                    \
  }                                                                      \




class LDAPConnection : public ObjectWrap
{
private:
  LDAP  *ld;
  ldap_sync_t * ls;
  uv_poll_t * uv_handle;
  Persistent<Function> connected_cb;
  Persistent<Function> disconnected_cb;
  Persistent<Function> searchresult_cb;
  Persistent<Function> result_cb;
  Persistent<Function> error_cb;
  Persistent<Function> syncentry_cb;
  Persistent<Function> syncintermediate_cb;
  Persistent<Function> syncresult_cb;
  int connected, iowatching;

public:
  LDAPConnection() : ObjectWrap(){ }

  static void Initialize(Handle<Object> target)
  {
    HandleScope scope;

    cookie_template = Persistent<ObjectTemplate>::New( ObjectTemplate::New() );
    cookie_template->SetInternalFieldCount(1);

    Local<FunctionTemplate> t = FunctionTemplate::New(New);//constructor template
    t->InstanceTemplate()->SetInternalFieldCount(1);
    t->SetClassName(String::NewSymbol("LDAPConnection"));
    //removed the EventEmitter inheritance from the C++ file. added to the LDAP.js file
    NODE_SET_PROTOTYPE_METHOD(t, "open", Open);
    NODE_SET_PROTOTYPE_METHOD(t, "close", Close);
    NODE_SET_PROTOTYPE_METHOD(t, "search", Search);
    NODE_SET_PROTOTYPE_METHOD(t, "err2string", err2string);
    NODE_SET_PROTOTYPE_METHOD(t, "sync", Sync);
    NODE_SET_PROTOTYPE_METHOD(t, "syncpoll", SyncPoll);
    NODE_SET_PROTOTYPE_METHOD(t, "getcookie", GetCookie);
    NODE_SET_PROTOTYPE_METHOD(t, "modify", Modify);
    NODE_SET_PROTOTYPE_METHOD(t, "simpleBind", SimpleBind);
    NODE_SET_PROTOTYPE_METHOD(t, "rename", Rename);
    NODE_SET_PROTOTYPE_METHOD(t, "add", Add);
    NODE_SET_PROTOTYPE_METHOD(t, "remove", Delete);
    NODE_SET_PROTOTYPE_METHOD(t, "setcallbacks", SetCallbacks);
    NODE_SET_PROTOTYPE_METHOD(t, "setsynccallbacks", SetSyncCallbacks);
    ldapConstructor = Persistent<Function>::New(t->GetFunction());
    target->Set(String::NewSymbol("LDAPConnection"), ldapConstructor);

    LJSDEB("Init Done %s:%u\n");
  }

  NODE_METHOD(New)
  {
    HandleScope scope;
    LDAPConnection * c = new LDAPConnection();
    c->Wrap(args.This());

    LJSDEB("NEW %s:%u\n");

    c->ld = NULL;
    c->ls = NULL;
    c->connected = false;
    c->iowatching = false;
    c->uv_handle = NULL;

    LJSDEB("NEW DONE %s:%u %p %p\n", c, c->ld);

    return args.This();
  }

  NODE_METHOD(Open)
  {
    HandleScope scope;
    GETOBJ(c);

    ARG_STR(uri, 0);
    ARG_INT(ver, 1);
    ARG_INT(timeout, 2);

    LJSDEB("OPEN1 %s:%u %p %p\n", c, c->ld);

    if (c->ld != NULL) {
      c->Close(args);
    }

    if (ldap_initialize(&(c->ld), *uri) != LDAP_SUCCESS) {
      THROW("Error init LDAP");
    }

    if (c->ld == NULL) {
      THROW("Error init LDAP");
    }

    struct timeval ntimeout = { timeout, 0 };

    if (timeout != -1) {
      ntimeout.tv_sec = timeout;
    }

    ldap_set_option(c->ld, LDAP_OPT_NETWORK_TIMEOUT, &ntimeout);

    ldap_set_option(c->ld, LDAP_OPT_RESTART, LDAP_OPT_ON);
    ldap_set_option(c->ld, LDAP_OPT_PROTOCOL_VERSION, &ver);

    LJSDEB("OPEN: %s:%u %p %p\n", c, c->ld);

    c->connected = true;

    RETURN_INT(0);
  }

  static void on_handle_close(uv_handle_t * handle) {
    LDAPConnection *c = (LDAPConnection *)handle->data;
    int res;
    LJSDEB("CLOSE CB %s:%u lsld: %p\n", c->ld);
    delete handle;

    if (c->ls) {
      c->ls->ls_ld = NULL; // this prevents sync_destroy from unbinding
      ldap_sync_destroy(c->ls, 1);
    }
    c->ls = NULL;

    if (c->ld) {
      res = ldap_unbind(c->ld);
      LJSDEB("UNBIND %s:%u res: %i\n", res);
    }
    c->ld = NULL;

    /*Local<Value> argv[1] = {
      Local<Value>::New(Null())
    };*/
    //c->disconnected_cb->Call(Context::GetCurrent()->Global(), 1, argv);
    c->iowatching = false;
    c->connected = false;
  }

  static void close(LDAPConnection *c) {
    int res;
    if (c->connected == false) {
      return;
    }

    LJSDEB("CLOSE: %s:%u %p %p\n", c, c->ld);

    if (c->uv_handle) {
      // this doesn't seem to stop immediately... wtf?
      uv_poll_stop(c->uv_handle);
      // and close poll handle
      uv_close((uv_handle_t *)c->uv_handle, on_handle_close);
      c->uv_handle = NULL;
    } else if (c->ld) {
      // ensure ldap instance gets freed
      res = ldap_unbind(c->ld);
      LJSDEB("UNBIND %s:%u res: %i\n", res);
      c->ld = NULL;
    }

    LJSDEB("CLOSE2: %s:%u %p %p\n", c, c->ld);
  }

  NODE_METHOD(Close) {
    HandleScope scope;
    GETOBJ(c);
    c->close(c);
    RETURN_INT(0);
  }

  NODE_METHOD(SetCallbacks) {
    HandleScope scope;
    GETOBJ(c);

    // I'm going to eschew error checking here, this should only be called from LDAP.js

    c->connected_cb    = Persistent<Function>::New(Local<Function>::Cast(args[0]));
    c->disconnected_cb = Persistent<Function>::New(Local<Function>::Cast(args[1]));
    c->searchresult_cb = Persistent<Function>::New(Local<Function>::Cast(args[2]));
    c->result_cb       = Persistent<Function>::New(Local<Function>::Cast(args[3]));
    c->error_cb        = Persistent<Function>::New(Local<Function>::Cast(args[4]));

    RETURN_INT(0);
  }

  NODE_METHOD(SetSyncCallbacks) {
    HandleScope scope;
    GETOBJ(c);

    c->syncentry_cb        = Persistent<Function>::New(Local<Function>::Cast(args[0]));
    c->syncintermediate_cb = Persistent<Function>::New(Local<Function>::Cast(args[1]));
    c->syncresult_cb       = Persistent<Function>::New(Local<Function>::Cast(args[2]));

    RETURN_INT(0);
  }

  static int parseServerControls(Local<Array> controls, LDAPControl **ctrls, int *countp) {
    int rc = LDAP_SUCCESS;
    int count = 0;
    for (int i = 0, n = controls->Length(); i < n; i++) {
      Local<Value> val = controls->Get(i);
      char *oid = NULL;
      Local<Value> ctrlValue;
      int crit = 0;
      
      if (val->IsString()) {
        oid = *(String::Utf8Value(val));
      } else if (val->IsArray()) {
        Local<Array> arr = Local<Array>::Cast(val);
        if (arr->Get(0)->IsString()) {
          oid = *(String::Utf8Value(arr->Get(0)));
        }
        ctrlValue = arr->Get(1);
      }
      
      if (oid) {
        if (oid[0] == '!') {
          crit = 1;
          oid++;
        }
        
        if (strcasecmp(oid, "manageDSAit") == 0) {
          rc = ldap_control_create(LDAP_CONTROL_MANAGEDSAIT, crit, NULL, 0, &ctrls[count++]);
          break;
        }
      }
    }
    *countp = count;
    return rc;
  }

  NODE_METHOD(Search) {
    HandleScope scope;
    GETOBJ(c);
    int msgid, rc, ctrlCount = 0;
    char * attrs[255];
    char ** ap;
    LDAPControl** serverCtrls;
    int page_size = 0;
    int page_offset = 0;
    char * sort_str = NULL;
    Local<Object> cookieObj;
    struct berval* cookie = NULL;
    
    ARG_STR(base,         0);
    ARG_INT(searchscope,  1);
    ARG_STR(filter,       2);
    ARG_STR(attrs_str,    3);
    ARG_ARRAY(controls,   4);

    if (!(args[5]->IsUndefined())) {
      // this is a paged search
      page_size = args[5]->Int32Value();
      if (!(args[6]->IsUndefined())) {
        if (!args[6]->IsObject()) {
          RETURN_INT(-1);
        }
        cookieObj = args[6]->ToObject();
        if (cookieObj->InternalFieldCount() != 1) {
          RETURN_INT(-1);
        }
        cookie = static_cast<berval*>(cookieObj->GetPointerFromInternalField(0));
        if (cookie == NULL) {
          RETURN_INT(-1);
        }
        cookieObj->SetPointerInInternalField(0, NULL);
      }
    }

    if (c->ld == NULL) {
      if (cookie) {
        ber_bvfree(cookie);
        cookie = NULL;
      }
      close(c);
      RETURN_INT(LDAP_SERVER_DOWN);
    }

    if (!(args[7]->IsUndefined())) {
      // this is a vlv search
      page_offset = args[7]->Int32Value();
    }
    if (args[8]->IsString()) {
      String::Utf8Value sortString(args[8]);
      sort_str = strdup(*sortString);
    }

    char *bufhead = strdup(*attrs_str);
    char *buf = bufhead;

    for (ap = attrs; (*ap = strsep(&buf, " \t,")) != NULL;)
      if (**ap != '\0')
        if (++ap >= &attrs[255])
          break;

    // Initialize server controls
    serverCtrls = (LDAPControl **) calloc(controls->Length() + 3, sizeof(LDAPControl *));

    if (sort_str) {
      LDAPSortKey **sortKeyList = NULL;
      rc = ldap_create_sort_keylist(&sortKeyList, sort_str);
      
      free(sort_str);
      sort_str = NULL;

      if (sortKeyList) {
        // create sort control
        rc = ldap_create_sort_control(c->ld, sortKeyList, 0, &serverCtrls[ctrlCount++]);
        // free key list
        ldap_free_sort_keylist(sortKeyList);
        sortKeyList = NULL;
      }
      if (rc != LDAP_SUCCESS) {
        if (cookie) {
          ber_bvfree(cookie);
          cookie = NULL;
        }
        ldap_controls_free(serverCtrls);
        free(bufhead);
        RETURN_INT(-1);
      }
    }

    if (page_offset > 0 || ctrlCount) {
      // vlv must be used if offset is specified or sort control is used
      LDAPVLVInfo vlvInfo;
      vlvInfo.ldvlv_after_count = (page_size > 0 ? page_size : 10) - 1;
      vlvInfo.ldvlv_attrvalue = NULL;
      vlvInfo.ldvlv_before_count = 0;
      vlvInfo.ldvlv_context = cookie;
      vlvInfo.ldvlv_count = 0;
      vlvInfo.ldvlv_extradata = NULL;
      // convert zero-based offset to one-based
      vlvInfo.ldvlv_offset = (page_offset > 0 ? page_offset : 0) + 1;
      // vlvInfo.ldvlv_version = LDAP_VLVINFO_VERSION; // Somehow ldapsearch.c just left this field out. Maybe it's not used
      rc = ldap_create_vlv_control(c->ld, &vlvInfo, &serverCtrls[ctrlCount++]);
      if (cookie) {
        ber_bvfree(cookie);
        cookie = NULL;
      }
      if (rc != LDAP_SUCCESS) {
        ldap_controls_free(serverCtrls);
        free(bufhead);
        RETURN_INT(-1);
      }

    } else if (cookie) {
      ber_bvfree(cookie);
      cookie = NULL;
    }

    // parse other server controls
    rc = parseServerControls(controls, serverCtrls, &ctrlCount);

    if (rc != LDAP_SUCCESS) {
      ldap_controls_free(serverCtrls);
      free(bufhead);
      RETURN_INT(-1);
    }

    rc = ldap_search_ext(c->ld, *base, searchscope, *filter, attrs, 0,
                         serverCtrls, NULL, NULL, 0, &msgid);
    
    ldap_controls_free(serverCtrls);
    
    if (LDAP_API_ERROR(rc)) {
      msgid = -1;
    }

    free(bufhead);

    RETURN_INT(msgid);
  }

  NODE_METHOD(err2string) {
    HandleScope scope;
    GETOBJ(c);
    int err;

    if (args.Length() < 1) {
      ldap_get_option(c->ld, LDAP_OPT_RESULT_CODE, (void *)&err);
      return scope.Close(String::New(ldap_err2string(err)));
    }

    ARG_INT(code, 0);

    return scope.Close(String::New(ldap_err2string(code)));
  }


  NODE_METHOD(Modify) {
    HandleScope scope;
    GETOBJ(c);
    int msgid;

    ARG_STR(dn, 0);
    ARG_ARRAY(modsHandle, 1);
    ARG_ARRAY(controls, 2);

    if (c->ld == NULL) {
      close(c);
      RETURN_INT(LDAP_SERVER_DOWN);
    }
    
    LDAPControl **serverCtrls = (LDAPControl **) calloc(controls->Length() + 1, sizeof(LDAPControl *));
    int ctrlCount = 0;
    if (parseServerControls(controls, serverCtrls, &ctrlCount) != LDAP_SUCCESS) {
      ldap_controls_free(serverCtrls);
      RETURN_INT(-1);
    }

    int numOfMods = modsHandle->Length();
    for (int i = 0; i < numOfMods; i++) {
      // Hey this is so cumbersome.
      if (!modsHandle->Get(Integer::New(i))->IsObject()) {
        THROW("Each mod should be an object");
      }
    }

    // Now prepare the LDAPMod array.
    LDAPMod **ldapmods = (LDAPMod **) malloc(sizeof(LDAPMod *) * (numOfMods + 1));

    for (int i = 0; i < numOfMods; i++) {
      Local<Object> modHandle =
        Local<Object>::Cast(modsHandle->Get(Integer::New(i)));

      ldapmods[i] = (LDAPMod *) malloc(sizeof(LDAPMod));

      // Step 1: mod_op
      String::Utf8Value mod_op(modHandle->Get(String::New("op")));

      if (!strcmp(*mod_op, "add")) {
        ldapmods[i]->mod_op = LDAP_MOD_ADD;
      } else if (!strcmp(*mod_op, "delete")) {
        ldapmods[i]->mod_op = LDAP_MOD_DELETE;
      } else {
        ldapmods[i]->mod_op = LDAP_MOD_REPLACE;
      }

      // Step 2: mod_type
      String::Utf8Value mod_type(modHandle->Get(String::New("attr")));
      ldapmods[i]->mod_type = strdup(*mod_type);

      // Step 3: mod_vals
      Local<Array> modValsHandle =
        Local<Array>::Cast(modHandle->Get(String::New("vals")));
      int modValsLength = modValsHandle->Length();
      ldapmods[i]->mod_values = (char **) malloc(sizeof(char *) *
                                                 (modValsLength + 1));
      for (int j = 0; j < modValsLength; j++) {
        String::Utf8Value modValue(modValsHandle->Get(Integer::New(j)));
        ldapmods[i]->mod_values[j] = strdup(*modValue);
      }
      ldapmods[i]->mod_values[modValsLength] = NULL;
    }

    ldapmods[numOfMods] = NULL;
    
    ldap_modify_ext(c->ld, *dn, ldapmods, serverCtrls, NULL, &msgid);

    if (msgid == LDAP_SERVER_DOWN) {
      close(c);
    }
    
    ldap_controls_free(serverCtrls);
    ldap_mods_free(ldapmods, 1);

    RETURN_INT(msgid);
  }

  NODE_METHOD(Add)
  {
    HandleScope scope;
    GETOBJ(c);
    int msgid;
    int fd;

    ARG_STR(dn, 0);
    ARG_ARRAY(attrsHandle, 1);
    ARG_ARRAY(controls, 2);

    if (c->ld == NULL) RETURN_INT(LDAP_SERVER_DOWN);
    
    LDAPControl **serverCtrls = (LDAPControl **) calloc(controls->Length() + 1, sizeof(LDAPControl *));
    int ctrlCount = 0;
    if (parseServerControls(controls, serverCtrls, &ctrlCount) != LDAP_SUCCESS) {
      ldap_controls_free(serverCtrls);
      RETURN_INT(-1);
    }

    int numOfAttrs = attrsHandle->Length();
    for (int i = 0; i < numOfAttrs; i++) {
      // Hey this is still so cumbersome.
      if (!attrsHandle->Get(Integer::New(i))->IsObject()) {
        THROW("Each attr should be an object");
      }
    }

    // Now prepare the LDAPMod array.
    LDAPMod **ldapmods = (LDAPMod **) malloc(sizeof(LDAPMod *) * (numOfAttrs + 1));

    for (int i = 0; i < numOfAttrs; i++) {
      Local<Object> attrHandle =
        Local<Object>::Cast(attrsHandle->Get(Integer::New(i)));

      ldapmods[i] = (LDAPMod *) malloc(sizeof(LDAPMod));

      // Step 1: mod_op
      ldapmods[i]->mod_op = LDAP_MOD_ADD;

      // Step 2: mod_type
      String::Utf8Value mod_type(attrHandle->Get(String::New("attr")));
      ldapmods[i]->mod_type = strdup(*mod_type);

      // Step 3: mod_vals
      Local<Array> attrValsHandle =
        Local<Array>::Cast(attrHandle->Get(String::New("vals")));
      int attrValsLength = attrValsHandle->Length();
      ldapmods[i]->mod_values = (char **) malloc(sizeof(char *) *
                                                 (attrValsLength + 1));
      for (int j = 0; j < attrValsLength; j++) {
        String::Utf8Value modValue(attrValsHandle->Get(Integer::New(j)));
        ldapmods[i]->mod_values[j] = strdup(*modValue);
      }
      ldapmods[i]->mod_values[attrValsLength] = NULL;
    }

    ldapmods[numOfAttrs] = NULL;

    ldap_add_ext(c->ld, *dn, ldapmods, serverCtrls, NULL, &msgid);
    ldap_get_option(c->ld, LDAP_OPT_DESC, &fd);

    if (msgid == LDAP_SERVER_DOWN) {
      close(c);
    }

    ldap_controls_free(serverCtrls);
    ldap_mods_free(ldapmods, 1);

    RETURN_INT(msgid);
  }

  NODE_METHOD(Delete)
  {
    HandleScope scope;
    GETOBJ(c);
    int msgid;
    int fd;

    ARG_STR(dn, 0);
    ARG_ARRAY(controls, 1);

    if (c->ld == NULL) RETURN_INT(LDAP_SERVER_DOWN);
    
    LDAPControl **serverCtrls = (LDAPControl **) calloc(controls->Length() + 1, sizeof(LDAPControl *));
    int ctrlCount = 0;
    if (parseServerControls(controls, serverCtrls, &ctrlCount) != LDAP_SUCCESS) {
      ldap_controls_free(serverCtrls);
      RETURN_INT(-1);
    }

    ldap_delete_ext(c->ld, *dn, serverCtrls, NULL, &msgid);
    ldap_get_option(c->ld, LDAP_OPT_DESC, &fd);

    if (msgid == LDAP_SERVER_DOWN) {
      close(c);
    }
    
    ldap_controls_free(serverCtrls);

    RETURN_INT(msgid);
  }

  NODE_METHOD(Rename)
  {
    HandleScope scope;
    GETOBJ(c);
    int msgid;

    // Validate args.
    ENFORCE_ARG_LENGTH(2, "Invalid number of arguments to Rename()");
    ENFORCE_ARG_STR(0);
    ENFORCE_ARG_STR(1);
    ARG_STR(dn, 0);
    ARG_STR(newrdn, 1);

    if (c->ld == NULL) {
      close(c);
      RETURN_INT(LDAP_SERVER_DOWN);
    }

    if ((msgid = ldap_modrdn(c->ld, *dn, *newrdn)) == LDAP_SERVER_DOWN) {
      close(c);
    }

    RETURN_INT(msgid);
  }

  NODE_METHOD(SimpleBind)
  {
    HandleScope scope;
    GETOBJ(c);
    int msgid;
    char * binddn = NULL;
    char * password = NULL;

    LJSDEB("BIND: %s:%u %p %p\n", c, c->ld);

    if (c->ld == NULL) {
      RETURN_INT(LDAP_SERVER_DOWN);
    }

    if (args.Length() > 0) {
      // this is NOT an anonymous bind
      ENFORCE_ARG_LENGTH(2, "Invalid number of arguments to SimpleBind()");
      ENFORCE_ARG_STR(0);
      ENFORCE_ARG_STR(1);
      ARG_STR(j_binddn, 0);
      ARG_STR(j_password, 1);

      binddn = strdup(*j_binddn);
      password = strdup(*j_password);
    }

    if ((msgid = ldap_simple_bind(c->ld, binddn, password)) == LDAP_SERVER_DOWN) {
      LJSDEB("BINDFAIL %s:%u %p %p\n", c, c->ld);
      close(c);
    } else {
      LDAPConnection::SetIO(c);
    }

    free(binddn);
    free(password);

    RETURN_INT(msgid);
  }

  static void SetIO(LDAPConnection *c) {
    int fd;
    uv_poll_t * handle = new uv_poll_t;
    handle->data = c;

    if (c->iowatching) {
      return;
    }

    ldap_get_option(c->ld, LDAP_OPT_DESC, &fd);

    LJSDEB("FD: %s:%u %u\n", fd);

    uv_poll_init(uv_default_loop(), handle, fd);
    uv_poll_start(handle, UV_READABLE, io_event);
    c->iowatching = true;
    c->uv_handle = handle;
  }

  static Local<Object> makeBuffer(berval * val) {
    HandleScope scope;

    node::Buffer *slowBuffer = node::Buffer::New(val->bv_len);
    memcpy(node::Buffer::Data(slowBuffer), val->bv_val, val->bv_len);
    v8::Local<v8::Object> globalObj = v8::Context::GetCurrent()->Global();
    v8::Local<v8::Function> bufferConstructor = v8::Local<v8::Function>::Cast(globalObj->Get(v8::String::New("Buffer")));
    v8::Handle<v8::Value> constructorArgs[3] = { slowBuffer->handle_, v8::Integer::New(val->bv_len), v8::Integer::New(0) };
    v8::Local<v8::Object> actualBuffer = bufferConstructor->NewInstance(3, constructorArgs);
    return scope.Close(actualBuffer);
  }

  static int isBinary(char * attrname) {
    if (!strcmp(attrname, "jpegPhoto") ||
        !strcmp(attrname, "photo") ||
        !strcmp(attrname, "personalSignature") ||
        !strcmp(attrname, "userCertificate") ||
        !strcmp(attrname, "cACertificate") ||
        !strcmp(attrname, "authorityRevocationList") ||
        !strcmp(attrname, "certificateRevocationList") ||
        !strcmp(attrname, "deltaRevocationList") ||
        !strcmp(attrname, "crossCertificatePair") ||
        !strcmp(attrname, "x500UniqueIdentifier") ||
        !strcmp(attrname, "audio") ||
        !strcmp(attrname, "javaSerializedObject") ||
        !strcmp(attrname, "thumbnailPhoto") ||
        !strcmp(attrname, "thumbnailLogo") ||
        !strcmp(attrname, "supportedAlgorithms") ||
        !strcmp(attrname, "protocolInformation") ||
        strstr(attrname, ";binary")) {
      return 1;
    }
    return 0;
  }


  Local<Value> parseReply(LDAPConnection * c, LDAPMessage * msg)
  {
    HandleScope scope;
    LDAPMessage * entry = NULL;
    BerElement * berptr = NULL;
    char * attrname     = NULL;
    berval ** vals;
    Local<Array>  js_result_list;
    Local<Object> js_result;
    Local<Array>  js_attr_vals;
    int j;
    char * dn;
    LDAPControl **ctrls = NULL;

    int entry_count = ldap_count_entries(c->ld, msg);

    js_result_list = Array::New(entry_count);

    for (entry = ldap_first_entry(c->ld, msg), j = 0 ; entry ;
         entry = ldap_next_entry(c->ld, entry), j++) {

      js_result = Object::New();
      js_result_list->Set(Integer::New(j), js_result);

      dn = ldap_get_dn(c->ld, entry);

      // get sync controls, if present...
      ldap_get_entry_controls( c->ld, entry, &ctrls );
      if ( ctrls != NULL ) {
        struct berval entryUUID = { 0, NULL };
        int state, i;
        BerElement *ber = NULL;

        for ( i = 0; ctrls[ i ] != NULL; i++ ) {
          if ( strcmp( ctrls[ i ]->ldctl_oid, LDAP_CONTROL_SYNC_STATE ) == 0 ) {
            break;
          }
        }
        if ( ctrls[ i ] != NULL ) {
          /* extract data */
          ber = ber_init( &ctrls[ i ]->ldctl_value );
          if ( ber != NULL ) {
            /* scan entryUUID in-place ("m") */
            if ( ber_scanf( ber, "{em" /*"}"*/, &state, &entryUUID ) == LBER_ERROR || entryUUID.bv_len != 0 ) {
              char * uuid;

              uuid_to_string((const uuid_t *)entryUUID.bv_val, uuid);
              js_result->Set(String::New("_syncUUID"), String::New(uuid));
              js_result->Set(String::New("_syncState"), Integer::New(state));
              free(uuid);
            }
          }
        }
	if ( ctrls != NULL ) {
          ldap_controls_free( ctrls );
	}
      }
      for (attrname = ldap_first_attribute(c->ld, entry, &berptr) ;
           attrname ; attrname = ldap_next_attribute(c->ld, entry, berptr)) {
        vals = ldap_get_values_len(c->ld, entry, attrname);
        int num_vals = ldap_count_values_len(vals);
        js_attr_vals = Array::New(num_vals);
        js_result->Set(String::New(attrname), js_attr_vals);

        int bin = c->isBinary(attrname);

        for (int i = 0 ; i < num_vals && vals[i] ; i++) {
          if (bin) {
            js_attr_vals->Set(Integer::New(i), c->makeBuffer(vals[i]));
          } else {
            js_attr_vals->Set(Integer::New(i), String::New(vals[i]->bv_val));
          }
        } // all values for this attr added.
        ldap_value_free_len(vals);
        ldap_memfree(attrname);
      } // attrs for this entry added. Next entry.
      js_result->Set(String::New("dn"), String::New(dn));
      ber_free(berptr,0);
      ldap_memfree(dn);
    } // all entries done.

    return scope.Close(js_result_list);
  }

  static void io_event (uv_poll_t* handle, int status, int events) {
    HandleScope scope;
    LDAPConnection *c = (LDAPConnection *)handle->data;
    LDAPMessage * res = NULL;
    LDAPControl** srv_controls = NULL;
    Handle<Value> args[5];
    int msgid = 0;
    int errp;
    LJSDEB("LDi: %s:%u %p %p\n", c, c->ld);

    if (c->connected == false) {
      LJSDEB("ACTIVITY ON CLOSED DESCRIPTOR %s:%u %p\n", c);
      return;
    }

//    not sure if this is neccesary...$
//    if (!(events & EV_READ)) {$
//      LJSDEB("EV_READ %s:%u\n");$
//      return;$
//    }$

    if (c->ld == NULL) {
      // disconnect event, or something arriving after
      // close(). Either way, ignore it.
      LJSDEB("NULL %s:%u %p %p\n", c, c->ld);
      return;
    }

    if (c->ls) {
      // there is a weird timing problem where a sync entry gets
      // missed. Calling poll twice seems to make it work.
      ldap_sync_poll(c->ls);
    }

    // now check for any other pending messages....
    switch(ldap_result(c->ld, LDAP_RES_ANY, LDAP_MSG_ALL, &ldap_tv, &res)) {
    case 0:
      LJSDEB("LDi4: %s:%u %p %p\n", c, c->ld);
      return;
    case -1:
      LJSDEB("LDi3: %s:%u %p %p\n", c, c->ld);
      close(c);
      return;
    default:
      ldap_parse_result(c->ld, res, &errp,
                        NULL, NULL, NULL, &srv_controls, 0);
      msgid = ldap_msgid(res);

      switch ( ldap_msgtype( res ) ) {
      case LDAP_RES_SEARCH_REFERENCE:
        break;
      case LDAP_RES_SEARCH_ENTRY:
      case LDAP_RES_SEARCH_RESULT:
        if (srv_controls) {
          struct berval* cookie = NULL;
          int rc;
          LDAPControl* control = NULL;
          Local<Object> pageResult = Object::New();

          control = ldap_control_find(LDAP_CONTROL_SORTRESPONSE, srv_controls, NULL);
          if (control) {
            Local<Object> sortResult = Object::New();
            ber_int_t sort_rc = 0;
            char *error_attr = NULL;
            rc = ldap_parse_sortresponse_control(c->ld, control, &sort_rc, &error_attr);
            if (rc == LDAP_SUCCESS) {
              sortResult->Set(String::New("returnCode"), Integer::New(sort_rc));
              if (error_attr) {
                sortResult->Set(String::New("errorAttr"), String::New(error_attr));
                ldap_memfree(error_attr);
                error_attr = NULL;
              }
              pageResult->Set(String::New("sort"), sortResult);
            }
            control = NULL;
          }

          int pos = 0;
          int count = 0;
          int errcode = LDAP_SUCCESS;
          if ( (control = ldap_control_find(LDAP_CONTROL_VLVRESPONSE, srv_controls, NULL)) ) {
            rc = ldap_parse_vlvresponse_control(c->ld, control, &pos, &count, &cookie, &errcode);
            if (rc == LDAP_SUCCESS) {
              pageResult->Set(String::New("offset"), Integer::New(pos - 1));
              pageResult->Set(String::New("count"), Integer::New(count));
              pageResult->Set(String::New("vlvReturnCode"), Integer::New(errcode));
            }
            control = NULL;
          } else if ( (control = ldap_control_find(LDAP_CONTROL_PAGEDRESULTS, srv_controls, NULL)) ) {
#if LDAP_DEPRECATED
            rc = ldap_parse_page_control(c->ld, srv_controls, &count, &cookie);
#else
            cookie = (struct berval *) malloc( sizeof( struct berval ) );
            rc = ldap_parse_pageresponse_control(c->ld, control, &count, cookie);
#endif
            if (rc == LDAP_SUCCESS) {
              pageResult->Set(String::New("count"), Integer::New(count));
            }
            control = NULL;
          }
          
          if (!cookie || cookie->bv_val == NULL || !*cookie->bv_val) {
            if (cookie) {
              ber_bvfree(cookie);
            }
            args[3] = Undefined();
          } else {
            Local<Object> cookieObj(cookie_template->NewInstance());
            cookieObj->SetPointerInInternalField(0, cookie);
            args[3] = cookieObj;
          }
          args[4] = pageResult;

          ldap_controls_free(srv_controls);
          srv_controls = NULL;
        } else {
          args[3] = Undefined();
          args[4] = Undefined();
        }

        args[0] = Integer::New(msgid);
        args[1] = Undefined(); // TODO: check for errors.
        args[2] = c->parseReply(c, res);
        // args[4] set above

        EMITSEARCHRESULT(c, args);
        break;

      case LDAP_RES_BIND:
      case LDAP_RES_MODIFY:
      case LDAP_RES_MODDN:
      case LDAP_RES_ADD:
      case LDAP_RES_DELETE:
        {
          args[0] = Integer::New(msgid);
          args[1] = errp?Integer::New(errp):Undefined();
          args[2] = Undefined(); // Any data goes here

          EMITRESULT(c, args);
        }
        break;
      default:
        args[0] = Integer::New(msgid);
        EMITERROR(c, args);
        break;
      }
      ldap_msgfree(res);
    }
    LJSDEB("LDi2: %s:%u %p %p\n", c, c->ld);
  }

  NODE_METHOD(SyncPoll) {
    HandleScope scope;
    GETOBJ(c);
    LJSDEB("LDp: %s:%u %p %p\n", c, c->ld);

    if (c->ls == NULL) {
      RETURN_INT(0);
    }

    if (c->ls->ls_ld) {
      ldap_sync_poll(c->ls);
    }
    LJSDEB("LDp2: %s:%u %p %p\n", c, c->ld);
    RETURN_INT(0);
  }


  /* *************************************************************************************
   * Sync Routines
   * These routines handle sync status
   *
   * ACKNOWLEDGEMENTS:
   * Adapted from software originally developed by Pierangelo Masarati
   * for inclusion in OpenLDAP.
   *
   * ************************************************************************************/

  NODE_METHOD(Sync) {
    HandleScope scope;
    GETOBJ(c);
    ldap_sync_t *ls;

    ARG_STR(base,         0);
    ARG_INT(searchscope,  1);
    ARG_STR(filter,       2);
    ARG_STR(attrs_str,    3);
    ARG_STR(cookie,       4);

    if (c->ld == NULL) {
      RETURN_INT(-1);
    }

    ls = (ldap_sync_t *)malloc(sizeof(ldap_sync_t));
    ldap_sync_initialize(ls);
    char ** attrs = (char **)ldap_memalloc(sizeof(char *)*2);

    attrs[0] = ldap_strdup("*");
    attrs[1] = NULL;

    ls->ls_base = ldap_strdup(*base);
    ls->ls_scope = searchscope;
    ls->ls_filter = ldap_strdup(*filter);
    ls->ls_attrs = attrs;
    ls->ls_timelimit = 0;
    ls->ls_sizelimit = 0;
    ls->ls_timeout = 0;
    ls->ls_search_entry = c->SyncSearchEntry;
    ls->ls_intermediate = c->SyncIntermediate;
    ls->ls_search_result = c->SyncResult;
    ls->ls_private = c;
    ls->ls_ld = c->ld;
    ls->ls_cookie = *(ber_bvstrdup(*cookie));

    c->ls = ls;

    ldap_sync_init(ls, LDAP_SYNC_REFRESH_AND_PERSIST);

    RETURN_INT(0);
  }

  NODE_METHOD(GetCookie) {
    HandleScope Scope;
    GETOBJ(c);
    if (c->ls) {
      return Scope.Close(String::New(c->ls->ls_cookie.bv_val));
    }
    return Undefined();
  }

  static int SyncSearchEntry(ldap_sync_t * ls, LDAPMessage * msg,
                      struct berval *entryUUID,
                      ldap_sync_refresh_t phase) {
    LDAPConnection *c = (LDAPConnection *)ls->ls_private;
    Handle<Value> args[1] = {
      c->parseReply(c, msg)
      // parseReply will pull the UUID and state out for us.
    };
    TryCatch tc;
    c->syncentry_cb->Call(Context::GetCurrent()->Global(), 1, args);
    if (tc.HasCaught()) {
      FatalException(tc);
    }
    return 0;
  }

  static int SyncIntermediate(ldap_sync_t *ls,
                       LDAPMessage *msg, BerVarray syncUUIDs,
                       ldap_sync_refresh_t phase) {
    LJSDEB("Search Intermediate! %s:%u\n");
    LDAPConnection *c = (LDAPConnection *)ls->ls_private;
    Handle<Value> args[2] = {
      String::New(ls->ls_cookie.bv_val),
      Integer::New(ls->ls_refreshPhase)
    };

    TryCatch tc;
    c->syncintermediate_cb->Call(Context::GetCurrent()->Global(), 2, args);
    if (tc.HasCaught()) {
      FatalException(tc);
    }
    return 0;
  }
  static int SyncResult(ldap_sync_t *ls,
                 LDAPMessage *msg, int refreshDeletes) {
    LJSDEB("SyncResult! %s:%u\n");
    LDAPConnection *c = (LDAPConnection *)ls->ls_private;
    Handle<Value> args[1] = {
      c->parseReply(c, msg)
      // parseReply will pull the UUID and state out for us.
    };
    TryCatch tc;
    c->syncresult_cb->Call(Context::GetCurrent()->Global(), 1, args);
    if (tc.HasCaught()) {
      FatalException(tc);
    }
    return 0;
  }

  Local<Value> uuid2array (BerVarray syncUUIDs) {
    HandleScope scope;
    int i;
    Local<Array>  js_result_list;

    // is there a better way to count this?
    for ( i = 0; syncUUIDs[ i ].bv_val != NULL; i++ );

    js_result_list = Array::New(i);

    for ( i = 0; syncUUIDs[ i ].bv_val != NULL; i++ ) {
      char * uuid;
      uuid_to_string((const uuid_t *)syncUUIDs[ i ].bv_val, uuid);
      js_result_list->Set(Integer::New(i), String::New(uuid));
      free(uuid);
    }

    return scope.Close(js_result_list);
  }
};

extern "C" void init(Handle<Object> target) {
  LDAPConnection::Initialize(target);
}

NODE_MODULE(LDAP, init);
