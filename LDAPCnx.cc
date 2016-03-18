#include "LDAPCnx.h"
#include <iostream>

static struct timeval ldap_tv = { 0, 0 };

// Search Result/Request Control
const int DEFAULT_SRC = 0;
const int SIMPLE_PAGED_RESULTS_SRC = 1;
const int VIRTUAL_LIST_VIEW_SRC = 2;

using namespace v8;
using namespace std;

static Persistent<ObjectTemplate> cookie_template;

Nan::Persistent<Function> LDAPCnx::constructor;

// Extracts a C string from a V8 Utf8Value.
const char* ToCString(const v8::String::Utf8Value& value) {
  return *value ? *value : "<string conversion failed>";
}

LDAPCnx::LDAPCnx() {
}

LDAPCnx::~LDAPCnx() {
#if NODELDAP_DEBUG
  cerr << "LDAPCnx()" << endl;
#endif
  free(this->ldap_callback);
  delete this->callback;
  delete this->reconnect_callback;
}

void LDAPCnx::Init(Local<Object> exports) {
#if NODELDAP_DEBUG
  cerr << "LDAPCnx::Init" << endl;
#endif
  Nan::HandleScope scope;

  // Prepare constructor template
  Local<FunctionTemplate> tpl = Nan::New<FunctionTemplate>(New);
  tpl->SetClassName(Nan::New("LDAPCnx").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  // Prototype
  Nan::SetPrototypeMethod(tpl, "search", Search);
  Nan::SetPrototypeMethod(tpl, "delete", Delete);
  Nan::SetPrototypeMethod(tpl, "bind", Bind);
  Nan::SetPrototypeMethod(tpl, "add", Add);
  Nan::SetPrototypeMethod(tpl, "modify", Modify);
  Nan::SetPrototypeMethod(tpl, "rename", Rename);
  Nan::SetPrototypeMethod(tpl, "initialize", Initialize);
  Nan::SetPrototypeMethod(tpl, "errorstring", GetErr);
  Nan::SetPrototypeMethod(tpl, "errorno", GetErrNo);
  Nan::SetPrototypeMethod(tpl, "fd", GetFD);
  Nan::SetPrototypeMethod(tpl, "close", Close);


  constructor.Reset(tpl->GetFunction());
  exports->Set(Nan::New("LDAPCnx").ToLocalChecked(), tpl->GetFunction());

  Isolate * isolate = exports->GetIsolate();
  Local<ObjectTemplate> ct = ObjectTemplate::New(isolate);
  ct->SetInternalFieldCount(1);
  cookie_template.Reset(isolate, ct);
}

void LDAPCnx::New(const Nan::FunctionCallbackInfo<Value>& info) {
#if NODELDAP_DEBUG
  cerr << "LDAPCnx::New" << endl;
#endif
  if (info.IsConstructCall()) {
    // Invoked as constructor: `new LDAPCnx(...)`
    LDAPCnx* ld = new LDAPCnx();
    ld->Wrap(info.Holder());

    ld->callback = new Nan::Callback(info[0].As<Function>());
    ld->reconnect_callback = new Nan::Callback(info[1].As<Function>());
    ld->disconnect_callback = new Nan::Callback(info[2].As<Function>());
    ld->handle = NULL;

    info.GetReturnValue().Set(info.Holder());
    return;
  }
  Nan::ThrowError("Must instantiate with new");
}

void LDAPCnx::Event(uv_poll_t* handle, int status, int events) {

  Nan::HandleScope scope;
  LDAPCnx *ld = (LDAPCnx *)handle->data;
  LDAPMessage * message = NULL;
  LDAPMessage * entry = NULL;
  LDAPControl** srv_controls = NULL;
  int err = -1;

  if (ld->ld == NULL) {
#if NODELDAP_DEBUG
    cerr << "LDAPCnx::Event connId:" << ld->connectionId <<" after closed()" << endl;
#endif
    if (ld->handle) {
      uv_poll_stop(ld->handle);
      ld->handle = NULL;
    }
    return;
  }

  int res = ldap_result(ld->ld, LDAP_RES_ANY, LDAP_MSG_ALL, &ldap_tv, &message);
#if NODELDAP_DEBUG
    cerr << "LDAPCnx::Event connId:" << ld->connectionId << ", res:" << res << endl;
#endif

  // 0: timeout occurred, which I don't think happens in async mode
  // -1: We can't really do much; we don't have a msgid to callback to
  if (res == 0) {
#if NODELDAP_DEBUG
    cerr << "LDAPCnx::Event connId:" << ld->connectionId << " failed.  Time out." << endl;
#endif
  }
  else if (res == -1)
  {
#if NODELDAP_DEBUG
    cerr << "LDAPCnx::Event connId:" << ld->connectionId << " failed.  Closing connection." << endl;
#endif

    if (ld->ld != NULL) {
      res = ldap_unbind(ld->ld);
      ld->ld = NULL;
      if (ld->handle) {
        uv_poll_stop(ld->handle);
        ld->handle = NULL;
      }
    }
  }
  else
  {
    //int err = ldap_result2error(ld->ld, message, 0);
    ldap_parse_result(ld->ld, message, &err,
                      NULL, NULL, NULL, &srv_controls, 0);
    if (err) {
#if NODELDAP_DEBUG
      cerr << "LDAPCnx::Event connId:"<< ld->connectionId <<" err: " << err << "(" << ldap_err2string(err) << ")" << endl;
#endif
    }

    switch ( ldap_msgtype( message ) ) {
    case LDAP_RES_SEARCH_REFERENCE:
      break;
    case LDAP_RES_SEARCH_ENTRY:
    case LDAP_RES_SEARCH_RESULT:
      {

        Local<Array> js_result_list = Nan::New<Array>(ldap_count_entries(ld->ld, message));

        int j;

        for (entry = ldap_first_entry(ld->ld, message), j = 0 ; entry ;
             entry = ldap_next_entry(ld->ld, entry), j++) {
          Local<Object> js_result = Nan::New<Object>();

          js_result_list->Set(Nan::New(j), js_result);

          char * dn = ldap_get_dn(ld->ld, entry);
          BerElement * berptr = NULL;
          for (char * attrname = ldap_first_attribute(ld->ld, entry, &berptr) ;
               attrname ; attrname = ldap_next_attribute(ld->ld, entry, berptr)) {
            berval ** vals = ldap_get_values_len(ld->ld, entry, attrname);
            int num_vals = ldap_count_values_len(vals);
            Local<Array> js_attr_vals = Nan::New<Array>(num_vals);
            js_result->Set(Nan::New(attrname).ToLocalChecked(), js_attr_vals);

            // char * bin = strstr(attrname, ";binary");
            int bin = !strcmp(attrname, "jpegPhoto");

            for (int i = 0 ; i < num_vals && vals[i] ; i++) {
              if (bin) {
                // js_attr_vals->Set(Nan::New(i), ld->makeBuffer(vals[i]));
                js_attr_vals->Set(Nan::New(i), Nan::CopyBuffer(vals[i]->bv_val, vals[i]->bv_len).ToLocalChecked());
              } else {
                js_attr_vals->Set(Nan::New(i), Nan::New(vals[i]->bv_val).ToLocalChecked());
              }
            } // all values for this attr added.
            ldap_value_free_len(vals);
            ldap_memfree(attrname);
          } // attrs for this entry added. Next entry.
          js_result->Set(Nan::New("dn").ToLocalChecked(), Nan::New(dn).ToLocalChecked());
          ber_free(berptr,0);
          ldap_memfree(dn);
        } // all entries done.

        if (srv_controls) {
          Isolate * isolate = v8::Isolate::GetCurrent();
          struct berval* cookie = NULL;
          int rc;
          LDAPControl* control = NULL;
          Local<Object> pageResult = Object::New(isolate);
          Local<Object> cookieObj = Object::New(isolate);

          control = ldap_control_find(LDAP_CONTROL_SORTRESPONSE, srv_controls, NULL);
          if (control) {
            Local<Object> sortResult = Object::New(isolate);
            ber_int_t sort_rc = 0;
            char *error_attr = NULL;
            rc = ldap_parse_sortresponse_control(ld->ld, control, &sort_rc, &error_attr);
            if (rc == LDAP_SUCCESS) {
              sortResult->Set(String::NewFromUtf8(isolate, "returnCode"), Integer::New(isolate, sort_rc));
              if (error_attr) {
                sortResult->Set(String::NewFromUtf8(isolate, "errorAttr"), String::NewFromUtf8(isolate, error_attr));
                ldap_memfree(error_attr);
                error_attr = NULL;
              }
              pageResult->Set(String::NewFromUtf8(isolate, "sort"), sortResult);
            }
            control = NULL;
          }

          int pos = 0;
          int count = 0;
          int errcode = LDAP_SUCCESS;
          if ( (control = ldap_control_find(LDAP_CONTROL_VLVRESPONSE, srv_controls, NULL)) ) {
            rc = ldap_parse_vlvresponse_control(ld->ld, control, &pos, &count, &cookie, &errcode);
            if (rc == LDAP_SUCCESS) {
              pageResult->Set(String::NewFromUtf8(isolate, "offset"), Integer::New(isolate, pos - 1));
              pageResult->Set(String::NewFromUtf8(isolate, "count"), Integer::New(isolate, count));
              pageResult->Set(String::NewFromUtf8(isolate, "vlvReturnCode"), Integer::New(isolate, errcode));
            }
            control = NULL;
          } else if ( (control = ldap_control_find(LDAP_CONTROL_PAGEDRESULTS, srv_controls, NULL)) ) {
#if LDAP_DEPRECATED
            rc = ldap_parse_page_control(ld->ld, srv_controls, &count, &cookie);
#else
            cookie = (struct berval *) malloc( sizeof( struct berval ) );
            rc = ldap_parse_pageresponse_control(ld->ld, control, &count, cookie);
#endif
            if (rc == LDAP_SUCCESS) {
              pageResult->Set(String::NewFromUtf8(isolate, "count"), Integer::New(isolate, count));
            }
            control = NULL;
          }

          if (!cookie || cookie->bv_val == NULL || !*cookie->bv_val) {
            if (cookie) {
              ber_bvfree(cookie);
            }
          } else {
            cookieObj->Set(String::NewFromUtf8(isolate, "bv_len"), Integer::New(isolate, cookie->bv_len));
            Nan::MaybeLocal<Object>buffer = Nan::NewBuffer(cookie->bv_val, cookie->bv_len);
            cookieObj->Set(String::NewFromUtf8(isolate, "bv_val"), buffer.ToLocalChecked());
          }

          ldap_controls_free(srv_controls);
          srv_controls = NULL;
          Local<Value> argv[6];
          argv[0] = Nan::New(err);
          if (err) {
            argv[1] = String::NewFromUtf8(isolate, ldap_err2string(err));
          } else {
            argv[1] = Nan::Undefined();
          }
          argv[2] = Nan::New(ldap_msgid(message));
          argv[3] = js_result_list;
          argv[4] = cookieObj;
          argv[5] = pageResult;
          ld->callback->Call(6, argv);
        }
        else {
          Isolate * isolate = v8::Isolate::GetCurrent();
          Local<Value> argv[4];
          argv[0] = Nan::New(err);
          if (err)
            argv[1] = String::NewFromUtf8(isolate, ldap_err2string(err));
          else
            argv[1] = Nan::Undefined();
          argv[2] = Nan::New(ldap_msgid(message));
          argv[3] = js_result_list;
          ld->callback->Call(4, argv);
        }

        break;
      }
    case LDAP_RES_BIND:
    case LDAP_RES_MODIFY:
    case LDAP_RES_MODDN:
    case LDAP_RES_ADD:
    case LDAP_RES_DELETE:
      {
        Isolate * isolate = v8::Isolate::GetCurrent();
        Local<Value> argv[3];
        argv[0] = Nan::New(err);
        if (err)
          argv[1] = String::NewFromUtf8(isolate, ldap_err2string(err));
        else
          argv[1] = Nan::Undefined();
        argv[2] = Nan::New(ldap_msgid(message));
        ld->callback->Call(3, argv);
        break;
      }
    default:
      {

        //emit an error
        // Nan::ThrowError("Unrecognized packet");
      }
    }
  }

  ldap_msgfree(message);
  return;
}

// this fires when the LDAP lib reconnects.
// TODO: plumb in a reconnect handler
// so the caller can re-bind when the reconnect
// happens... this could be handled automatically
// (remember the last bind call) by the js driver
int LDAPCnx::OnConnect(LDAP *ld, Sockbuf *sb,
                      LDAPURLDesc *srv, struct sockaddr *addr,
                      struct ldap_conncb *ctx) {
  int fd;
  LDAPCnx * lc = (LDAPCnx *)ctx->lc_arg;
#if NODELDAP_DEBUG
  cerr << "LDAPCnx::OnConnect connId:" << lc->connectionId << endl;
#endif

  if (lc->handle == NULL) {
    lc->handle = new uv_poll_t;
    ldap_get_option(ld, LDAP_OPT_DESC, &fd);
    uv_poll_init(uv_default_loop(), lc->handle, fd);
    lc->handle->data = lc;
  } else {
    uv_poll_stop(lc->handle);
  }
  uv_poll_start(lc->handle, UV_READABLE, (uv_poll_cb)lc->Event);

  lc->reconnect_callback->Call(0, NULL);

  return LDAP_SUCCESS;
}

void LDAPCnx::OnDisconnect(LDAP *ld, Sockbuf *sb,
                      struct ldap_conncb *ctx) {
  // this fires when the connection closes
  LDAPCnx * lc = (LDAPCnx *)ctx->lc_arg;
#if NODELDAP_DEBUG
  cerr << "LDAPCnx::OnDisconnect connId:" << lc->connectionId << endl;
#endif
  if (lc->handle) {
    uv_poll_stop(lc->handle);
    lc->handle = NULL;
  }
  lc->disconnect_callback->Call(0, NULL);
}

void LDAPCnx::Initialize(const Nan::FunctionCallbackInfo<Value>& info) {
#if NODELDAP_DEBUG_ARG
  cerr << "LDAPCnx::Initialize" << endl;
  for (int i = 0; i < info.Length(); i++) {
    v8::String::Utf8Value str(info[i]);
    const char* cstr = ToCString(str);
    cerr << "LDAPCnx::Initialize: arg" << i << "=" << cstr << endl;
  }
#endif

  LDAPCnx* ld = ObjectWrap::Unwrap<LDAPCnx>(info.Holder());
  Nan::Utf8String       url(info[0]);
  int fd              = 0;
  int ver             = LDAP_VERSION3;
  int timeout         = info[1]->NumberValue();
  int starttls        = info[2]->NumberValue();
  int connectionId    = info[3]->NumberValue();

  ld->ldap_callback = (ldap_conncb *)malloc(sizeof(ldap_conncb));
  ld->ldap_callback->lc_add = OnConnect;
  ld->ldap_callback->lc_del = OnDisconnect;
  ld->ldap_callback->lc_arg = ld;
  ld->connectionId = connectionId;

  int res = ldap_initialize(&(ld->ld), *url) ;
  if (res != LDAP_SUCCESS) {
#if NODELDAP_DEBUG
    cerr << "LDAPCnx::Initialize Error:" << res << endl;
#endif
    Nan::ThrowError("Error init");
    return;
  }
#if NODELDAP_DEBUG
  cerr << "LDAPCnx::Initialized connId:" << ld->connectionId <<" result:" << res << endl;
#endif

  struct timeval ntimeout = { timeout/1000, (timeout%1000) * 1000 };

  ldap_set_option(ld->ld, LDAP_OPT_PROTOCOL_VERSION, &ver);
  ldap_set_option(ld->ld, LDAP_OPT_CONNECT_CB,       ld->ldap_callback);
  ldap_set_option(ld->ld, LDAP_OPT_REFERRALS,        LDAP_OPT_OFF);
  ldap_set_option(ld->ld, LDAP_OPT_NETWORK_TIMEOUT,  &ntimeout);

  if (starttls == 1) {
    res = ldap_start_tls_s(ld->ld, NULL, NULL);
#if NODELDAP_DEBUG
    cerr << "LDAPCnx::Initialize ldap_start_tls_s: " << res << endl;
#endif
  }

  res = ldap_simple_bind(ld->ld, NULL, NULL);
#if NODELDAP_DEBUG
  cerr << "LDAPCnx::Initialize ldap_simple_bind: " << res << endl;
#endif

  if (res == -1) {
    Nan::ThrowError("Error anon bind");
    return;
  }

  ldap_get_option(ld->ld, LDAP_OPT_DESC, &fd);

  if (fd < 0) {
#if NODELDAP_DEBUG
    cerr << "LDAPCnx::Initialize Connection issue: fd < 0" << endl;
#endif
    Nan::ThrowError("Connection issue");
    return;
  }

  info.GetReturnValue().Set(info.This());
}

void LDAPCnx::GetErr(const Nan::FunctionCallbackInfo<Value>& info) {
  LDAPCnx* ld = ObjectWrap::Unwrap<LDAPCnx>(info.Holder());
  int err;
  ldap_get_option(ld->ld, LDAP_OPT_RESULT_CODE, &err);
  info.GetReturnValue().Set(Nan::New(ldap_err2string(err)).ToLocalChecked());
}

void LDAPCnx::GetErrNo(const Nan::FunctionCallbackInfo<Value>& info) {
  LDAPCnx* ld = ObjectWrap::Unwrap<LDAPCnx>(info.Holder());
  int err;
  ldap_get_option(ld->ld, LDAP_OPT_RESULT_CODE, &err);
  info.GetReturnValue().Set(err);
}

void LDAPCnx::GetFD(const Nan::FunctionCallbackInfo<Value>& info) {
  LDAPCnx* ld = ObjectWrap::Unwrap<LDAPCnx>(info.Holder());
  int fd;
  ldap_get_option(ld->ld, LDAP_OPT_DESC, &fd);
  info.GetReturnValue().Set(fd);
}

void LDAPCnx::Delete(const Nan::FunctionCallbackInfo<Value>& info) {
  LDAPCnx* ld = ObjectWrap::Unwrap<LDAPCnx>(info.Holder());
  Nan::Utf8String dn(info[0]);

  info.GetReturnValue().Set(ldap_delete(ld->ld, *dn));
}

void LDAPCnx::Bind(const Nan::FunctionCallbackInfo<Value>& info) {
  LDAPCnx* ld = ObjectWrap::Unwrap<LDAPCnx>(info.Holder());
#if NODELDAP_DEBUG_ARG
  cerr << "LDAPCnx::Bind connId:" << ld->connectionId << endl;
  for (int i = 0; i < info.Length(); i++) {
    v8::String::Utf8Value str(info[i]);
    const char* cstr = ToCString(str);
    cerr << "LDAPCnx::Bind arg" << i << "=" << cstr << endl;
  }
#endif

  Nan::Utf8String dn(info[0]);
  Nan::Utf8String pw(info[1]);

  int res = ldap_simple_bind(ld->ld, *dn, *pw);
#if NODELDAP_DEBUG
  cerr << "LDAPCnx::Bind conId:" << ld->connectionId << " result:" << res << endl;
#endif
  info.GetReturnValue().Set(res);
}

void LDAPCnx::Close(const Nan::FunctionCallbackInfo<Value>& info) {
  LDAPCnx* ld = ObjectWrap::Unwrap<LDAPCnx>(info.Holder());
  int res = -1;
  if (ld->ld != NULL) {
    res = ldap_unbind(ld->ld);
    ld->ld = NULL;
    if (ld->handle) {
      uv_poll_stop(ld->handle);
      ld->handle = NULL;
    }
  }
#if NODELDAP_DEBUG
  cerr << "LDAPCnx::Close connId:" << ld->connectionId <<" result:" << res << endl;
#endif
  info.GetReturnValue().Set(res);
}

void LDAPCnx::Rename(const Nan::FunctionCallbackInfo<Value>& info) {
  LDAPCnx* ld = ObjectWrap::Unwrap<LDAPCnx>(info.Holder());
  Nan::Utf8String dn(info[0]);
  Nan::Utf8String newrdn(info[1]);
  int res;

  ldap_rename(ld->ld, *dn, *newrdn, NULL, 1, NULL, NULL, &res);

  info.GetReturnValue().Set(res);
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

void LDAPCnx::Search(const Nan::FunctionCallbackInfo<Value>& info) {
  LDAPCnx* ld = ObjectWrap::Unwrap<LDAPCnx>(info.Holder());
#if NODELDAP_DEBUG
  cerr << "LDAPCnx::Search connId:" << ld->connectionId << endl;
#endif

#if NODELDAP_DEBUG_ARG
  cerr << "LDAPCnx::Search connId:" << ld->connectionId << endl;
  for (int i = 0; i < info.Length(); i++) {
    v8::String::Utf8Value str(info[i]);
    const char* cstr = ToCString(str);
    cerr << "LDAPCnx::Search arg" << i << "=" << cstr << endl;
  }
#endif

  if (ld->ld == NULL) {
    info.GetReturnValue().Set(-1);
    return;
  }

  Nan::Utf8String base(info[0]);
  Nan::Utf8String filter(info[1]);
  Nan::Utf8String attrs(info[2]);
  int scope = info[3]->NumberValue();

  int rc, ctrlCount = 0, searchRequestControlType = 0;
  Local<Array> controls;
  LDAPControl** serverCtrls;
  int page_size = 0;
  int page_offset = 0;
  char * sort_str = NULL;

  Local<Object> cookieObj;
  struct berval* cookie = NULL;

  if (!(info[4]->IsUndefined())) {
    controls = Local<Array>::Cast(info[4]);
  } else {
    info.GetReturnValue().Set(-1);
    return;
  }
  if (!(info[5]->IsUndefined())) {
    // this is a paged search
    searchRequestControlType = info[5]->Int32Value();
  }
  if (!(info[6]->IsUndefined())) {
    // this is a paged search
    page_size = info[6]->Int32Value();
  }
  if (!(info[7]->IsUndefined())) {
    if (!info[7]->IsObject()) {
      info.GetReturnValue().Set(-1);
      return;
    }
    Isolate * isolate = v8::Isolate::GetCurrent();
    Handle<Object> cookieObj = Handle<Object>::Cast(info[7]);
    Handle<Value> bv_val =
                  cookieObj->Get(String::NewFromUtf8(isolate,"bv_val"));
    Handle<Value> bv_len =
                  cookieObj->Get(String::NewFromUtf8(isolate,"bv_len"));
    cookie = (struct berval *) malloc( sizeof( struct berval ) );
    cookie->bv_val = node::Buffer::Data(bv_val->ToObject());
    cookie->bv_len = bv_len->NumberValue();
  }
  if (!(info[8]->IsUndefined())) {
    // this is a vlv search
    page_offset = info[8]->Int32Value();
  }
  if (info[9]->IsString()) {
    String::Utf8Value sortString(info[9]);
    sort_str = strdup(*sortString);
  }

  int msgid = 0;
  char * attrlist[255];
  char *bufhead = strdup(*attrs);
  char *buf = bufhead;
  char **ap;
  for (ap = attrlist; (*ap = strsep(&buf, " \t,")) != NULL;)
    if (**ap != '\0')
      if (++ap >= &attrlist[255])
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
      rc = ldap_create_sort_control(ld->ld, sortKeyList, 0, &serverCtrls[ctrlCount++]);
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
      info.GetReturnValue().Set(-1);
      return;
    }
  }

  if (searchRequestControlType == DEFAULT_SRC) {

  }
  else if (searchRequestControlType == SIMPLE_PAGED_RESULTS_SRC) {
    rc = ldap_create_page_control(ld->ld, page_size, cookie, 'F', &serverCtrls[ctrlCount++]);
    if (cookie) {
      ber_bvfree(cookie);
      cookie = NULL;
    }
    if (rc != LDAP_SUCCESS) {
      ldap_controls_free(serverCtrls);
      free(bufhead);
      info.GetReturnValue().Set(-1);
      return;
    }
  }
  else if (searchRequestControlType == VIRTUAL_LIST_VIEW_SRC) {
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
      rc = ldap_create_vlv_control(ld->ld, &vlvInfo, &serverCtrls[ctrlCount++]);
      if (cookie) {
        ber_bvfree(cookie);
        cookie = NULL;
      }
      if (rc != LDAP_SUCCESS) {
        ldap_controls_free(serverCtrls);
        free(bufhead);
        info.GetReturnValue().Set(-1);
        return;
      }

    } else if (cookie) {
      ber_bvfree(cookie);
      cookie = NULL;
    }
  }

  // parse other server controls
  rc = parseServerControls(controls, serverCtrls, &ctrlCount);

  if (rc != LDAP_SUCCESS) {
    ldap_controls_free(serverCtrls);
    free(bufhead);
    info.GetReturnValue().Set(-1);
    return;
  }

  rc = ldap_search_ext(ld->ld, *base, scope, *filter , (char **)attrlist, 0,
                       serverCtrls, NULL, NULL, 0, &msgid);

  ldap_controls_free(serverCtrls);

  if (LDAP_API_ERROR(rc)) {
    msgid = -1;
  }

  free(bufhead);
  info.GetReturnValue().Set(msgid);
}

void LDAPCnx::Modify(const Nan::FunctionCallbackInfo<Value>& info) {
  LDAPCnx* ld = ObjectWrap::Unwrap<LDAPCnx>(info.Holder());
  Nan::Utf8String dn(info[0]);

  Handle<Array> mods = Handle<Array>::Cast(info[1]);
  unsigned int nummods = mods->Length();

  LDAPMod **ldapmods = (LDAPMod **) malloc(sizeof(LDAPMod *) * (nummods + 1));

  for (unsigned int i = 0; i < nummods; i++) {
    Local<Object> modHandle =
      Local<Object>::Cast(mods->Get(Nan::New(i)));

    ldapmods[i] = (LDAPMod *) malloc(sizeof(LDAPMod));

    String::Utf8Value mod_op(modHandle->Get(Nan::New("op").ToLocalChecked()));

    if (!strcmp(*mod_op, "add")) {
      ldapmods[i]->mod_op = LDAP_MOD_ADD;
    } else if (!strcmp(*mod_op, "delete")) {
      ldapmods[i]->mod_op = LDAP_MOD_DELETE;
    } else {
      ldapmods[i]->mod_op = LDAP_MOD_REPLACE;
    }

    String::Utf8Value mod_type(modHandle->Get(Nan::New("attr").ToLocalChecked()));
    ldapmods[i]->mod_type = strdup(*mod_type);

    Local<Array> modValsHandle =
      Local<Array>::Cast(modHandle->Get(Nan::New("vals").ToLocalChecked()));

    int modValsLength = modValsHandle->Length();
    ldapmods[i]->mod_values = (char **) malloc(sizeof(char *) *
                                               (modValsLength + 1));
    for (int j = 0; j < modValsLength; j++) {
      Nan::Utf8String modValue(modValsHandle->Get(Nan::New(j)));
      ldapmods[i]->mod_values[j] = strdup(*modValue);
    }
    ldapmods[i]->mod_values[modValsLength] = NULL;
  }
  ldapmods[nummods] = NULL;

  int msgid = ldap_modify(ld->ld, *dn, ldapmods);

  ldap_mods_free(ldapmods, 1);

  info.GetReturnValue().Set(msgid);
}

void LDAPCnx::Add(const Nan::FunctionCallbackInfo<Value>& info) {
  LDAPCnx* ld = ObjectWrap::Unwrap<LDAPCnx>(info.Holder());
  Nan::Utf8String dn(info[0]);
  Handle<Array> attrs = Handle<Array>::Cast(info[1]);
  unsigned int numattrs = attrs->Length();

  LDAPMod **ldapmods = (LDAPMod **) malloc(sizeof(LDAPMod *) * (numattrs + 1));
  for (unsigned int i = 0; i < numattrs; i++) {
    Local<Object> attrHandle =
      Local<Object>::Cast(attrs->Get(Nan::New(i)));

    ldapmods[i] = (LDAPMod *) malloc(sizeof(LDAPMod));

    // Step 1: mod_op
    ldapmods[i]->mod_op = LDAP_MOD_ADD;

    // Step 2: mod_type
    String::Utf8Value mod_type(attrHandle->Get(Nan::New("attr").ToLocalChecked()));
    ldapmods[i]->mod_type = strdup(*mod_type);

    // Step 3: mod_vals
    Local<Array> attrValsHandle =
      Local<Array>::Cast(attrHandle->Get(Nan::New("vals").ToLocalChecked()));
    int attrValsLength = attrValsHandle->Length();
    ldapmods[i]->mod_values = (char **) malloc(sizeof(char *) *
                                               (attrValsLength + 1));
    for (int j = 0; j < attrValsLength; j++) {
      Nan::Utf8String modValue(attrValsHandle->Get(Nan::New(j)));
      ldapmods[i]->mod_values[j] = strdup(*modValue);
    }
    ldapmods[i]->mod_values[attrValsLength] = NULL;
  }

  ldapmods[numattrs] = NULL;

  int msgid = ldap_add(ld->ld, *dn, ldapmods);

  info.GetReturnValue().Set(msgid);

  ldap_mods_free(ldapmods, 1);
}
