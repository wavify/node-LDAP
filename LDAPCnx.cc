#include "LDAPCnx.h"

static struct timeval ldap_tv = { 0, 0 };

using namespace v8;

Nan::Persistent<Function> LDAPCnx::constructor;

LDAPCnx::LDAPCnx() {
}

LDAPCnx::~LDAPCnx() {
  free(this->ldap_callback);
  delete this->callback;
  delete this->reconnect_callback;
}

void LDAPCnx::Init(Local<Object> exports) {
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

  constructor.Reset(tpl->GetFunction());
  exports->Set(Nan::New("LDAPCnx").ToLocalChecked(), tpl->GetFunction());
}

void LDAPCnx::New(const Nan::FunctionCallbackInfo<Value>& info) {
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
  Local<Value> errparam;
  
  switch(ldap_result(ld->ld, LDAP_RES_ANY, LDAP_MSG_ALL, &ldap_tv, &message)) {
  case 0:
    // timeout occurred, which I don't think happens in async mode
  case -1:
    {
      // We can't really do much; we don't have a msgid to callback to
      break;
    }
  default:
    {
      int err = ldap_result2error(ld->ld, message, 0);
      if (err) {
        errparam = Nan::Error(ldap_err2string(err));
      } else {
        errparam = Nan::Undefined();
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
  
          Local<Value> argv[] = {
            errparam,
            Nan::New(ldap_msgid(message)),
            js_result_list
          };
          ld->callback->Call(3, argv);
          break;
        }
      case LDAP_RES_BIND:
      case LDAP_RES_MODIFY:
      case LDAP_RES_MODDN:
      case LDAP_RES_ADD:
      case LDAP_RES_DELETE:
        {
          Local<Value> argv[] = {
            errparam,
            Nan::New(ldap_msgid(message))
          };
          ld->callback->Call(2, argv);
          break;
        }
      default:
        {
          
          //emit an error
          // Nan::ThrowError("Unrecognized packet");
        }
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
  lc->disconnect_callback->Call(0, NULL);
}

void LDAPCnx::Initialize(const Nan::FunctionCallbackInfo<Value>& info) {
  LDAPCnx* ld = ObjectWrap::Unwrap<LDAPCnx>(info.Holder());
  Nan::Utf8String       url(info[0]);  
  int fd              = 0;
  int ver             = LDAP_VERSION3;
  int timeout         = info[1]->NumberValue();
  int starttls        = info[2]->NumberValue();

  ld->ldap_callback = (ldap_conncb *)malloc(sizeof(ldap_conncb));
  ld->ldap_callback->lc_add = OnConnect;
  ld->ldap_callback->lc_del = OnDisconnect;
  ld->ldap_callback->lc_arg = ld;
  
  if (ldap_initialize(&(ld->ld), *url) != LDAP_SUCCESS) {
    Nan::ThrowError("Error init");
    return;
  }

  struct timeval ntimeout = { timeout/1000, (timeout%1000) * 1000 };

  ldap_set_option(ld->ld, LDAP_OPT_PROTOCOL_VERSION, &ver);
  ldap_set_option(ld->ld, LDAP_OPT_CONNECT_CB,       ld->ldap_callback);
  ldap_set_option(ld->ld, LDAP_OPT_REFERRALS,        LDAP_OPT_OFF);
  ldap_set_option(ld->ld, LDAP_OPT_NETWORK_TIMEOUT,  &ntimeout);

  if (starttls == 1) {      
      ldap_start_tls_s(ld->ld, NULL, NULL);
  }
  
  if ((ldap_simple_bind(ld->ld, NULL, NULL)) == -1) {
    Nan::ThrowError("Error anon bind");
    return;
  }

  ldap_get_option(ld->ld, LDAP_OPT_DESC, &fd);
   
  if (fd < 0) {
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
  Nan::Utf8String dn(info[0]);
  Nan::Utf8String pw(info[1]);

  info.GetReturnValue().Set(ldap_simple_bind(ld->ld, *dn, *pw));
}

void LDAPCnx::Rename(const Nan::FunctionCallbackInfo<Value>& info) {
  LDAPCnx* ld = ObjectWrap::Unwrap<LDAPCnx>(info.Holder());
  Nan::Utf8String dn(info[0]);
  Nan::Utf8String newrdn(info[1]);
  int res;

  ldap_rename(ld->ld, *dn, *newrdn, NULL, 1, NULL, NULL, &res);
    
  info.GetReturnValue().Set(res);
}

void LDAPCnx::Search(const Nan::FunctionCallbackInfo<Value>& info) {
  LDAPCnx* ld = ObjectWrap::Unwrap<LDAPCnx>(info.Holder());
  Nan::Utf8String base(info[0]);
  Nan::Utf8String filter(info[1]);
  Nan::Utf8String attrs(info[2]);
  int scope = info[3]->NumberValue();
  
  int msgid = 0;
  char * attrlist[255];

  char *bufhead = strdup(*attrs);
  char *buf = bufhead;
  char **ap;
  for (ap = attrlist; (*ap = strsep(&buf, " \t,")) != NULL;)
    if (**ap != '\0')
      if (++ap >= &attrlist[255])
        break;

  ldap_search_ext(ld->ld, *base, scope, *filter , (char **)attrlist, 0,
                         NULL, NULL, NULL, 0, &msgid);

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
