#ifndef LDAPCNX_H
#define LDAPCNX_H

#include <nan.h>
#include <ldap.h>

class LDAPCnx : public Nan::ObjectWrap {
 public:
  static void Init(v8::Local<v8::Object> exports);
  Nan::Callback * callback;
  Nan::Callback * reconnect_callback;
  Nan::Callback * disconnect_callback;
  
 private:
  explicit LDAPCnx();
  ~LDAPCnx();

  static void New(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void Initialize(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void Event(uv_poll_t* handle, int status, int events);
  static int  OnConnect(LDAP *ld, Sockbuf *sb, LDAPURLDesc *srv, struct sockaddr *addr, struct ldap_conncb *ctx);
  static void OnDisconnect(LDAP *ld, Sockbuf *sb, struct ldap_conncb *ctx);
  static void Search(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void Delete(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void Bind(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void Close(const Nan::FunctionCallbackInfo<v8::Value>& info);  
  static void Add(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void Modify(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void Rename(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void GetErr(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void GetErrNo(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void GetFD(const Nan::FunctionCallbackInfo<v8::Value>& info);
  ldap_conncb * ldap_callback;
  uv_poll_t * handle;

  static Nan::Persistent<v8::Function> constructor;
  LDAP * ld;
  int connectionId;
};

#endif
