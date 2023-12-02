#include <node.h>
#include <nan.h>
#include <Windows.h>
#include <dpapi.h>

v8::Local<v8::String> CreateUtf8String(const char* strData)
{
    return Nan::New<v8::String>(strData).ToLocalChecked();
}

void ProtectDataCommon(bool protect, Nan::NAN_METHOD_ARGS_TYPE info)
{
    Nan::HandleScope scope;

    v8::Isolate* isolate = info.GetIsolate();

    if (info.Length() != 3)
    {
        Nan::ThrowError("3 arguments are required");
        return;
    }

    if (!info[0]->IsUint8Array())
    {
        Nan::ThrowTypeError("First argument, data, must be a valid Uint8Array");
        return;
    }

    if (!info[1]->IsNull() && !info[1]->IsUint8Array())
    {
        Nan::ThrowTypeError("Second argument, optionalEntropy, must be null or an ArrayBuffer");
        return;
    }

    if (!info[2]->IsString())
    {
        Nan::ThrowTypeError("Third argument, scope, must be a string");
        return;
    }

    DWORD flags = 0;
    if (!info[2]->IsNullOrUndefined())
    {
        Nan::Utf8String scopeStr(info[2]);
        std::string scope(*scopeStr);
        if (stricmp(scope.c_str(), "LocalMachine") == 0)
        {
            flags = CRYPTPROTECT_LOCAL_MACHINE;
        }
    }

    auto buffer = node::Buffer::Data(info[0]);
    auto len = node::Buffer::Length(info[0]);

    DATA_BLOB entropyBlob;
    entropyBlob.pbData = nullptr;
    if (!info[1]->IsNull())
    {
        entropyBlob.pbData = reinterpret_cast<BYTE*>(node::Buffer::Data(info[1]));
        entropyBlob.cbData = node::Buffer::Length(info[1]);
    }

    DATA_BLOB dataIn;
    DATA_BLOB dataOut;

    dataIn.pbData = reinterpret_cast<BYTE*>(buffer);
    dataIn.cbData = len;

    bool success = false;

    if (protect)
    {
        success = CryptProtectData(
            &dataIn,
            nullptr, 
            entropyBlob.pbData ? &entropyBlob : nullptr,
            nullptr,
            nullptr,
            flags, 
            &dataOut);
    }
    else
    {
        success = CryptUnprotectData(
            &dataIn,
            nullptr, 
            entropyBlob.pbData ? &entropyBlob : nullptr,
            nullptr, 
            nullptr, 
            flags, 
            &dataOut);
    }

    if (!success)
    {
        DWORD errorCode = GetLastError();
        Nan::ThrowError("Decryption failed. TODO: Error code");
        return;
    }

    auto returnBuffer = Nan::CopyBuffer(reinterpret_cast<char*>(dataOut.pbData), dataOut.cbData).ToLocalChecked();
    LocalFree(dataOut.pbData);

    info.GetReturnValue().Set(returnBuffer);
}

NAN_METHOD(protectData)
{
    ProtectDataCommon(true, info);
}

NAN_METHOD(unprotectData)
{
    ProtectDataCommon(false, info);
}

NAN_MODULE_INIT(init)
{
    Nan::SetMethod(target, "protectData", protectData);
    Nan::SetMethod(target, "unprotectData", unprotectData);
}

#if NODE_MAJOR_VERSION >= 10
NAN_MODULE_WORKER_ENABLED(binding, init)
#else
NODE_MODULE(binding, init)
#endif
