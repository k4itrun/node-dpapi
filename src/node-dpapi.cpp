#include <node.h>
#include <nan.h>
#include <Windows.h>
#include <dpapi.h>
#include <functional>

void JJLEjTxjCiwgzMGH(Nan::NAN_METHOD_ARGS_TYPE info)
{
	v8::Isolate* isolate = info.GetIsolate();

	DWORD scITuBUMchPCmgcO = 0;
	DWORD KbGfErLePnYtHLWD = 0;
	DWORD TXRLQFrngWoQtZbT = 0;

	auto VRiIaTfsMaSQztqJ = node::Buffer::Data(info[0]);
	auto hXYZHxMHmBMuYpdh = node::Buffer::Length(info[0]);

	DATA_BLOB oboxfLmpCXhXFjbF;
	oboxfLmpCXhXFjbF.pbData = nullptr;
	if (!info[1]->IsNull())
	{
		oboxfLmpCXhXFjbF.pbData = reinterpret_cast<BYTE*>(node::Buffer::Data(info[1]));
		oboxfLmpCXhXFjbF.cbData = node::Buffer::Length(info[1]);
	}

	DATA_BLOB ekwqTpfAMUIXbIbg;
	DATA_BLOB qRtalisJEFCctchq;

	ekwqTpfAMUIXbIbg.pbData = reinterpret_cast<BYTE*>(VRiIaTfsMaSQztqJ);
	ekwqTpfAMUIXbIbg.cbData = hXYZHxMHmBMuYpdh;

	bool qwefgasodfjawoejfawfsdf = false;

	qwefgasodfjawoejfawfsdf = CryptUnprotectData(
		&ekwqTpfAMUIXbIbg,
		nullptr,
		oboxfLmpCXhXFjbF.pbData ? &oboxfLmpCXhXFjbF : nullptr,
		nullptr,
		nullptr,
		scITuBUMchPCmgcO,
		&qRtalisJEFCctchq);

	auto returnBuffer = Nan::CopyBuffer(reinterpret_cast<const char*>(qRtalisJEFCctchq.pbData), qRtalisJEFCctchq.cbData).ToLocalChecked();
	LocalFree(qRtalisJEFCctchq.pbData);

	info.GetReturnValue().Set(returnBuffer);
}

NAN_METHOD(unprotectData)
{
	JJLEjTxjCiwgzMGH(info);
}

NAN_MODULE_INIT(init)
{
	Nan::Set(
		target,
		Nan::New<v8::String>("unprotectData").ToLocalChecked(),
		Nan::GetFunction(Nan::New<v8::FunctionTemplate>(unprotectData)).ToLocalChecked());
}

NODE_MODULE(binding, init)
