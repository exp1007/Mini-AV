#include "Communication.h"

#include "../../Logging/Logging.h"
#include "MiniAvFilterMessages.h"

#include <Windows.h>
#include <atomic>
#include <cstddef>
#include <cstring>
#include <cwchar>
#include <thread>

#include <fltuser.h>

#pragma comment(lib, "fltLib.lib")

namespace {

HANDLE g_hPort = INVALID_HANDLE_VALUE;
std::atomic<bool> g_workerStop{ false };
std::thread g_worker;

typedef struct _MiniAvFilterGetMessageBuffer {
	FILTER_MESSAGE_HEADER Header;
	MINIAV_CREATE_DECISION_REQUEST Request;
} MiniAvFilterGetMessageBuffer;

static_assert(
	offsetof(MiniAvFilterGetMessageBuffer, Request) == MINIAV_FILTER_MESSAGE_HEADER_WIRE_BYTES,
	"get-message layout");
static_assert(sizeof(FILTER_MESSAGE_HEADER) == MINIAV_FILTER_MESSAGE_HEADER_WIRE_BYTES, "FILTER_MESSAGE_HEADER size");
static_assert(sizeof(FILTER_REPLY_HEADER) == MINIAV_FILTER_REPLY_HEADER_WIRE_BYTES, "FILTER_REPLY_HEADER size");
static_assert(sizeof(MINIAV_CREATE_DECISION_REQUEST) == MINIAV_CREATE_DECISION_REQUEST_BYTES, "CREATE request size");

typedef struct _MiniAvReplyBundle {
	FILTER_REPLY_HEADER rh;
	MINIAV_CREATE_DECISION_REPLY body;
} MiniAvReplyBundle;

static_assert(offsetof(MiniAvReplyBundle, body) == MINIAV_FILTER_REPLY_HEADER_WIRE_BYTES, "reply body offset");
static_assert(sizeof(MiniAvReplyBundle) == MINIAV_FILTER_REPLY_HEADER_WIRE_BYTES + sizeof(MINIAV_CREATE_DECISION_REPLY), "reply bundle size");

static bool PathContainsInsensitive(const WCHAR* path, const WCHAR* needle)
{
	if (!path || !needle) {
		return false;
	}

	const size_t n = wcslen(needle);
	if (n == 0) {
		return false;
	}

	for (const WCHAR* p = path; *p != L'\0'; ++p) {
		if (_wcsnicmp(p, needle, n) == 0) {
			return true;
		}
	}

	return false;
}

static const WCHAR kBlockTestExe[] = L"MiniAvBlockTest.exe";

static bool PolicyShouldDenyCreate(const MINIAV_CREATE_DECISION_REQUEST* req)
{
	if (!req || req->PathLengthChars == 0 || req->Path[0] == L'\0') {
		return false;
	}

	const WCHAR* path = req->Path;
	const WCHAR* slash = wcsrchr(path, L'\\');
	const WCHAR* fname = slash ? (slash + 1) : path;
	const WCHAR* colon = wcschr(fname, L':');
	const size_t fnameLen = colon ? static_cast<size_t>(colon - fname) : wcslen(fname);
	const size_t blockLen = wcslen(kBlockTestExe);
	if (fnameLen == blockLen && _wcsnicmp(fname, kBlockTestExe, blockLen) == 0) {
		return true;
	}

	return PathContainsInsensitive(path, kBlockTestExe);
}

static void EvaluateCreatePolicy(const MINIAV_CREATE_DECISION_REQUEST* req, MINIAV_CREATE_DECISION_REPLY* outReply)
{
	outReply->Magic = MINIAV_MSG_MAGIC;
	outReply->Version = MINIAV_PROTOCOL_VERSION;
	outReply->Verdict = MiniAvVerdictAllow;
	outReply->NtStatusIfDeny = 0;

	if (PolicyShouldDenyCreate(req)) {
		outReply->Verdict = MiniAvVerdictDeny;
		outReply->NtStatusIfDeny = static_cast<LONG>(0xC0000022L);
	}
}

static void MessagePumpLoop()
{
	for (;;) {
		if (g_workerStop.load()) {
			break;
		}

		alignas(16) MiniAvFilterGetMessageBuffer msg{};

		HRESULT hr = FilterGetMessage(
			g_hPort,
			&msg.Header,
			static_cast<DWORD>(sizeof(msg)),
			nullptr);

		if (FAILED(hr)) {
			if (g_workerStop.load()) {
				break;
			}
			static DWORD s_lastGetMessageErrLogMs = 0;
			const DWORD nowMs = GetTickCount();
			if ((nowMs - s_lastGetMessageErrLogMs) > 5000u) {
				s_lastGetMessageErrLogMs = nowMs;
				LOG_ERROR("Mini-AV filter: FilterGetMessage failed hr=0x%08lX", static_cast<unsigned long>(hr));
			}
			Sleep(50);
			continue;
		}

		MINIAV_CREATE_DECISION_REQUEST* req = &msg.Request;
		FILTER_MESSAGE_HEADER* header = &msg.Header;

		constexpr ULONG kMaxReplyWire = 512u;
		const ULONG ourStructBytes = static_cast<ULONG>(sizeof(MiniAvReplyBundle));
		const ULONG kernelExpectedReply = msg.Header.ReplyLength;
		ULONG sendBytes = (kernelExpectedReply == 0) ? ourStructBytes : kernelExpectedReply;
		if (sendBytes < ourStructBytes) {
			sendBytes = ourStructBytes;
		}

		if (sendBytes > kMaxReplyWire) {
			LOG_ERROR("Mini-AV filter: reply length %lu too large (max %lu)", sendBytes, kMaxReplyWire);
			continue;
		}

		alignas(MiniAvReplyBundle) unsigned char wireBuf[kMaxReplyWire]{};
		std::memset(wireBuf, 0, sendBytes);

		auto* prh = reinterpret_cast<FILTER_REPLY_HEADER*>(wireBuf);
		prh->Status = static_cast<NTSTATUS>(0);
		prh->MessageId = header->MessageId;

		MINIAV_CREATE_DECISION_REPLY* pBody = reinterpret_cast<MINIAV_CREATE_DECISION_REPLY*>(
			wireBuf + MINIAV_FILTER_REPLY_HEADER_WIRE_BYTES);

		pBody->Magic = MINIAV_MSG_MAGIC;
		pBody->Version = MINIAV_PROTOCOL_VERSION;
		pBody->Verdict = MiniAvVerdictAllow;
		pBody->NtStatusIfDeny = 0;
		std::memset(pBody->Reserved, 0, sizeof(pBody->Reserved));

		const bool validCreate =
			(req->Magic == MINIAV_MSG_MAGIC) &&
			(req->Version == MINIAV_PROTOCOL_VERSION) &&
			(req->MessageType == MiniAvMsgCreateDecision);

		if (validCreate) {
			EvaluateCreatePolicy(req, pBody);
		} else {
			LOG_WARNING(
				"Mini-AV filter: bad create message magic=0x%08lX ver=%lu type=%lu",
				req->Magic,
				req->Version,
				req->MessageType);
		}

		const HRESULT replyHr = FilterReplyMessage(g_hPort, prh, sendBytes);

		if (FAILED(replyHr)) {
			LOG_ERROR(
				"Mini-AV filter: FilterReplyMessage failed hr=0x%08lX len=%lu send=%lu",
				static_cast<unsigned long>(replyHr),
				kernelExpectedReply,
				sendBytes);
			continue;
		}

		if (validCreate && pBody->Verdict == MiniAvVerdictDeny) {
			LOG_WARNING(
				"Mini-AV filter: DENY pid=%lu subtype=%lu access=0x%08lX path=%ls",
				req->ProcessId,
				req->OperationSubtype,
				req->DesiredAccess,
				(req->Path[0] != L'\0') ? req->Path : L"(empty)");
		}
	}
}

}

bool Communication::Connect()
{
	if (g_hPort != INVALID_HANDLE_VALUE) {
		return true;
	}

	HRESULT hr = FilterConnectCommunicationPort(MINIAV_PORT_NAME, 0, nullptr, 0, nullptr, &g_hPort);

	if (FAILED(hr)) {
		return false;
	}

	g_workerStop = false;
	g_worker = std::thread(MessagePumpLoop);

	LOG_INFO("Mini-AV filter: port connected");

	return true;
}

void Communication::Disconnect()
{
	const bool hadPort = (g_hPort != INVALID_HANDLE_VALUE);

	g_workerStop = true;

	if (g_hPort != INVALID_HANDLE_VALUE) {
		CancelIoEx(g_hPort, nullptr);
	}

	if (g_worker.joinable()) {
		g_worker.join();
	}

	if (g_hPort != INVALID_HANDLE_VALUE) {
		CloseHandle(g_hPort);
		g_hPort = INVALID_HANDLE_VALUE;
	}

	if (hadPort) {
		LOG_INFO("Mini-AV filter: port closed");
	}
}

bool Communication::Ping()
{
	if (g_hPort == INVALID_HANDLE_VALUE) {
		return false;
	}

	MINIAV_PING_REQUEST req{};
	req.Magic = MINIAV_MSG_MAGIC;
	req.Version = MINIAV_PROTOCOL_VERSION;
	req.MessageType = MiniAvMsgPing;
	req.Cookie = 0x3C6EF35Fu;

	MINIAV_PING_REPLY reply{};
	DWORD bytesReturned = 0;

	HRESULT hr = FilterSendMessage(
		g_hPort,
		&req,
		static_cast<DWORD>(sizeof(req)),
		&reply,
		static_cast<DWORD>(sizeof(reply)),
		&bytesReturned);

	if (FAILED(hr)) {
		return false;
	}

	if (bytesReturned < sizeof(reply)) {
		return false;
	}

	if (reply.Magic != MINIAV_MSG_MAGIC ||
		reply.Version != MINIAV_PROTOCOL_VERSION ||
		reply.CookieEcho != req.Cookie) {
		return false;
	}

	return reply.NtStatus == 0L;
}
