#include "Communication.h"

#include "../../Alerts/Alerts.h"
#include "../../Logging/Logging.h"
#include "../../Protections/Protections.h"
#include "../../Protections/Quarantine.h"
#include "MiniAvFilterMessages.h"

#include <Windows.h>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstring>
#include <cwchar>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>

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

static void SetDenyReply(MINIAV_CREATE_DECISION_REPLY* outReply)
{
	outReply->Verdict = MiniAvVerdictDeny;
	outReply->NtStatusIfDeny = static_cast<LONG>(0xC0000022L);
}

static std::string PathToUtf8(const std::wstring& Path)
{
	if (Path.empty()) {
		return std::string("(unknown)");
	}
	const int needed = WideCharToMultiByte(CP_UTF8, 0, Path.c_str(), -1, nullptr, 0, nullptr, nullptr);
	if (needed <= 1) {
		return std::string("(unknown)");
	}
	std::string out(static_cast<size_t>(needed - 1), '\0');
	WideCharToMultiByte(CP_UTF8, 0, Path.c_str(), -1, out.data(), needed, nullptr, nullptr);
	return out;
}

static void EvaluateCreatePolicy(const MINIAV_CREATE_DECISION_REQUEST* req, MINIAV_CREATE_DECISION_REPLY* outReply)
{
	outReply->Magic = MINIAV_MSG_MAGIC;
	outReply->Version = MINIAV_PROTOCOL_VERSION;
	outReply->Verdict = MiniAvVerdictAllow;
	outReply->NtStatusIfDeny = 0;

	if (!req) {
		return;
	}

	const Protections::ExecutionScanResult result = Protections::EvaluateExecutionCreate(*req);

	const wchar_t* const reqPath = (req->Path[0] != L'\0') ? req->Path : L"(empty)";
	const std::string reason = result.Reason.empty() ? std::string("(no reason)") : result.Reason;

	// Every action taken (block / deny / dangerous / suspicious) is reported every
	// time it happens — no per-path de-dup — so the user always sees what occurred.
	switch (result.Verdict) {
	case Protections::ScanVerdict::Block: {
		if (result.ApplyQuarantine && !result.ResolvedPath.empty()) {
			std::wstring quarantinePath;
			if (!Quarantine::MoveToQuarantine(result.ResolvedPath, quarantinePath)) {
				LOG_ERROR(
					"Mini-AV filter: quarantine failed for %ls (%s)",
					result.ResolvedPath.c_str(),
					result.Reason.c_str());
			}
		}
		SetDenyReply(outReply);
		LOG_WARNING(
			"Mini-AV filter: DENY (block) score=%d pid=%lu subtype=%lu path=%ls reason=%s",
			result.Score,
			req->ProcessId,
			req->OperationSubtype,
			reqPath,
			reason.c_str());
		Alerts::Add(
			"Execution blocked: " + PathToUtf8(result.ResolvedPath) + "\n" + reason,
			AlertRisk::high,
			"",
			result.Category.empty() ? "Malicious file" : result.Category);
		break;
	}
	case Protections::ScanVerdict::Error: {
		SetDenyReply(outReply);
		LOG_ERROR(
			"Mini-AV filter: DENY (fail-closed) pid=%lu subtype=%lu path=%ls reason=%s",
			req->ProcessId,
			req->OperationSubtype,
			reqPath,
			reason.c_str());
		Alerts::Add(
			"Access denied (scan error): " + PathToUtf8(result.ResolvedPath) + "\n" + reason,
			AlertRisk::medium,
			"",
			result.Category.empty() ? "Scan error" : result.Category);
		break;
	}
	case Protections::ScanVerdict::Allow:
	default:
		// Allowed but flagged by the heuristic score. Surfaced without blocking so
		// the user sees what was let through and why. Two severities:
		//   dangerous (50-59) -> Warning toast ("could be a dangerous program")
		//   suspicious (30-49) -> low-key Notice toast
		if (result.Dangerous) {
			LOG_WARNING(
				"Mini-AV filter: ALLOW (dangerous score=%d) pid=%lu path=%ls reason=%s",
				result.Score,
				req->ProcessId,
				reqPath,
				reason.c_str());
			Alerts::Add(
				"Potentially dangerous (allowed): " + PathToUtf8(result.ResolvedPath) + "\n" + reason,
				AlertRisk::medium,
				"",
				result.Category.empty() ? "Potentially dangerous" : result.Category);
		} else if (result.Suspicious) {
			LOG_INFO(
				"Mini-AV filter: ALLOW (suspicious score=%d) pid=%lu path=%ls reason=%s",
				result.Score,
				req->ProcessId,
				reqPath,
				reason.c_str());
			Alerts::Add(
				"Suspicious (allowed): " + PathToUtf8(result.ResolvedPath) + "\n" + reason,
				AlertRisk::low,
				"",
				result.Category.empty() ? "Suspicious file" : result.Category);
		}
		break;
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

		if (!validCreate) {
			static DWORD s_lastBadMessageLogMs = 0;
			const DWORD nowMs = GetTickCount();
			if ((nowMs - s_lastBadMessageLogMs) > 5000u) {
				s_lastBadMessageLogMs = nowMs;
				LOG_WARNING(
					"Mini-AV filter: ignored non-create message magic=0x%08lX ver=%lu type=%lu",
					req->Magic,
					req->Version,
					req->MessageType);
			}
			continue;
		}

		if (kernelExpectedReply < ourStructBytes) {
			LOG_ERROR(
				"Mini-AV filter: reply length %lu too small (need %lu)",
				kernelExpectedReply,
				ourStructBytes);
			continue;
		}

		EvaluateCreatePolicy(req, pBody);

		const HRESULT replyHr = FilterReplyMessage(g_hPort, prh, sendBytes);

		if (FAILED(replyHr)) {
			LOG_ERROR(
				"Mini-AV filter: FilterReplyMessage failed hr=0x%08lX len=%lu send=%lu",
				static_cast<unsigned long>(replyHr),
				kernelExpectedReply,
				sendBytes);
		}
	}
}

}

bool Communication::Connect()
{
	if (g_hPort != INVALID_HANDLE_VALUE) {
		return true;
	}

	Protections::Initialize();

	MINIAV_CONNECT_CONTEXT connectCtx{};
	connectCtx.Magic = MINIAV_MSG_MAGIC;
	connectCtx.Version = MINIAV_PROTOCOL_VERSION;
	connectCtx.ClientProcessId = GetCurrentProcessId();

	HRESULT hr = FilterConnectCommunicationPort(
		MINIAV_PORT_NAME,
		0,
		&connectCtx,
		static_cast<WORD>(sizeof(connectCtx)),
		nullptr,
		&g_hPort);

	if (FAILED(hr)) {
		Protections::Shutdown();
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

	Protections::Shutdown();

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
