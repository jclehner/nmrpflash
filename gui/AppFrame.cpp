#include "AppFrame.h"
#include "Util.h"
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <system_error>
#include <pcap/pcap.h>
#include <wx/event.h>
#include <wx/log.h>
#include <wx/menu.h>
#include <wx/string.h>
#include <wx/timer.h>
#include <wx/utils.h>
#include <wx/version.h>
#include <wx/aboutdlg.h>
#include <wx/msgdlg.h>
#include <wx/textdlg.h>
#include <wx/cmdline.h>
#include <wx/windowptr.h>

#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

#ifndef _WIN32
#  include <pcap.h>
#else
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <iphlpapi.h>
#endif
using namespace std;

namespace nmrpflash {
namespace {
struct AdapterData : public wxClientData
{
#ifdef _WIN32
	AdapterData(const MIB_IF_ROW2& row)
	{
		this->name = "eth" + to_string(row.InterfaceIndex);
		memcpy(hwaddr, row.PhysicalAddress, min(row.PhysicalAddressLength, ULONG(sizeof(hwaddr))));
		this->wifi = row.Type == IF_TYPE_IEEE80211;
	}
#else
	AdapterData(const pcap_if_t* p)
	{
		this->name = p->name;
		this->wifi = p->flags & PCAP_IF_WIRELESS;
	}
#endif

	string name;
	string description;
	uint8_t hwaddr[6];
	bool wifi = false;
};

fs::path GetMyExecutableFilename()
{
#ifndef _WIN32
	fs::path paths[] = {
		"/proc/self/exe",
		"/proc/self/exefile",
		"/proc/self/path/a.out",
		"/proc/curproc/exe",
		"/proc/curproc/file",
	};

	for (auto& p : paths) {
		try {
			if (fs::exists(p) && fs::is_symlink(p)) {
				p = fs::read_symlink(p);
				if (fs::exists(p)) {
					return p;
				}
			}
		} catch(const fs::filesystem_error&e ) {
			wxLogWarning("%s", e.what());
		}
	}
#endif

#ifdef __APPLE__
	uint32_t bufsize = 0;

	_NSGetExecutablePath(nullptr, &bufsize);
	auto buf = std::make_unique<char>(bufsize);

	if (_NSGetExecutablePath(buf.get(), &bufsize) == 0) {
		return buf.get();
	}
#endif

#ifdef _WIN32
	char buf[MAX_PATH];

	if (GetModuleFileName(nullptr, buf, sizeof(buf)) > 0) {
		return buf;
	}
#endif

	throw std::runtime_error("couldn't get executable file name");
}
}

AppFrame::AppFrame()
:
m_process(PrivilegedProcess::Create(this)),
m_timer(new wxTimer(this))
{
	Bind(wxEVT_TIMER, &AppFrame::OnTimer, this);
	Bind(wxEVT_UPDATE_UI, &AppFrame::OnUpdateUI, this);
	Bind(wxEVT_END_PROCESS, &AppFrame::OnTerminate, this);
	Bind(wxEVT_CLOSE_WINDOW, &AppFrame::OnCloseWindow, this);

	m_startStopBtn->Bind(wxEVT_BUTTON, &AppFrame::OnStartStopPressed, this);
	m_adapterListBtn->Bind(wxEVT_BUTTON, &AppFrame::OnAdapterListBtnPressed, this);
	m_linkCopyright->Bind(wxEVT_HYPERLINK, &AppFrame::OnSubtitleClicked, this);

#if 1
	// clear values from mockup
	m_textCmdStatus->SetLabelText("");

	// FIXME
	auto dummy = "0" + string(60-3, '.') + "60" + string(20-2, '.') + "80";
	m_textLog->WriteText(dummy + "\n");

	m_textLog->WriteText("self: " + GetMyExecutableFilename().string() + "\n");

	while (m_textLog->GetNumberOfLines() < 10) {
		m_textLog->WriteText("\n");
	}

	auto vi = wxGetLibraryVersionInfo();
	m_textLog->AppendText(vi.ToString());

	UpdateNetAdapterList(false);
#endif
}

AppFrame::~AppFrame()
{
	EndProcess();
}

void AppFrame::SetFirmwareFilename(const std::string& filename)
{
	if (!filename.empty()) {
		m_filePicker->SetPath(wxFileName(filename).GetAbsolutePath());
	} else {
		m_filePicker->SetPath("");
	}
}

void AppFrame::OnCloseWindow(wxCloseEvent& event)
{
	if (m_process->IsExecuting()) {
		if (event.CanVeto()) {
			auto ret = wxMessageBox("nmrpflash is still running. Really quit?",
				"Question", wxICON_QUESTION|wxYES_NO);
			if (ret != wxYES) {
					event.Veto();
					return;
			}
		}

		EndProcess();
	}

	Destroy();
}

void AppFrame::OnAdapterListBtnPressed(wxCommandEvent&)
{
	UpdateNetAdapterList(true);
}

void AppFrame::OnStartStopPressed(wxCommandEvent&)
{
	if (!m_process->IsExecuting()) {
		m_textCmdStatus->SetLabelText("");
		m_textLog->Clear();

		auto ret = ExecuteProcess();
		if (ret > 0) {
				UpdateProcessState(true);
				m_startStopBtn->SetLabelText(wxString::FromUTF8("⏹︎ Stop"));
				m_timer->Start(100);
		}
	} else {
		EndProcess();
		// only re-enable in OnTerminate
		m_startStopBtn->Enable(false);
	}
}

void AppFrame::OnTerminate(wxProcessEvent& event)
{
	while (ReadProcessOutputLine());

	string text;
	string color;

	if (event.GetExitCode() == 0) {
		text = "Command finished successfully.";
		color = "#2EC27E";
	} else {
		text = "Command failed: status " + to_string(event.GetExitCode());
		color = "#F66151";
	}

	m_textCmdStatus->SetLabelText(text);
	m_textCmdStatus->SetForegroundColour(wxColour(color));

	m_startStopBtn->SetLabel(wxString::FromUTF8("⏵︎ Start "));
	m_startStopBtn->Enable();

	UpdateProcessState(false);
}

void AppFrame::OnTimer(wxTimerEvent&)
{
	ReadProcessOutputLine();
}

void AppFrame::OnIdle(wxIdleEvent& event)
{
	if (ReadProcessOutputLine()) {
		event.RequestMore();
	}
}

void AppFrame::OnUpdateUI(wxUpdateUIEvent& event)
{
	if (event.GetId() != wxID_EXECUTE || m_process->IsExecuting()) {
		return;
	}

	event.Enable(m_filePicker->GetPath() != ""
		&& m_adapterList->IsEnabled()
		&& m_adapterList->GetSelection() != wxNOT_FOUND);
}

void AppFrame::OnSubtitleClicked(wxHyperlinkEvent& event)
{
	wxAboutDialogInfo info;
	info.SetName("nmrpflash");
	info.SetVersion("1.0");
	info.SetCopyright("(C) 2016-2026");
	info.SetWebSite("https://github.com/jclehner/nmrpflash");
	info.AddDeveloper("Joseph C. Lehner");
	info.SetDescription("Unbrick Utility for Netgear Routers");
	info.SetIcon(m_iconBitmap->GetIcon());

	wxAboutBox(info, this);
}

void AppFrame::WriteProcessInput(const string& str)
{
	auto s = m_process->GetStdin();
	if (s) {
		s->WriteAll(str.data(), str.length());
	}
}

bool AppFrame::ReadProcessOutputLine()
{
	wxTextAttr style = m_textLog->GetDefaultStyle();
	auto font = m_textLog->GetFont();

	auto out = m_process->GetStdout();
	auto err = m_process->GetStderr();
	decltype(out) stream;

	if (out && out->CanRead() && !out->Eof()) {
		stream = out;
		style.SetFontWeight(wxFONTWEIGHT_NORMAL);
	} else if (err && err->CanRead() && !err->Eof()) {
		stream = err;
		style.SetFontWeight(wxFONTWEIGHT_BOLD);
	} else {
		return false;
	}

	string buf;

	if (ReadLine(stream, buf, true)) {
		m_textLog->SetDefaultStyle(style);
		m_textLog->WriteText(buf);
		style.SetFontWeight(wxFONTWEIGHT_NORMAL);
		m_textLog->SetDefaultStyle(style);
		m_textLog->SetFont(font);
		return true;
	}

	return false;
}

void AppFrame::EndProcess()
{
	// write to nmrpflash's control thread
	if (m_process->IsExecuting()) {
		WriteProcessInput("i\n");
		wxKill(m_process->GetPid());
	}
}

long AppFrame::ExecuteProcess()
{
	auto adapter = dynamic_cast<AdapterData*>(m_adapterList->GetClientObject(m_adapterList->GetSelection()));
	long ret = m_process->Execute("nmrpflash", {
		m_textCmdlineAdd->GetValue().ToStdString(),
		"-i", adapter->name,
		"-f", m_filePicker->GetPath().ToStdString()
	});

	return ret;
}

void AppFrame::UpdateProcessState(bool running)
{
	m_filePicker->Enable(!running);
	m_adapterList->Enable(!running);
	m_adapterListBtn->Enable(!running);
	m_textCmdlineAdd->Enable(!running);
}

namespace {
#ifdef _WIN32
auto mac_to_str(const MIB_IF_ROW2& row)
{
	wxString ret;

	for (ULONG i = 0; i < row.PhysicalAddressLength; ++i) {
		if (i) {
			ret += ":";
		}
		ret += wxString::Format("%02x", row.PhysicalAddress[i]);
	}

	return ret;
}
#endif
}

void AppFrame::UpdateNetAdapterList(bool userInitiated)
{
	m_adapterList->Clear();

#ifndef _WIN32
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t* dev;
	int r = pcap_findalldevs(&dev, errbuf);
	if (r != 0) {
		return;
	}

	for (; dev; dev = dev->next) {
		auto s = wxString::Format("%s", dev->name);
		m_adapterList->Append(s, new AdapterData(dev));
	}

	pcap_freealldevs(dev);
#else
	PIP_ADAPTER_ADDRESSES adapters;
	ULONG ret, flags, bufLen;
	bool found = false;

	flags = GAA_FLAG_INCLUDE_ALL_INTERFACES;
	bufLen = 0;
	ret = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, NULL, &bufLen);
	if (ret != ERROR_BUFFER_OVERFLOW) {
		fprintf(stderr, "GetAdaptersAddresses: ret=%lu\n", ret);
		return;
	}

	adapters = static_cast<PIP_ADAPTER_ADDRESSES>(malloc(bufLen));
	if (!adapters) {
		perror("malloc");
		return;
	}

	ret = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, adapters, &bufLen);
	if (ret == NO_ERROR) {
		for (auto a = adapters; a; a = a->Next) {
			if (a->IfType != IF_TYPE_ETHERNET_CSMACD && a->IfType != IF_TYPE_IEEE80211) {
				continue;
			}

			MIB_IF_ROW2 row;
			memset(&row, 0, sizeof(row));
			row.InterfaceIndex = a->IfIndex;

			if (GetIfEntry2(&row) != NO_ERROR || !row.InterfaceAndOperStatusFlags.HardwareInterface) {
				continue;
			} else if (!row.PhysicalAddressLength) {
				continue;
			}

			auto s = wxString::Format("%ls (%s)", a->FriendlyName, mac_to_str(row));
			m_adapterList->Append(s, new AdapterData(row));
		}
	}

	free(adapters);
#endif

	if (m_adapterList->IsEmpty()) {
		m_adapterList->Append("No suitable network interfaces found!");
		m_adapterList->Enable(false);
	} else {
		m_adapterList->Enable();
	}

	if (m_adapterList->GetCount() > 1) {
		// this is the default behaviour on wxGTK and wxMSW, but not wxOSX!
		m_adapterList->SetSelection(wxNOT_FOUND);
	} else {
		// if there's only one entry, select that automatically
		m_adapterList->SetSelection(0);
	}
}
}