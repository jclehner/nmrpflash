#include "AppFrame.h"
#include "Util.h"
#include "boost/algorithm/string/classification.hpp"
#include "boost/algorithm/string/constants.hpp"
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <stdexcept>
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

#ifdef NMRPFLASH_MACOS
#include <mach-o/dyld.h>
#endif

using namespace std;

namespace nmrpflash {
namespace {
struct AdapterData : public wxClientData
{
	AdapterData(const ethsock_list_item* p)
	{
		this->native_name = p->native_name;
		this->pcap_name = p->pcap_name;
		memcpy(hwaddr, p->hwaddr, sizeof(hwaddr));
	}

	string native_name;
	string pcap_name;
	uint8_t hwaddr[6];
	bool wifi = false;
};

fs::path GetMyExecutableFilename()
{
#if defined(NMRPFLASH_MACOS)
	uint32_t bufsize = 0;

	_NSGetExecutablePath(nullptr, &bufsize);
	auto buf = std::make_unique<char>(bufsize);

	if (_NSGetExecutablePath(buf.get(), &bufsize) == 0) {
		return buf.get();
	}
#elif defined(NMRPFLASH_WINDOWS)
	char buf[MAX_PATH];

	if (GetModuleFileNameA(nullptr, buf, sizeof(buf)) > 0) {
		return buf;
	}
#else
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

	// FIXME this prevents using -c <command> at the moment!
	auto v = wxTextValidator(wxFILTER_INCLUDE_LIST | wxFILTER_ALPHANUMERIC);
	v.AddCharIncludes("-_ ");
	m_textCmdlineAdd->SetValidator(v);
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

	list<string> args;
	boost::algorithm::split(args, m_textCmdlineAdd->GetValue(), boost::is_any_of(" "), boost::algorithm::token_compress_on);
	args.insert(args.end(), {
		"-g", "sub",
		"-i", adapter->native_name,
		"-f", m_filePicker->GetPath().ToStdString()
	});

	long ret = m_process->Execute(GetMyExecutableFilename().string(), args);

	return ret;
}

void AppFrame::UpdateProcessState(bool running)
{
	m_filePicker->Enable(!running);
	m_adapterList->Enable(!running);
	m_adapterListBtn->Enable(!running);
	m_textCmdlineAdd->Enable(!running);
}

void AppFrame::UpdateNetAdapterList(bool userInitiated)
{
	m_adapterList->Clear();

	ethsock_list_all([](const ethsock_list_item* p, void* adapterListRaw) -> bool {
		auto name = p->pretty_name ?: p->native_name;
		auto choice = static_cast<decltype(m_adapterList)>(adapterListRaw);
		choice->Append(name, new AdapterData(p));
		return true;
	}, m_adapterList);

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