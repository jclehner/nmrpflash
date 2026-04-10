/**
 * nmrpflash - Netgear Unbrick Utility
 * Copyright (C) 2016-2026 Joseph Lehner <joseph.c.lehner@gmail.com>
 *
 * nmrpflash is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nmrpflash is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with nmrpflash.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include "AppFrame.h"
#include "Util.h"
#include <cstdint>
#include <cstring>
#include <gsl/pointers>
#include <stdexcept>
#include <filesystem>
#include <wx/event.h>
#include <wx/log.h>
#include <wx/menu.h>
#include <wx/string.h>
#include <wx/timer.h>
#include <wx/utils.h>
#include <wx/valtext.h>
#include <wx/version.h>
#include <wx/aboutdlg.h>
#include <wx/msgdlg.h>
#include <wx/textdlg.h>
#include "../nmrpd.h"

#ifdef NMRPFLASH_MACOS
#include <mach-o/dyld.h>
#endif

#ifdef __FreeBSD__
#include <sys/sysctl.h>
#endif

using namespace std;

namespace nmrpflash {
namespace {

namespace fs = std::filesystem;

struct AdapterData : public wxClientData
{
	AdapterData(const ethsock_list_item* p)
	{
		this->native_name = p->native_name;
		this->pcap_name = p->pcap_name;
		this->device_name = p->device_name;
		this->ip4addr = p->ip4addr;
		memcpy(hwaddr, p->hwaddr, sizeof(hwaddr));
	}

	static AdapterData* Get(gsl::not_null<wxChoice*> choice)
	{
		return dynamic_cast<AdapterData*>(choice->GetClientObject(choice->GetSelection()));
	}

	string native_name;
	string pcap_name;
	string device_name;
	uint8_t hwaddr[6];
	bool wifi = false;
	string ip4addr;
};

std::string GetMyExecutableFilename()
{
#if defined(NMRPFLASH_MACOS)
	uint32_t bufsize = 0;

	_NSGetExecutablePath(nullptr, &bufsize);
	auto buf = std::make_unique<char[]>(bufsize);

	if (_NSGetExecutablePath(buf.get(), &bufsize) == 0) {
		return buf.get();
	}
#elif defined(NMRPFLASH_WINDOWS)
	char buf[MAX_PATH];

	if (GetModuleFileNameA(nullptr, buf, sizeof(buf)) > 0) {
		return buf;
	}
#elif defined(__FreeBSD__)
	char buf[1024];
	size_t bufsize = sizeof(buf);
	int name[] = { CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1 };

	if (sysctl(name, std::size(name), buf, &bufsize, nullptr, 0) == 0 && bufsize > 0) {
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
m_redirector(gsl::make_not_null(m_textLog), &std::cout),
m_subprocess(PrivilegedProcess::Create(this)),
m_timer(new wxTimer(this))
{
	Bind(wxEVT_TIMER, &AppFrame::OnTimer, this);
	Bind(wxEVT_UPDATE_UI, &AppFrame::OnUpdateUI, this);
	Bind(wxEVT_END_PROCESS, &AppFrame::OnTerminate, this);
	Bind(wxEVT_CLOSE_WINDOW, &AppFrame::OnCloseWindow, this);

	m_startStopBtn->Bind(wxEVT_BUTTON, &AppFrame::OnStartStopPressed, this);
	m_linkCopyright->Bind(wxEVT_HYPERLINK, &AppFrame::OnSubtitleClicked, this);
	m_adapterListBtn->Bind(wxEVT_BUTTON, &AppFrame::OnAdapterListBtnPressed, this);
	m_adapterList->Bind(wxEVT_CHOICE, &AppFrame::OnAdapterSelected, this);

	// clear values from mockup
	m_textCmdStatus->SetLabelText("");
#if 1

	// FIXME
	auto dummy = "0" + string(60-3, '.') + "60" + string(20-2, '.') + "80";
	m_textLog->WriteText(dummy + "\n");

	m_textLog->WriteText("self: " + GetMyExecutableFilename() + "\n");

	while (m_textLog->GetNumberOfLines() < 10) {
		m_textLog->WriteText("\n");
	}

	auto vi = wxGetLibraryVersionInfo();
	m_textLog->AppendText(vi.ToString());

	m_textLog->ScrollLines(-m_textLog->GetNumberOfLines());

#endif
	UpdateNetAdapterList(false);

	// filter out quotes, so we can split the string more easily
	wxTextValidator v(wxFILTER_ASCII | wxFILTER_EXCLUDE_CHAR_LIST);
	v.SetCharExcludes("\"'");
	m_textCmdlineAdd->SetValidator(v);

	m_verbosityChoice->SetSelection(std::min(g_verbosity, m_verbosityChoice->GetCount()-1));
	m_verbosityChoice->Bind(wxEVT_CHOICE, [](wxCommandEvent& event) {
		int n = event.GetSelection();
		if (event.IsSelection() && n >= 0) {
			if (n >= 0) {
				g_verbosity = n;
			}
		}
	});
}

AppFrame::~AppFrame()
{
	EndSubprocess();
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
	if (m_subprocess->IsExecuting()) {
		if (event.CanVeto()) {
			auto ret = wxMessageBox("nmrpflash is still running. Really quit?",
				"Question", wxICON_QUESTION|wxYES_NO);
			if (ret != wxYES) {
					event.Veto();
					return;
			}
		}

		EndSubprocess();
	}

	Destroy();
}

void AppFrame::OnAdapterListBtnPressed(wxCommandEvent&)
{
	UpdateNetAdapterList(true);
}

void AppFrame::OnAdapterSelected(wxCommandEvent&)
{
	auto adapter = AdapterData::Get(m_adapterList);
	m_adapterList->SetToolTip("MAC: "s + mac_to_str(adapter->hwaddr));
}

void AppFrame::OnStartStopPressed(wxCommandEvent&)
{
	if (!m_subprocess->IsExecuting()) {
		m_textCmdStatus->SetLabelText("");
		m_textLog->Clear();

		auto ret = ExecuteSubprocess();
		if (ret > 0) {
				UpdateSubprocessState(true);
				m_startStopBtn->SetLabelText(wxString::FromUTF8("⏹︎ Stop"));
				m_timer->Start(100);
		}
	} else {
		EndSubprocess();
		// only re-enable in OnTerminate
		m_startStopBtn->Enable(false);
	}
}

void AppFrame::OnTerminate(wxProcessEvent& event)
{
	while (ConsumeLineFromSubprocess(true));

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

	UpdateSubprocessState(false);
}

void AppFrame::OnTimer(wxTimerEvent&)
{
	ConsumeLineFromSubprocess();
}

void AppFrame::OnUpdateUI(wxUpdateUIEvent& event)
{
	if (event.GetId() != wxID_EXECUTE || m_subprocess->IsExecuting()) {
		return;
	}

	event.Enable(
		(!m_filePicker->GetPath().IsEmpty() || !m_textCustomCmd->IsEmpty())
		&& m_adapterList->IsEnabled()
		&& m_adapterList->GetSelection() != wxNOT_FOUND);
}

void AppFrame::OnSubtitleClicked(wxHyperlinkEvent& event)
{
	wxAboutDialogInfo info;
	info.SetName("nmrpflash");
	info.SetVersion(NMRPFLASH_VERSION);
	info.SetCopyright("(C) 2016-2026");
	info.SetWebSite("https://github.com/jclehner/nmrpflash");
	info.AddDeveloper("Joseph C. Lehner");
	info.SetDescription("Unbrick Utility for Netgear Routers");
	info.SetIcon(m_iconBitmap->GetIcon());

	wxAboutBox(info, this);
}

void AppFrame::WriteToSubprocess(const string& str)
{
	auto s = m_subprocess->GetStdin();
	if (s) {
		s->WriteAll(str.data(), str.length());
	}
}

bool AppFrame::ConsumeLineFromSubprocess(bool terminated)
{
	auto err = m_subprocess->GetStderr();

	auto streams = { m_subprocess->GetStdout(), err };
	bool haveValidStream = false;

	for (auto s : streams) {
		if (!s || s->Eof()) {
			continue;
		}

		haveValidStream = true;

		string buf;
		if (ReadLine(s, buf, true)) {
			wxTextAttr style = m_textLog->GetDefaultStyle();
			style.SetFontWeight(s == err ? wxFONTWEIGHT_BOLD : wxFONTWEIGHT_NORMAL);
			m_textLog->SetDefaultStyle(style);
			m_textLog->WriteText(buf);
			style.SetFontWeight(wxFONTWEIGHT_NORMAL);
			m_textLog->SetDefaultStyle(style);
			return true;
		}
	}

	if (!haveValidStream) {
		return false;
	}

	return !terminated;
}

void AppFrame::EndSubprocess()
{
	if (m_subprocess->IsExecuting()) {
		// write to the control thread of the nmrpflash subprocess. unless that
		// thread is malfunctioning, this should have the same effect as sending
		// SIGINT to the process.
		WriteToSubprocess("\x1b\n");

		// Linux/BSD: terminates `sudo` and its child process. doesn't work with `pkexec`
		// macOS: terminates `osascript` only (which should have already exited at this point)
		// Windows: actually terminates the subprocess
		wxKill(m_subprocess->GetPid());
	}
}

long AppFrame::ExecuteSubprocess()
{
	auto adapter = AdapterData::Get(m_adapterList);

	list<string> args;
	boost::algorithm::split(args, m_textCmdlineAdd->GetValue(), boost::is_any_of(" "), boost::algorithm::token_compress_on);
	args.insert(args.end(), {
		"-g", "sub",
		"-i", adapter->device_name,
	});

	auto f = [&args](const std::string& flag, const wxString& s) {
		if (!s.IsEmpty()) {
			args.push_back(flag);
			args.push_back(s.ToStdString());
		}
	};

	f("-f", m_filePicker->GetPath());
	f("-c", m_textCustomCmd->GetValue());

	string verbosityArg(m_verbosityChoice->GetSelection(), 'v');
	if (!verbosityArg.empty()) {
		args.push_back("-" + verbosityArg);
	}

	long ret = m_subprocess->Execute(GetMyExecutableFilename(), args);

	return ret;
}

void AppFrame::UpdateSubprocessState(bool running)
{
	m_filePicker->Enable(!running);
	m_adapterList->Enable(!running);
	m_adapterListBtn->Enable(!running);
	m_textCmdlineAdd->Enable(!running);
}

void AppFrame::UpdateNetAdapterList(bool userInitiated)
{
	m_adapterList->Clear();

	ethsock_for_each([](const ethsock_list_item* p, void* adapterListRaw) {
		std::string item = p->pretty_name ? p->pretty_name : p->native_name;
		if (p->ip4addr) {
			item += " - "s + p->ip4addr;
		}

		static_cast<decltype(m_adapterList)>(adapterListRaw)->Append(item, new AdapterData(p));
		return true;
	}, m_adapterList);

	if (m_adapterList->IsEmpty()) {
		m_adapterList->Append("No suitable network interfaces found!");
		m_adapterList->Disable();
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
