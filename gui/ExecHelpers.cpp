#include "ExecHelpers.h"
#include <cerrno>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <ostream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <system_error>
#include <type_traits>
#include <unistd.h>
#include <list>
#include <wx/event.h>
#include <wx/filefn.h>
#include <wx/log.h>
#include <wx/textdlg.h>
#include <wx/process.h>
#include <wx/strconv.h>
#include <wx/stream.h>
#include <wx/timer.h>
#include <wx/wfstream.h>
#include <wx/utils.h>
#include <wx/windowptr.h>
#include "Util.h"

using namespace std::literals::string_literals;

namespace nmrpflash {
namespace {
class BaseExecHelper : public ElevatedProcess::ExecHelper
{
	public:
	void AdjustCommand(std::string&, ArgVec&, std::string&) override {}
	bool OnPreExecute(ElevatedProcess&, const std::string&) override { return true; }
	void OnPostExecute(ElevatedProcess&) override {}
	bool UsesCustomRedirection() const override { return false; }
	bool TryRedirect(ElevatedProcess&) override { return false; }
};

template<class T> class NonSeekableStream : public T
{
	public:
	using T::T;

	bool IsSeekable() const override
	{ return false; }

	size_t GetSize() const override
	{ return 0; }

	wxFileOffset GetLength() const override
	{ return wxInvalidOffset; }
};

// there's a wxPipe{Input,Output}Stream in wxWidgets, but it's private
class PipeInputStream : public NonSeekableStream<wxFileInputStream>
{
	public:
	using NonSeekableStream<wxFileInputStream>::NonSeekableStream;

	PipeInputStream(const fs::path& p)
	: NonSeekableStream<wxFileInputStream>(p.string())
	{}

	bool CanRead() const override
	{
		// adapted from https://github.com/wxWidgets/wxWidgets/blob/master/src/unix/utilsunx.cpp
		if (Eof()) {
			return false;
		}

		struct timeval tv = { 0, 0 };

		int fd = GetFile()->fd();
		fd_set readfds;

		FD_ZERO(&readfds);
		FD_SET(fd, &readfds);

		int ret = select(fd + 1, &readfds, nullptr, nullptr, &tv);
		if (ret == -1) {
			throw errno_error("select");
		}

		return ret ? !Eof() : false;
	}
};

class PipeOutputStream : public NonSeekableStream<wxFileOutputStream>
{
	public:
	using NonSeekableStream<wxFileOutputStream>::NonSeekableStream;

	PipeOutputStream(const fs::path& p)
	: NonSeekableStream<wxFileOutputStream>(p.string())
	{}

protected:
	size_t OnSysWrite(const void *buffer, size_t size) override
	{
		// adapted from https://github.com/wxWidgets/wxWidgets/blob/master/src/unix/utilsunx.cpp
		ssize_t ret = write(GetFile()->fd(), buffer, size);

		if (ret == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				ret = 0;
			} else {
				throw errno_error("write");
			}
		}

		return ret;
	}

};

template<class T1, class T2> bool RedirectStream(T2& p_stream, const fs::path& p)
{
	if (p_stream) {
		if (p.empty()) {
			p_stream.reset();
		}

		// don't allow re-redirecting the stream
		return true;
	}

	int oflag = O_NONBLOCK | (std::is_base_of_v<wxInputStream, T1> ? O_RDONLY : O_WRONLY);
	int fd = open(p.c_str(), oflag);
	if (fd == -1) {
		if ((oflag & O_WRONLY) && errno == ENXIO) {
			return false;
		}

		throw errno_error("open: " + p.string());
	}

	std::cout << __func__ << ": 0x" << std::hex << oflag << " " << p << std::endl;

	p_stream.reset(new T1(fd));
	return true;
}

template<class T1, class T2> auto GetStream(T1& p_stream, const T2& p_proc, typename T1::pointer (T2::element_type::*func)() const)
{
	if (p_stream) {
		return p_stream.get();
	} else {
		return std::invoke(func, p_proc);
	}
}

std::string EscapeAndQuote(std::string s, char quote, bool quoteIfSpace, bool quoteAlways)
{
	bool doQuote = quoteAlways;
	std::string delims = "\\"s + quote + (quoteIfSpace ? " " : "");

	size_t i = 0;
	while ((i = s.find_first_of(delims, i)) != s.npos) {
		if (s[i] == ' ') {
			i += 1;
		} else {
			s.replace(i, 1, "\\"s + s[i]);
			i += 2;
		}

		doQuote = true;
	}

	if (doQuote) {
		s = quote + s + quote;
	}

	return s;
}

std::string EscapeShellArgvElement(const std::string& s)
{
	return EscapeAndQuote(s, '\'', true, false);
}

std::string EscapeAndSingleQuote(const std::string& s)
{
	return EscapeAndQuote(s, '\'', true, true);
}

std::string EscapeAndDoubleQuote(const std::string& s)
{
	return EscapeAndQuote(s, '\"', false, true);
}

#ifndef _WIN32
std::string GetPasswordFromUser()
{
	return wxGetPasswordFromUser(
		"Authentication is needed to run this program as the super user.",
		"Authentication Required"
	).ToStdString();
}

fs::path mkdtemp()
{
	auto tmp = (fs::temp_directory_path() / "nmrpflashXXXXXX").string();

	if (!::mkdtemp(tmp.data())) {
		throw errno_error("mkdtemp");
	}

	return tmp;
}

void mkfifo(const fs::path& p, mode_t mode)
{
	if (::mkfifo(p.c_str(), mode) != 0) {
		throw errno_error("mkfifo");
	}
}

void chmod(const fs::path& p, mode_t mode)
{
	if (::chmod(p.c_str(), mode) != 0) {
		throw errno_error("chmod");
	}
}

std::string ToCmdString(const std::string& cmd, const std::list<std::string>& args, const std::string& tail)
{
#ifdef _WIN32
	auto f = &EscapeAndDoubleQuote;
#else
	auto f = &EscapeShellArgvElement;
#endif

	auto s = f(cmd);

	for (auto& a : args) {
		if (!a.empty()) {
			s += " " + f(a);
		}
	}

	return s + tail;
}

class SudoExecHelper : public BaseExecHelper
{
public:
	virtual ~SudoExecHelper()
	{
		ZeroPassword();
	}

	void AdjustCommand(std::string& cmd, ArgVec& args, std::string&) override
	{
		args.push_front(cmd);
		args.push_front("--");
		args.push_front("-kS");
		cmd = "sudo";
	}

	bool OnPreExecute(ElevatedProcess&, const std::string&) override
	{
		m_password = GetPasswordFromUser();
		return !m_password.empty();
	}

	void OnPostExecute(ElevatedProcess &process) override
	{
		process.GetStdin()->WriteAll(m_password.data(), m_password.size());
		ZeroPassword();
	}

private:
	void ZeroPassword()
	{
		wxSecureZeroMemory(m_password.data(), m_password.size());
		m_password.clear();
	}

	std::string m_password;
};

class TmpDirExecHelper : public BaseExecHelper
{
public:
	TmpDirExecHelper()
	: m_tempDir(mkdtemp())
	{}

	~TmpDirExecHelper()
	{
		std::error_code ec;
		fs::remove_all(m_tempDir, ec);
	}

	fs::path GetPath(const std::string& filename) const
	{
		return m_tempDir / filename;
	}
private:
	fs::path m_tempDir;
};

class PipeExecHelper : public TmpDirExecHelper
{
public:
	PipeExecHelper()
	:
	m_stdoutPath(GetPath("stdout")),
	m_stderrPath(GetPath("stderr")),
	m_stdinPath(GetPath("stdin"))
	{}

	bool OnPreExecute(ElevatedProcess& process, const std::string& cmd) override
	{
		for (auto& p : { m_stdoutPath, m_stderrPath, m_stdinPath} ) {
			std::error_code ec;
			fs::remove(p, ec);
			mkfifo(p, 0600);
		}

		return TmpDirExecHelper::OnPreExecute(process, cmd);
	}

	void AdjustCommand(std::string& cmd, ArgVec& args, std::string& tail) override
	{
		TmpDirExecHelper::AdjustCommand(cmd, args, tail);
		tail += " >" + m_stdoutPath + " 2>" + m_stderrPath + " <" + m_stdinPath;
	}


	bool TryRedirect(ElevatedProcess& process) override
	{
		return process.Redirect(m_stdoutPath, m_stderrPath, m_stdinPath);
	}

	bool UsesCustomRedirection() const override { return true; }

private:
	std::string m_stdoutPath;
	std::string m_stderrPath;
	std::string m_stdinPath;
};

class ScriptExecHelper : public PipeExecHelper
{
	public:
	ScriptExecHelper(const std::string& cmd, const std::string& filename)
	:
	m_cmd(cmd), m_scriptPath(GetPath(filename))
	{}

	void AdjustCommand(std::string& cmd, ArgVec& args, std::string& tail) override final
	{
		PipeExecHelper::AdjustCommand(cmd, args, tail);

		std::ofstream f(m_scriptPath, std::ios::trunc);
		f << GenerateScript(cmd, args, tail);
		f.close();

		chmod(m_scriptPath, 0700);

		cmd = m_cmd;
		args = { fs::absolute(m_scriptPath) };
		tail = "";
	}

	virtual std::string GenerateScript(const std::string& cmd, const ArgVec& args, const std::string& tail) = 0;

private:
	std::string m_cmd;
	fs::path m_scriptPath;
};

class OsascriptExecHelper : public ScriptExecHelper
{
public:
	OsascriptExecHelper()
	: ScriptExecHelper("osascript", "nmrpflash.js")
	{}

	std::string GenerateScript(const std::string &cmd, const ArgVec &args, const std::string &tail) override
	{
		return
			"#!/usr/bin/osascript -l JavaScript\n"
			"\n"
			"const cmd = " + EscapeAndDoubleQuote(ToCmdString(cmd, args, tail)) + ";\n"
			"const app = Application.currentApplication();\n"
			"app.includeStandardAdditions = true;\n"
			"app.doShellScript(cmd, { administratorPrivileges: true });\n"
		;
	}
};

class PkExecHelper : public BaseExecHelper
{
public:
	void AdjustCommand(std::string& cmd, ArgVec& args, std::string&) override
	{
		args.push_front(cmd);
		cmd = "pkexec";
	}
};

class PkExecScriptHelper : public ScriptExecHelper
{
public:
	PkExecScriptHelper()
	: ScriptExecHelper("sh", "nmrpflash.sh")
	{}

	std::string GenerateScript(const std::string &cmd, const ArgVec &args, const std::string &tail) override
	{
		return 
			"#!/bin/sh\n"
			"\n"
			"pkexec sh -c " + EscapeAndDoubleQuote(ToCmdString(cmd, args, tail)) + "\n"
			"\n"
		;
	}
};
#endif
}

std::unique_ptr<ElevatedProcess::ExecHelper> ElevatedProcess::CreateHelper()
{
#ifndef _WIN32
	struct {
		std::string cmd;
		std::unique_ptr<ExecHelper> helper;
	} utils[] = {
		{ "pkexec", std::make_unique<PkExecScriptHelper>() },
		{ "osascript", std::make_unique<OsascriptExecHelper>() },
		// must be last, as it's just a fallback
		{ "sudo", std::make_unique<SudoExecHelper>() }
	};

	for (auto& u : utils) {
		if (!which(u.cmd).empty()) {
			return std::move(u.helper);
		}
	}
#endif
	// dummy helper, doing nothing
	return std::make_unique<BaseExecHelper>();
}

ElevatedProcess::ElevatedProcess(wxEvtHandler* parent)
: m_helper(CreateHelper()), m_timer(&m_handler), m_parent(parent)
{
	m_handler.Bind(wxEVT_END_PROCESS, &ElevatedProcess::OnTerminate, this);
	m_handler.Bind(wxEVT_TIMER, &ElevatedProcess::OnTimer, this);
}

bool ElevatedProcess::IsExecuting() const
{
	return m_isExecuting;
}

long ElevatedProcess::GetPid() const
{
	return m_process ? m_process->GetPid() : -1;
}

long ElevatedProcess::Execute(std::string cmd, std::list<std::string> args)
{
	if (m_isExecuting) {
		throw std::runtime_error("process is still executing");
	}

	m_stdout.reset();
	m_stderr.reset();
	m_stdin.reset();

	m_process.reset(new wxProcess(&m_handler));
	if (!m_helper->UsesCustomRedirection()) {
		m_isRedirected = true;
		m_process->Redirect();
	}

	std::string tail;
	m_helper->AdjustCommand(cmd, args, tail);
	cmd = ToCmdString(cmd, args, tail);

	if (!m_helper->OnPreExecute(*this, cmd)) {
		return -1;
	}

	// FIXME
	std::cout << "cmd: " << cmd << std::endl;

	long ret = wxExecute(cmd, wxEXEC_ASYNC | wxEXEC_MAKE_GROUP_LEADER, m_process.get());
	if (!ret) {
		throw std::runtime_error("wxExecute failed: " + std::to_string((ret)));
	}

	m_isExecuting = true;
	m_helper->OnPostExecute(*this);

	if (m_helper->UsesCustomRedirection()) {
		if (m_helper->TryRedirect(*this)) {
			m_isRedirected = true;
		} else {
			// redirection (i.e. opening the pipes) failed, probably because the actual process
			// we're trying to call hasn't started yet (for example, because pkexec / osascript
			// are still waiting for user authentication
			m_timer.Start(100);
		}
	}

	return ret;
}

void ElevatedProcess::OnTerminate(wxProcessEvent& event)
{
	std::cout << __PRETTY_FUNCTION__ << std::endl;
	m_timer.Stop();
	m_isExecuting = false;
	//event.Skip();
	if (m_parent) {
		m_parent->ProcessEvent(event);
	}
	std::cout << __PRETTY_FUNCTION__ << ": redirecting" << std::endl;
	Redirect("", "", "");
}

void ElevatedProcess::OnTimer(wxTimerEvent& event)
{
	if (!m_isRedirected) {
		m_isRedirected = m_helper->TryRedirect(*this);
		if (m_isRedirected) {
			m_timer.Stop();
		}
	}
}

wxInputStream* ElevatedProcess::GetStdout() const
{
	return GetStream(m_stdout, m_process, &wxProcess::GetInputStream);
}

wxInputStream* ElevatedProcess::GetStderr() const
{
	return GetStream(m_stderr, m_process, &wxProcess::GetErrorStream);
}

wxOutputStream* ElevatedProcess::GetStdin() const
{
	return GetStream(m_stdin, m_process, &wxProcess::GetOutputStream);
}

bool ElevatedProcess::Redirect(const fs::path& out, const fs::path& err, const fs::path& in)
{
	return RedirectStream<PipeInputStream>(m_stdout, out)
		&& RedirectStream<PipeInputStream>(m_stderr, err)
		&& RedirectStream<PipeOutputStream>(m_stdin, in);
}
}
