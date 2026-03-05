#include "PrivilegedProcess.h"
#include "Util.h"
#include <filesystem>
#include <memory>
#include <fstream>
#include <stdexcept>
#include <unistd.h>
#include <wx/event.h>
#include <wx/process.h>
#include <wx/stream.h>
#include <wx/utils.h>
#include <wx/timer.h>
#include <wx/textdlg.h>
#include <wx/wfstream.h>

#ifndef _WIN32
#include <boost/algorithm/string/join.hpp>
#endif

using namespace std::literals::string_literals;

namespace nmrpflash {
namespace {

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

fs::path which(const std::string& cmd)
{
	wxPathList pl;
	pl.AddEnvList("PATH");

	auto ret = pl.FindAbsoluteValidPath(cmd).ToStdString();
	return ret;
}

fs::path cmd_to_absolute_path(const std::string& cmd)
{
	auto p = fs::path(cmd);
	if (p.is_absolute()) {
		return p;
	}

	return which(cmd);
}

#ifndef _WIN32
fs::path mkdtemp()
{
	auto tmp = (fs::temp_directory_path() / "nmrpflashXXXXXX").string();

	if (!::mkdtemp(tmp.data())) {
		throw errno_error("mkdtemp");
	}

	return tmp;
}

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
#endif

class ProcessBase : public PrivilegedProcess
{
public:
	ProcessBase()
	: m_timer(&m_handler)
	{
		m_handler.Bind(wxEVT_END_PROCESS, &ProcessBase::OnTerminate, this);
		m_handler.Bind(wxEVT_TIMER, &ProcessBase::OnTimer, this);
	}

	void SetParent(wxEvtHandler* parent)
	{
		m_parent = parent;
	}

	long GetPid() const override final
	{
		return m_wxprocess ? m_wxprocess->GetPid() : -1;
	}

	bool IsExecuting() const override final
	{
		return m_isExecuting;
	}

	bool IsRedirected() const override final
	{
		return m_isRedirected;
	}

	wxOutputStream* GetStdin() const override
	{
		return m_wxprocess ? m_wxprocess->GetOutputStream() : nullptr;
	}

	wxInputStream* GetStdout() const override
	{
		return m_wxprocess ? m_wxprocess->GetInputStream() : nullptr;
	}

	wxInputStream* GetStderr() const override
	{
		return m_wxprocess ? m_wxprocess->GetErrorStream() : nullptr;
	}

	long Execute(std::string cmd, Args args) override final
	{
		if (IsExecuting()) {
			throw std::runtime_error("process is still executing");
		}

		OnInit();

		m_wxprocess.reset(new wxProcess(&m_handler));
		if (!UsesCustomRedirection()) {
			m_wxprocess->Redirect();
			m_isRedirected = true;
		} else {
			m_isRedirected = false;
		}

		std::string redirection;

		cmd = cmd_to_absolute_path(cmd).string();
		AdjustCommand(cmd, args, redirection);

		auto cmdstr = ToCmdString(cmd, args, redirection);
		long ret = wxExecute(cmdstr, wxEXEC_ASYNC | wxEXEC_MAKE_GROUP_LEADER, m_wxprocess.get());
		if (!ret) {
			return ret;
		}

		m_isExecuting = true;
		OnPostExecute();

		if (UsesCustomRedirection()) {
			m_isRedirected = RedirectStreams();
			if (!m_isRedirected) {
				// redirection (i.e. opening the stdin pipe) failed, probably because the actual process
				// we're trying to call hasn't started yet (for example, because pkexec / osascript
				// are still waiting for user authentication
				m_timer.Start(100);
			} else {
				OnRedirect();
			}
		}

		return ret;
	}

protected:
	virtual void OnInit() {}
	virtual void AdjustCommand(std::string& cmd, Args& args, std::string& redirection) {}

	virtual void OnPostExecute() {}
	virtual void OnRedirect() {}
	virtual void OnTerminate() {}

	virtual bool UsesCustomRedirection() const { return false; }
	virtual bool RedirectStreams() { return false; }

	static std::string ToCmdString(const std::string& cmd, const Args& args, const std::string& redirection)
	{
#ifdef _WIN32
		auto f = &EscapeAndDoubleQuote;
#else
		auto f = &EscapeAndSingleQuote;
#endif
		auto s = EscapeShellArgvElement(cmd);

		for (auto& a : args) {
			if (!a.empty()) {
				s += " " + f(a);
			}
		}

		return s + redirection;
	}

private:
	void OnTimer(wxTimerEvent&)
	{
		if (!m_isRedirected) {
			m_isRedirected = RedirectStreams();
			if (m_isRedirected) {
				m_timer.Stop();
				OnRedirect();
			}
		}
	}

	void OnTerminate(wxProcessEvent& event)
	{
		m_timer.Stop();
		if (m_parent) {
			m_parent->ProcessEvent(event);
		}
		m_isRedirected = false;
		m_isExecuting = false;
		m_wxprocess.reset();
		OnTerminate();
	}

private:
	wxTimer m_timer;
	wxEvtHandler m_handler;

	wxWeakRef<wxEvtHandler> m_parent;
	std::unique_ptr<wxProcess> m_wxprocess;

	bool m_isExecuting = false;
	bool m_isRedirected = false;
};

#ifndef _WIN32
class ProcessWithPkExec : public ProcessBase
{
protected:
	void AdjustCommand(std::string& cmd, Args& args, std::string& redirection) override
	{
		args.push_front(cmd);
		cmd = which("pkexec");
	}
};

class ProcessWithSudo : public ProcessBase
{
public:
	void AdjustCommand(std::string& cmd, Args& args, std::string&) override
	{
		args.insert(args.begin(), { "-kS", "--", cmd });
		cmd = which("sudo");
	}

	void OnPostExecute() override
	{
		auto pw = wxGetPasswordFromUser(
			"Authentication is needed to run this program as the super user.",
			"Authentication Required"
		).ToStdString();

		auto s = GetStdin();
		if (s) {
			// three newlines to skip sudo prompts in case of a bad password
			pw += "\n\n\n";
			s->WriteAll(pw.data(), pw.size());
		}

		wxSecureZeroMemory(pw.data(), pw.size());
	}
};

class ProcessWithNamedPipeRedirection : public ProcessBase
{
public:
	~ProcessWithNamedPipeRedirection()
	{
		Cleanup();
	}

	wxOutputStream* GetStdin() const override
	{
		return m_stdin ? m_stdin.get() : ProcessBase::GetStdin();
	}

	wxInputStream* GetStdout() const override
	{
		return m_stdout ? m_stdout.get() : ProcessBase::GetStdout();
	}

	wxInputStream* GetStderr() const override
	{
		return m_stderr ? m_stderr.get() : ProcessBase::GetStderr();
	}

protected:
	void OnInit() override
	{
		m_tmpDir = mkdtemp();

		m_pipePath[STDIN_FILENO] = m_tmpDir / "stdin";
		m_pipePath[STDOUT_FILENO] = m_tmpDir / "stdout";
		m_pipePath[STDERR_FILENO] = m_tmpDir / "stderr";

		for (auto& p : m_pipePath) {
			int err = mkfifo(p.c_str(), 0600);
			if (err) {
				throw errno_error("mkfifo: " + p.string());
			}
		}
	}

	void AdjustCommand(std::string& cmd, Args& args, std::string& redirection) override
	{
		redirection =
			" <" + m_pipePath[STDIN_FILENO].string() +
			" >" + m_pipePath[STDOUT_FILENO].string() +
			" 2>" + m_pipePath[STDERR_FILENO].string();
	}

	bool UsesCustomRedirection() const override
	{
		return true;
	}

	bool RedirectStreams() override
	{
		// redirect stdin last, because the process won't be started until we've opened stdin
		// for reading. that way, no data from stdout/stderr is lost
		return RedirectStream<PipeInputStream>(m_stdout, m_pipePath[STDOUT_FILENO])
			&& RedirectStream<PipeInputStream>(m_stderr, m_pipePath[STDERR_FILENO])
			&& RedirectStream<PipeOutputStream>(m_stdin, m_pipePath[STDIN_FILENO]);
	}

	void OnTerminate() override
	{
		Cleanup();
		m_stdin.reset();
		m_stdout.reset();
		m_stderr.reset();
	}

	void Cleanup()
	{
		try {
			fs::remove_all(m_tmpDir);
		} catch (...) {

		}
	}

	fs::path GetPath(const std::string& filename) const
	{
		return fs::absolute(m_tmpDir / filename);
	}

private:
	template<class T1, class T2> static bool RedirectStream(std::unique_ptr<T2>& stream, const fs::path& p)
	{
		if (stream) {
			if (p.empty()) {
				stream.reset();
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

		stream.reset(new T1(fd));
		return true;
	}

protected:
	fs::path m_tmpDir;
	fs::path m_pipePath[3];
	std::unique_ptr<wxOutputStream> m_stdin;
	std::unique_ptr<wxInputStream> m_stdout;
	std::unique_ptr<wxInputStream> m_stderr;
};

class ProcessWithHelperScript : public ProcessWithNamedPipeRedirection
{
public:
	ProcessWithHelperScript(
		const std::string& interpreter,
		const Args& interpreterArgs={})
	:
	m_interpreter(which(interpreter)),
	m_interpreterArgs(interpreterArgs)
	{}

protected:
	virtual std::string GenerateScript(const std::string& cmd, const Args& args, const std::string& redirection) const = 0;

	std::string GenerateShebang() const
	{
		using boost::algorithm::join;
		return "#!" + m_interpreter + " " + join(m_interpreterArgs, " ");
	}

	fs::path GetScriptPath() const
	{
		return GetPath(m_scriptName);
	}

	void AdjustCommand(std::string& cmd, Args& args, std::string& redirection) override
	{
		if (fs::exists(cmd)) {
			m_scriptName = fs::path(cmd).filename();
		} else {
			m_scriptName = cmd;
		}

		ProcessWithNamedPipeRedirection::AdjustCommand(cmd, args, redirection);
		WriteScript(GenerateScript(cmd, args, redirection));

		cmd = m_interpreter;
		args = m_interpreterArgs;
		args.push_back(GetScriptPath());
		redirection = "";
	}

	virtual void WriteScript(const std::string& code)
	{
		std::ofstream f(GetScriptPath(), std::ios::trunc);
		f << code;
	}

private:
	std::string m_interpreter;
	Args m_interpreterArgs;

	std::string m_scriptName;
};

class ProcessWithOsascript : public ProcessWithHelperScript
{
public:
	ProcessWithOsascript()
	: ProcessWithHelperScript("osascript", { "-l", "JavaScript" })
	{}

protected:
	std::string GenerateScript(const std::string& cmd, const Args& args, const std::string& redirection) const override
	{
		return GenerateShebang() +
			"\n"
			"const cmd = " + EscapeAndDoubleQuote(ToCmdString(cmd, args, redirection)) + ";\n"
			"const app = Application.currentApplication();\n"
			"app.includeStandardAdditions = true;\n"
			"app.doShellScript(cmd, { administratorPrivileges: true });\n"
		;
	}

	void WriteScript(const std::string& code) override
	{
		ProcessWithHelperScript::WriteScript(code);
		// if the script file is executable, the authentication prompt will show
		// "<script name> wants to make changes", instead of "osascript wants to
		// make changes" (on macOS 15 at least)
		chmod(GetScriptPath().c_str(), 0700);
	}
};
#endif
}

PrivilegedProcess::~PrivilegedProcess() {}

std::unique_ptr<PrivilegedProcess> PrivilegedProcess::Create(wxEvtHandler* parent)
{
	std::unique_ptr<ProcessBase> ret;
#ifndef _WIN32
	if (!which("pkexec").empty()) {
		ret.reset(new ProcessWithPkExec);
	} else if (!which("osascript").empty()) {
		ret.reset(new ProcessWithOsascript());
	} else if (!which("sudo").empty()) {
		ret.reset(new ProcessWithSudo);
	}
#else
	ret.reset(new ProcessBase());
#endif

	if (ret) {
		ret->SetParent(parent);
	}

	return ret;
}
}
