#ifndef NMRPFLASH_ELEVATED_ASYNC_PROCESS_H
#define NMRPFLASH_ELEVATED_ASYNC_PROCESS_H

#include <memory>
#include <string>
#include <list>
#include <wx/process.h>
#include <wx/stream.h>
#include <wx/event.h>
#include <wx/weakref.h>

namespace nmrpflash {
class PrivilegedProcess
{
public:
	typedef std::list<std::string> Args;

	virtual ~PrivilegedProcess();

	virtual long Execute(std::string cmd, Args args) = 0;

	virtual long GetPid() const = 0;
	virtual bool IsExecuting() const = 0;
	virtual bool IsRedirected() const = 0;

	virtual wxInputStream* GetStdout() const = 0;
	virtual wxInputStream* GetStderr() const = 0;
	virtual wxOutputStream* GetStdin() const = 0;

	static std::unique_ptr<PrivilegedProcess> Create(wxEvtHandler* parent=nullptr);

private:
};
}
#endif
