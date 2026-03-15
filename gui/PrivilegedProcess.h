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
#ifndef NMRPFLASH_GUI_PRIVILEGED_PROCESS_H
#define NMRPFLASH_GUI_PRIVILEGED_PROCESS_H

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
