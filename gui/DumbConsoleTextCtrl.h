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
#ifndef NMRPFLASH_GUI_DUMB_CONSOLE_TEXT_CTRL
#define NMRPFLASH_GUI_DUMB_CONSOLE_TEXT_CTRL
#include <string>
#include <wx/object.h>
#include <wx/textctrl.h>

namespace nmrpflash {
class DumbConsoleTextCtrl : public wxTextCtrl
{
	wxDECLARE_DYNAMIC_CLASS(DumbConsoleTextCtrl);

public:
	DumbConsoleTextCtrl() = default;

	virtual void WriteText(const wxString& text) override;
	virtual void Clear() override;

	virtual long GetCursorPosition() const;
	virtual void SetCursorPosition(long pos, bool relative=false);
	virtual void SetCursorPositionEnd();

private:
	std::string m_currentLine;
	long m_currentLineNum = 0;
	long m_cursorPos = 0;

	void WriteTextPart(const std::string_view& text, bool commit);
	void DoWriteText(const std::string_view& text, bool commit);
	void UpdateCurrentLineInfo(bool updateCursor=true);
};
}
#endif