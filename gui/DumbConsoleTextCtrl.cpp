#include "DumbConsoleTextCtrl.h"
using namespace std;

wxIMPLEMENT_DYNAMIC_CLASS(nmrpflash::DumbConsoleTextCtrl, wxTextCtrl);

namespace nmrpflash {
long DumbConsoleTextCtrl::GetCursorPosition() const
{
	return m_cursorPos;
}

void DumbConsoleTextCtrl::SetCursorPosition(long pos, bool relative)
{
	if (relative) {
		SetCursorPosition(m_cursorPos + pos, false);
	} else {
		if (pos < 0 || pos > m_currentLine.length()) {
			pos = m_currentLine.length();
		}

		m_cursorPos = pos;
	}
}

void DumbConsoleTextCtrl::SetCursorPositionEnd()
{
	SetCursorPosition(-1, false);
}

void DumbConsoleTextCtrl::WriteText(const wxString& text)
{
	if (!text.empty()) {
		WriteTextPart(text.ToStdString(), true);
	} else {
		wxTextCtrl::WriteText("");
	}
}

void DumbConsoleTextCtrl::Clear()
{
	wxTextCtrl::Clear();
	UpdateCurrentLineInfo(true);
}

void DumbConsoleTextCtrl::WriteTextPart(const std::string_view& text, bool commit)
{
	size_t beg = 0;
	size_t pos;

	while ((pos = text.find_first_of("\r\n\b", beg)) != string::npos) {
		// XXX add inner loop to handle sequential control characters,
		// instead of recursive calls?
		WriteTextPart(text.substr(beg, pos - beg), false);

		if (text[pos] == '\n') {
			DoWriteText("\n", true);
		} else if (text[pos] == '\r') {
			SetCursorPosition(0);
		} else if (text[pos] == '\b') {
			SetCursorPosition(-1, true);
		}

		beg = pos + 1;
	}

	DoWriteText(text.substr(beg), commit);
}

void DumbConsoleTextCtrl::DoWriteText(const std::string_view& text, bool commit)
{
	// always append "\n" to the end. Otherwise wxTextCtrl would split the line!
	if (m_cursorPos >= m_currentLine.length() || text == "\n") {
		m_currentLine += text;
		SetCursorPositionEnd();
	} else {
		m_currentLine.replace(m_cursorPos, text.length(), text);
		m_cursorPos += text.length();
	}

	if (commit || text == "\n") {
		long beg = XYToPosition(0, m_currentLineNum);
		wxTextCtrl::Remove(beg, -1);
		// XXX is this really neccessary?
		SetInsertionPoint(beg);
		wxTextCtrl::WriteText(m_currentLine);

		if (text == "\n") {
			m_cursorPos = 0;
			m_currentLineNum += 1;
			m_currentLine.clear();
		}
	}
}

void DumbConsoleTextCtrl::UpdateCurrentLineInfo(bool updateCursor)
{
	long end = GetLastPosition();
	long x;

	PositionToXY(end, &x, &m_currentLineNum);
	long beg = XYToPosition(0, m_currentLineNum);

	m_currentLine = GetRange(beg, end);

	if (updateCursor) {
		m_cursorPos = x;
	}
}
}
