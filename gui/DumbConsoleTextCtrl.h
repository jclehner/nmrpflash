#pragma once
#include <string>
#include <wx/object.h>
#include <wx/textctrl.h>

namespace nmrpflash {
class DumbConsoleTextCtrl : public wxTextCtrl
{
	wxDECLARE_DYNAMIC_CLASS(DumbConsoleTextCtrl);

public:
	DumbConsoleTextCtrl() = default;

	bool Create(
		wxWindow* parent,
		wxWindowID id,
		const wxString& value=wxEmptyString,
		const wxPoint& pos=wxDefaultPosition,
		const wxSize& size=wxDefaultSize,
		long style=wxTE_MULTILINE,
		const wxValidator& validator=wxDefaultValidator,
		const wxString& name=wxTextCtrlNameStr
	);

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
