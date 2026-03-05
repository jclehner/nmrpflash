#ifndef NMRPFLASH_GUI_APP_FRAME_BASE_H
#define NMRPFLASH_GUI_APP_FRAME_BASE_H
#include <wx/stattext.h>
#include <wx/statbmp.h>
#include <wx/button.h>
#include <wx/choice.h>
#include <wx/colour.h>
#include <wx/filepicker.h>
#include <wx/frame.h>
#include <wx/hyperlink.h>
#include <wx/textctrl.h>

namespace nmrpflash {
class AppFrameBase : public wxFrame
{
	public:
	AppFrameBase();

	protected:
	wxStaticBitmap* m_iconBitmap;
	wxStaticText* m_textTitle;
	wxHyperlinkCtrl* m_linkCopyright;
	wxChoice* m_adapterList;
	wxButton* m_adapterListBtn;
	wxFilePickerCtrl* m_filePicker;
	wxTextCtrl* m_textCmdlineAdd;
	wxTextCtrl* m_textLog;
	wxStaticText* m_textCmdStatus;
	wxButton* m_startStopBtn;

	private:
	void CreateFromXml();
};
}
#endif
