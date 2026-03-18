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
#ifndef NMRPFLASH_GUI_APP_FRAME_BASE_H
#define NMRPFLASH_GUI_APP_FRAME_BASE_H
#include <wx/stattext.h>
#include <wx/statbmp.h>
#include <wx/button.h>
#include <wx/choice.h>
#include <wx/colour.h>
#include <wx/filepicker.h>
#include <wx/frame.h>
#include <wx/dialog.h>
#include <wx/hyperlink.h>
#include <wx/textctrl.h>
#include <wx/collpane.h>
#include <wx/panel.h>

namespace nmrpflash {
class AppFrameBase : public wxFrame
{
	public:
	AppFrameBase();

	protected:
	wxPanel* m_panel;
	wxStaticBitmap* m_iconBitmap;
	wxStaticText* m_textTitle;
	wxHyperlinkCtrl* m_linkCopyright;
	wxChoice* m_adapterList;
	wxButton* m_adapterListBtn;
	wxFilePickerCtrl* m_filePicker;
	wxCollapsiblePane* m_advancedPane;
	wxChoice* m_verbosityChoice;
	wxTextCtrl* m_textCustomCmd;
	wxTextCtrl* m_textCmdlineAdd;
	wxTextCtrl* m_textLog;
	wxStaticText* m_textCmdStatus;
	wxButton* m_startStopBtn;

	private:
	void CreateFromXml();
};
}
#endif
