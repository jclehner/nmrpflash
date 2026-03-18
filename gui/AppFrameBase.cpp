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
#include <wx/collpane.h>
#include <wx/menu.h>
#include <wx/panel.h>
#include <wx/sizer.h>
#include <wx/toplevel.h>
#include <wx/xrc/xmlres.h>

#include "AppFrameBase.h"

namespace nmrpflash {
namespace {
void MakeSameWidth(wxWindow* a, wxWindow* b)
{
	auto aSize = a->GetSize();
	auto bSize = b->GetSize();

	if (aSize.x < bSize.x) {
		a->SetMinSize({ bSize.x, aSize.y });
	} else {
		b->SetMinSize({ aSize.x, bSize.y });
	}
}
}

AppFrameBase::AppFrameBase()
{
	CreateFromXml();

	SetIcon(m_iconBitmap->GetIcon());

	m_iconBitmap->SetScaleMode(wxStaticBitmap::Scale_Fill);

	auto fpBtn = m_filePicker->GetPickerCtrl();
	fpBtn->SetToolTip("Browse");
	MakeSameWidth(fpBtn, m_adapterListBtn);

#ifdef __WXMSW__
	auto font = wxFontInfo(8).FaceName("Consolas");
	m_textLog->SetFont(font);
#endif

	// since we'll modify the default style later
	auto style = m_textLog->GetDefaultStyle();
	style.SetFont(m_textLog->GetFont());
	m_textLog->SetDefaultStyle(style);

	// resize log window to 60 columns x 16 lines
	const int logCols = 60;
	const int logRows = 16;
	auto sz = m_textLog->GetTextExtent("X");
	sz = m_textLog->GetSizeFromTextSize({ sz.x * logCols, sz.y * logRows});
	m_textLog->SetMinSize(sz);

#ifdef __WXGTK__
	// on wxGTK, the frame doesn't shrink as expected when collapsing the pane
	// again. this hack works around that issue...
	m_advancedPane->SetWindowStyle(m_advancedPane->GetWindowStyle() | wxCP_NO_TLW_RESIZE);
	m_advancedPane->Bind(wxEVT_COLLAPSIBLEPANE_CHANGED,
		[this] (wxCollapsiblePaneEvent&) {
		SetSizeHints(wxDefaultSize, wxDefaultSize);

		Layout();
		Fit();

		auto size = GetSize();
		SetSizeHints(size, size);
	});
#endif

#if 0
	CallAfter([this] () {
		GetSizer()->SetSizeHints(this);
		#if 0
		auto sizer = m_panel->GetContainingSizer();
		if (sizer) {
			sizer->SetSizeHints(this);
		}
		#endif
		//GetSizer()->Set
		Fit();
		//Fit();
	});
#endif

#ifdef __WXMAC__
	// dummy menu bar for macOS
	SetMenuBar(new wxMenuBar());
#endif
}

void AppFrameBase::CreateFromXml()
{
	wxXmlResource::Get()->LoadFrame(this, nullptr, "AppFrameBase");
	m_panel = XRCCTRL(*this, "panel", wxPanel);
	m_iconBitmap = XRCCTRL(*this, "icon", wxStaticBitmap);
	m_textTitle = XRCCTRL(*this, "textTitle", wxStaticText);
	m_linkCopyright = XRCCTRL(*this, "linkCopyright", wxHyperlinkCtrl);
	m_adapterList = XRCCTRL(*this, "adapterList", wxChoice);
	m_adapterListBtn = XRCCTRL(*this, "adapterListBtn", wxButton);
	m_filePicker = XRCCTRL(*this, "filePicker", wxFilePickerCtrl);
	m_advancedPane = XRCCTRL(*this, "advancedPane", wxCollapsiblePane);
	m_verbosityChoice = XRCCTRL(*this, "verbosityChoice", wxChoice);
	m_textCustomCmd = XRCCTRL(*this, "textCustomCmd", wxTextCtrl);
	m_textCmdlineAdd = XRCCTRL(*this, "textCmdlineAdd", wxTextCtrl);
	m_textLog = XRCCTRL(*this, "textLog", wxTextCtrl);
	m_textCmdStatus = XRCCTRL(*this, "textCmdStatus", wxStaticText);
	m_startStopBtn = XRCCTRL(*this, "wxID_EXECUTE", wxButton);
}
}
