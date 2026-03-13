#include <wx/menu.h>
#include <wx/panel.h>
#include <wx/sizer.h>
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

	//m_iconBitmap->SetScaleMode(wxStaticBitmap::Scale_Fill);

	auto fpBtn = m_filePicker->GetPickerCtrl();
	fpBtn->SetToolTip("Browse");
	MakeSameWidth(fpBtn, m_adapterListBtn);

#ifdef __WXMSW__
	auto font = wxFontInfo(7).FaceName("Consolas");
	m_textLog->SetFont(font);
#endif

	// resize log window to 60 columns x 16 lines
	const int logCols = 60;
	const int logRows = 16;
	auto sz = m_textLog->GetTextExtent("X");
	sz = m_textLog->GetSizeFromTextSize({ sz.x * logCols, sz.y * logRows});
	m_textLog->SetMinSize(sz);

	auto f = [this]() {
		auto sizer = XRCCTRL(*this, "panel", wxPanel)->GetContainingSizer();
		sizer->SetSizeHints(this);
	};

	CallAfter(f);

#ifdef __WXMAC__
	// dummy menu bar for macOS
	SetMenuBar(new wxMenuBar());
#endif
}

void AppFrameBase::CreateFromXml()
{
	wxXmlResource::Get()->LoadFrame(this, nullptr, "AppFrameBase");
	m_iconBitmap = XRCCTRL(*this, "icon", wxStaticBitmap);
	m_textTitle = XRCCTRL(*this, "textTitle", wxStaticText);
	m_linkCopyright = XRCCTRL(*this, "linkCopyright", wxHyperlinkCtrl);
	m_adapterList = XRCCTRL(*this, "adapterList", wxChoice);
	m_adapterListBtn = XRCCTRL(*this, "adapterListBtn", wxButton);
	m_filePicker = XRCCTRL(*this, "filePicker", wxFilePickerCtrl);
	m_textCmdlineAdd = XRCCTRL(*this, "textCmdlineAdd", wxTextCtrl);
	m_textLog = XRCCTRL(*this, "textLog", wxTextCtrl);
	m_textCmdStatus = XRCCTRL(*this, "textCmdStatus", wxStaticText);
	m_startStopBtn = XRCCTRL(*this, "startStopBtn", wxButton);
}
}
