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
#ifndef NMRPFLASH_GUI_APP_FRAME_H
#define NMRPFLASH_GUI_APP_FRAME_H
#include <wx/collpane.h>
#include <wx/timer.h>
#include <wx/process.h>
#include <string>
#include "AppFrameBase.h"
#include "PrivilegedProcess.h"

namespace nmrpflash {
class AppFrame : public AppFrameBase
{
public:
	AppFrame();
	~AppFrame();

	void SetFirmwareFilename(const std::string& filename);


protected:
	void WriteProcess(const std::string& str);

	void OnTimer(wxTimerEvent& event);
	void OnTerminate(wxProcessEvent& event);
	void OnUpdateUI(wxUpdateUIEvent& event);
	void OnCloseWindow(wxCloseEvent& event);

	void OnAdapterListBtnPressed(wxCommandEvent& event);
	void OnStartStopPressed(wxCommandEvent& event);
	void OnSubtitleClicked(wxHyperlinkEvent& event);
	void OnCollapsibleEvent(wxCollapsiblePaneEvent& event);

private:
	void CreateFromXml(wxWindow* parent);

	bool ReadProcessOutputLine(bool terminated=false);
	void WriteProcessInput(const std::string& str);
	void EndProcess();
	long ExecuteProcess();
	std::string GetProcessCommand(char quote) const;

	void UpdateProcessState(bool running);
	void UpdateNetAdapterList(bool userInitiated);

	std::unique_ptr<PrivilegedProcess> m_process;
	wxTimer* m_timer = nullptr;
	const std::string* m_p_authUtil = nullptr;
};
}
#endif
