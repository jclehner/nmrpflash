#pragma once
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
	void OnIdle(wxIdleEvent& event);
	void OnCloseWindow(wxCloseEvent& event);

	void OnAdapterListBtnPressed(wxCommandEvent& event);
	void OnStartStopPressed(wxCommandEvent& event);
	void OnSubtitleClicked(wxHyperlinkEvent& event);

private:
	void CreateFromXml(wxWindow* parent);

	bool ReadProcessOutputLine();
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
