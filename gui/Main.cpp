#include <exception>
#include <wx/cmdline.h>
#include <wx/log.h>
#include <wx/xrc/xmlres.h>
#include <wx/app.h>
#include "AppFrame.h"
#include "../nmrpd.h"

void InitXmlResource();

namespace nmrpflash {
class MyApp : public wxApp
{
public:
	bool OnInit() override
	{
		wxImage::AddHandler(new wxPNGHandler());
		wxXmlResource::Get()->InitAllHandlers();
		InitXmlResource();

		AppFrame* frame = new AppFrame();
		frame->SetFirmwareFilename(filename);

		frame->Show(true);
		return true;
	}

	bool OnExceptionInMainLoop() override
	{
		try {
			throw;
		} catch (const std::exception& e) {
			wxLogFatalError("Caught exception: %s", e.what());
		} catch (...) {
			wxLogFatalError("Caught unknown exception");
		}

		return false;
	}

#ifdef __WXOSX__
	void MacOpenFiles(const wxArrayString& filenames) override
	{
		if (!filenames.IsEmpty()) {
			filename = fileNames.Last().ToStdString();
		}
	}
#endif

	static std::string filename;
};

std::string MyApp::filename;
}

wxIMPLEMENT_APP_NO_MAIN(nmrpflash::MyApp);

int start_gui(char* argv0, nmrpd_args* args)
{
	umask(077);

	int argc = 1;
	char* argv[] = {
		argv0,
		nullptr,
	};

	if (args->file_local) {
		nmrpflash::MyApp::filename = args->file_local;
	}

#ifdef NMRPFLASH_WINDOWS
	if (console_window_is_ours()) {
		FreeConsole();
	}
#endif

	return wxEntry(argc, argv);
}
