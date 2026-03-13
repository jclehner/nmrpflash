#include <chrono>
#include <exception>
#include <thread>
#include <signal.h>
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

// the functions below are called from C code

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

int start_control_thread()
{
	try {
		std::thread ctrl([] () {
			if (verbosity > 1) {
				std::cout << "Control thread reading from stdin..." << std::endl;
			}

			while (!g_interrupted) {
				std::this_thread::sleep_for(std::chrono::milliseconds(100));
				// if we just called getchar() without checking if there's actually any
				// data, the control thread could block even after main() has returned
#ifdef NMRPFLASH_WINDOWS
				if (!kbhit()) {
					continue;
				}
#else
				int s = select_readfd(STDIN_FILENO, 0);
				if (s < 0) {
					break;
				} else if (!s) {
					continue;
				}
#endif
				int c = getchar();
				if (c == 'i') {
					g_interrupted = 1;
				} else if (c == 't') {
					raise(SIGTERM);
				} else if (c == EOF) {
					break;
				}
			}
		});

		ctrl.detach();
		return 0;
	} catch (const std::exception& e) {
		std::cerr <<  __func__ << ": " << e.what() << "\n";
	} catch (...) {
		std::cerr <<  __func__ << ": unknown exception\n";
	}

	return -1;
}