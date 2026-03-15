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

static bool getchar_nonblocking(char& c)
{
#ifdef NMRPFLASH_WINDOWS
	OVERLAPPED ov = {};

	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);

	if (!ReadFile(hStdin, &c, sizeof(c), nullptr, &ov)) {
		if (GetLastError() == ERROR_IO_PENDING) {
			win_perror("ReadFile");
		}
		return false;
	} else {
		return true;
	}

	DWORD bytes = 0;
	if (!GetOverlappedResultEx(hStdin, &ov, &bytes, 0, false)) {
		if (GetLastError() != ERROR_IO_INCOMPLETE) {
			win_perror("GetOverlappedResultEx");
		}
	} else if (bytes == sizeof(c)) {
		return true;
	}

	return false;
#else
	int s = select_readfd(STDIN_FILENO, 0);
	if (s <= 0) {
		return false;
	}

	int i = getchar();
	if (i == EOF) {
		return false;
	}

	c = i;
	return true;
#endif
}

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
				printf("Control thread listening on stdin...\n");
			}

			while (!g_interrupted) {
				std::this_thread::sleep_for(std::chrono::milliseconds(100));

				char c = 0;

				// if we just called getchar() without checking if there's actually any
				// data, the control thread could block even after main() has returned
				if (getchar_nonblocking(c)) {
					if (c == 'i') {
						g_interrupted = 1;
					} else if (c == 't') {
						raise(SIGTERM);
					}
				}
			}
		});

		ctrl.detach();
		return 0;
	} catch (const std::exception& e) {
		fprintf(stderr, "Error: %s: %s\n", __func__, e.what());
	} catch (...) {
		fprintf(stderr, "Error: %s: unknown exception\n", __func__);
	}

	return -1;
}