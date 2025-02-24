// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2014-2021 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/scc-config.h>
#endif

#include <chainparams.h>
#include <clientversion.h>
#include <compat.h>
#include <init.h>
#include <interfaces/chain.h>
#include <noui.h>
#include <shutdown.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <util/threadnames.h>
#include <stacktraces.h>

#include <stdio.h>

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

static void WaitForShutdown()
{
    while (!ShutdownRequested())
    {
        UninterruptibleSleep(std::chrono::milliseconds{200});
    }
    Interrupt();
}

//////////////////////////////////////////////////////////////////////////////
//
// Start
//
static bool AppInit(int argc, char* argv[])
{
    InitInterfaces interfaces;
    interfaces.chain = interfaces::MakeChain();

    bool fRet = false;

    util::ThreadSetInternalName("init");

    //
    // Parameters
    //
    // If Qt is used, parameters/stakecubecoin.conf are parsed in qt/scc.cpp's main()
    SetupServerArgs();
    std::string error;
    if (!gArgs.ParseParameters(argc, argv, error)) {
        tfm::format(std::cerr, "Error parsing command line arguments: %s\n", error.c_str());
        return false;
    }

    if (gArgs.IsArgSet("-printcrashinfo")) {
        std::cout << GetCrashInfoStrFromSerializedStr(gArgs.GetArg("-printcrashinfo", "")) << std::endl;
        return true;
    }

    // Process help and version before taking care about datadir
    if (HelpRequested(gArgs) || gArgs.IsArgSet("-version")) {
        std::string strUsage = PACKAGE_NAME " Daemon version " + FormatFullVersion() + "\n";

        if (gArgs.IsArgSet("-version"))
        {
            strUsage += FormatParagraph(LicenseInfo()) + "\n";
        }
        else
        {
            strUsage += "\nUsage:  sccd [options]                     Start " PACKAGE_NAME " Daemon\n";
            strUsage += "\n" + gArgs.GetHelpMessage();
        }

        tfm::format(std::cout, "%s", strUsage.c_str());
        return true;
    }

    try
    {
        bool datadirFromCmdLine = gArgs.IsArgSet("-datadir");
        if (datadirFromCmdLine && !fs::is_directory(GetDataDir(false)))
        {
            tfm::format(std::cerr, "Error: Specified data directory \"%s\" does not exist.\n", gArgs.GetArg("-datadir", "").c_str());
            return false;
        }
        if (!gArgs.ReadConfigFiles(error, true)) {
            tfm::format(std::cerr, "Error reading configuration file: %s\n", error.c_str());
            return false;
        }
        if (!datadirFromCmdLine && !fs::is_directory(GetDataDir(false)))
        {
            tfm::format(std::cerr, "Error: Specified data directory \"%s\" from config file does not exist.\n", gArgs.GetArg("-datadir", "").c_str());
            return EXIT_FAILURE;
        }
        // Check for -testnet or -regtest parameter (Params() calls are only valid after this clause)
        try {
            SelectParams(gArgs.GetChainName());
        } catch (const std::exception& e) {
            tfm::format(std::cerr, "Error: %s\n", e.what());
            return false;
        }

        // Error out when loose non-argument tokens are encountered on command line
        for (int i = 1; i < argc; i++) {
            if (!IsSwitchChar(argv[i][0])) {
                tfm::format(std::cerr, "Error: Command line contains unexpected token '%s', see sccd -h for a list of options.\n", argv[i]);
                return false;
            }
        }

        // -server defaults to true for sccd but not for the GUI so do this here
        gArgs.SoftSetBoolArg("-server", true);
        // Set this early so that parameter interactions go to console
        InitLogging();
        InitParameterInteraction();
        if (!AppInitBasicSetup())
        {
            // InitError will have been called with detailed error, which ends up on console
            return false;
        }
        if (!AppInitParameterInteraction())
        {
            // InitError will have been called with detailed error, which ends up on console
            return false;
        }
        if (!AppInitSanityChecks())
        {
            // InitError will have been called with detailed error, which ends up on console
            return false;
        }
        if (gArgs.GetBoolArg("-daemon", false))
        {
#if HAVE_DECL_DAEMON
#if defined(MAC_OSX)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
            tfm::format(std::cout, "SCC Core server starting\n");

            // Daemonize
            if (daemon(1, 0)) { // don't chdir (1), do close FDs (0)
                tfm::format(std::cerr, "Error: daemon() failed: %s\n", strerror(errno));
                return false;
            }
#if defined(MAC_OSX)
#pragma GCC diagnostic pop
#endif
#else
            tfm::format(std::cerr, "Error: -daemon is not supported on this operating system\n");
            return false;
#endif // HAVE_DECL_DAEMON
        }
        // Lock data directory after daemonization
        if (!AppInitLockDataDirectory())
        {
            // If locking the data directory failed, exit immediately
            return false;
        }
        fRet = AppInitMain(interfaces);
    } catch (...) {
        PrintExceptionContinue(std::current_exception(), "AppInit()");
    }

    if (!fRet)
    {
        Interrupt();
    } else {
        WaitForShutdown();
    }
    Shutdown(interfaces);

    return fRet;
}

int main(int argc, char* argv[])
{
    RegisterPrettyTerminateHander();
    RegisterPrettySignalHandlers();

#ifdef WIN32
    util::WinCmdLineArgs winArgs;
    std::tie(argc, argv) = winArgs.get();
#endif
    SetupEnvironment();

    // Connect sccd signal handlers
    noui_connect();

    return (AppInit(argc, argv) ? EXIT_SUCCESS : EXIT_FAILURE);
}
