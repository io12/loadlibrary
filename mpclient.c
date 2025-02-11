//
// Copyright (C) 2017 Tavis Ormandy
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <ctype.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/unistd.h>
#include <asm/unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <mcheck.h>
#include <err.h>

//#include "winnt_types.h"
//#include "pe_linker.h"
//#include "ntoskernel.h"
//#include "util.h"
#include "hook.h"
#include "log.h"
#include "rsignal.h"
#include "engineboot.h"
#include "scanreply.h"
#include "streambuffer.h"
#include "openscan.h"

// Any usage limits to prevent bugs disrupting system.
const struct rlimit kUsageLimits[] = {
	[RLIMIT_FSIZE]  = { .rlim_cur = 0x20000000, .rlim_max = 0x20000000 },
	[RLIMIT_CPU]    = { .rlim_cur = 3600,       .rlim_max = RLIM_INFINITY },
	[RLIMIT_CORE]   = { .rlim_cur = 0,          .rlim_max = 0 },
	[RLIMIT_NOFILE] = { .rlim_cur = 32,         .rlim_max = 32 },
};

DWORD (* __rsignal)(PHANDLE KernelHandle, DWORD Code, PVOID Params, DWORD Size);

static DWORD EngineScanCallback(PSCANSTRUCT Scan)
{
	if (Scan->Flags & SCAN_MEMBERNAME) {
		LogMessage("Scanning archive member %s", Scan->VirusName);
	}
	if (Scan->Flags & SCAN_FILENAME) {
		LogMessage("Scanning %s", Scan->FileName);
	}
	if (Scan->Flags & SCAN_PACKERSTART) {
		LogMessage("Packer %s identified.", Scan->VirusName);
	}
	if (Scan->Flags & SCAN_ENCRYPTED) {
		LogMessage("File is encrypted.");
	}
	if (Scan->Flags & SCAN_CORRUPT) {
		LogMessage("File may be corrupt.");
	}
	if (Scan->Flags & SCAN_FILETYPE) {
		LogMessage("File %s is identified as %s", Scan->FileName, Scan->VirusName);
	}
	if (Scan->Flags & 0x08000022) {
		LogMessage("Threat %s identified.", Scan->VirusName);
	}
	// This may indicate PUA.
	if ((Scan->Flags & 0x40010000) == 0x40010000) {
		LogMessage("Threat %s identified.", Scan->VirusName);
	}
	return 0;
}

static DWORD ReadStream(PVOID this, ULONGLONG Offset, PVOID Buffer, DWORD Size, PDWORD SizeRead)
{
	fseek(this, Offset, SEEK_SET);
	*SizeRead = fread(Buffer, 1, Size, this);
	return TRUE;
}

static DWORD GetStreamSize(PVOID this, PULONGLONG FileSize)
{
	fseek(this, 0, SEEK_END);
	*FileSize = ftell(this);
	return TRUE;
}

static PWCHAR GetStreamName(PVOID this)
{
	return L"input";
}

// These are available for pintool.
BOOL __attribute__((noinline)) InstrumentationCallback(PVOID ImageStart, SIZE_T ImageSize)
{
	// Prevent the call from being optimized away.
	asm volatile ("");
	return TRUE;
}

int main(int argc, char **argv, char **envp)
{
	HANDLE KernelHandle;
	SCAN_REPLY ScanReply;
	BOOTENGINE_PARAMS BootParams;
	SCANSTREAM_PARAMS ScanParams;
	STREAMBUFFER_DESCRIPTOR ScanDescriptor;
	ENGINE_INFO EngineInfo;
	ENGINE_CONFIG EngineConfig;
	HMODULE Module;
	DWORD res;

	Module = LoadLibrary(TEXT("./engine/mpengine.dll"));
	if (Module == NULL) {
		errx(EXIT_FAILURE, "Failed to load mpengine module");
	}

	__rsignal = (void *) GetProcAddress(Module, "__rsignal");
	if (__rsignal == NULL) {
		errx(EXIT_FAILURE, "Failed to resolve mpengine entrypoint");
	}

	VOID ResourceExhaustedHandler(int Signal)
	{
		errx(EXIT_FAILURE, "Resource Limits Exhausted, Signal %s", strsignal(Signal));
	}

	// Install usage limits to prevent system crash.
	setrlimit(RLIMIT_CORE, &kUsageLimits[RLIMIT_CORE]);
	setrlimit(RLIMIT_CPU, &kUsageLimits[RLIMIT_CPU]);
	setrlimit(RLIMIT_FSIZE, &kUsageLimits[RLIMIT_FSIZE]);
	setrlimit(RLIMIT_NOFILE, &kUsageLimits[RLIMIT_NOFILE]);

	signal(SIGXCPU, ResourceExhaustedHandler);
	signal(SIGXFSZ, ResourceExhaustedHandler);

# ifndef NDEBUG
	// Enable Maximum heap checking.
	mcheck_pedantic(NULL);
# endif

	ZeroMemory(&BootParams, sizeof BootParams);
	ZeroMemory(&EngineInfo, sizeof EngineInfo);
	ZeroMemory(&EngineConfig, sizeof EngineConfig);

	BootParams.ClientVersion = BOOTENGINE_PARAMS_VERSION;
	BootParams.Attributes    = BOOT_ATTR_NORMAL;
	BootParams.SignatureLocation = L"engine";
	BootParams.ProductName = L"Legitimate Antivirus";
	EngineConfig.QuarantineLocation = L"quarantine";
	EngineConfig.Inclusions = L"*.*";
	EngineConfig.EngineFlags = 1 << 1;
	BootParams.EngineInfo = &EngineInfo;
	BootParams.EngineConfig = &EngineConfig;
	KernelHandle = NULL;

#if 0
	asm volatile ("int3");
#endif

	res = __rsignal(&KernelHandle, RSIG_BOOTENGINE, &BootParams, sizeof BootParams);
	if (res != 0) {
		LogMessage("__rsignal(RSIG_BOOTENGINE) returned failure, missing definitions?");
		LogMessage("Make sure the VDM files and mpengine.dll are in the engine directory");
		LogMessage("Error code: %#x", res);
		return 1;
	}

	ZeroMemory(&ScanParams, sizeof ScanParams);
	ZeroMemory(&ScanDescriptor, sizeof ScanDescriptor);
	ZeroMemory(&ScanReply, sizeof ScanReply);

	ScanParams.Descriptor        = &ScanDescriptor;
	ScanParams.ScanReply         = &ScanReply;
	ScanReply.EngineScanCallback = EngineScanCallback;
	ScanReply.field_C            = 0x7fffffff;
	ScanDescriptor.Read          = ReadStream;
	ScanDescriptor.GetSize       = GetStreamSize;
	ScanDescriptor.GetName       = GetStreamName;

	if (argc < 2) {
		LogMessage("usage: %s [filenames...]", *argv);
		return 1;
	}

	for (char *filename = *++argv; *argv; ++argv) {
		ScanDescriptor.UserPtr = fopen(*argv, "r");

		if (ScanDescriptor.UserPtr == NULL) {
			LogMessage("failed to open file %s", *argv);
			return 1;
		}

		LogMessage("Scanning %s...", *argv);

		res = __rsignal(&KernelHandle, RSIG_SCAN_STREAMBUFFER, &ScanParams, sizeof ScanParams);
		if (res != 0) {
			LogMessage("__rsignal(RSIG_SCAN_STREAMBUFFER) returned failure, file unreadable?");
			LogMessage("Error code: %#x", res);
			return 1;
		}

		fclose(ScanDescriptor.UserPtr);
	}

	return 0;
}
