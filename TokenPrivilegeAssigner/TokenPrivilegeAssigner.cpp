// TokenPrivilegeAssigner.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "windows.h"
#include "stdio.h"


#define NUM_PRIVS_TOTAL 36

#define SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME TEXT("SeDelegateSessionUserImpersonatePrivilege")

wchar_t* sPriv[NUM_PRIVS_TOTAL]=
{SE_ASSIGNPRIMARYTOKEN_NAME,
SE_AUDIT_NAME,
SE_BACKUP_NAME,
SE_CHANGE_NOTIFY_NAME,
SE_CREATE_GLOBAL_NAME,
SE_CREATE_PAGEFILE_NAME,
SE_CREATE_PERMANENT_NAME,
SE_CREATE_SYMBOLIC_LINK_NAME,
SE_CREATE_TOKEN_NAME,
SE_DEBUG_NAME,
SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME,
SE_ENABLE_DELEGATION_NAME,
SE_IMPERSONATE_NAME,
SE_INC_BASE_PRIORITY_NAME,
SE_INCREASE_QUOTA_NAME,
SE_INC_WORKING_SET_NAME,
SE_LOAD_DRIVER_NAME,
SE_LOCK_MEMORY_NAME,
SE_MACHINE_ACCOUNT_NAME,
SE_MANAGE_VOLUME_NAME,
SE_PROF_SINGLE_PROCESS_NAME,
SE_RELABEL_NAME,
SE_REMOTE_SHUTDOWN_NAME,
SE_RESTORE_NAME,
SE_SECURITY_NAME,
SE_SHUTDOWN_NAME,
SE_SYNC_AGENT_NAME,
SE_SYSTEM_ENVIRONMENT_NAME,
SE_SYSTEM_PROFILE_NAME,
SE_SYSTEMTIME_NAME,
SE_TAKE_OWNERSHIP_NAME,
SE_TCB_NAME,
SE_TIME_ZONE_NAME,
SE_TRUSTED_CREDMAN_ACCESS_NAME,
SE_UNDOCK_NAME,
SE_UNSOLICITED_INPUT_NAME};



bool SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, bool bEnablePrivilege)
{
    LUID luid;
    bool bRet=false;

    if (LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
    {
        TOKEN_PRIVILEGES tp;

        tp.PrivilegeCount=1;
        tp.Privileges[0].Luid=luid;
        tp.Privileges[0].Attributes=(bEnablePrivilege) ? SE_PRIVILEGE_ENABLED: 0;
        //
        //  Enable the privilege or disable all privileges.
        //
        if (AdjustTokenPrivileges(hToken, FALSE, &tp, NULL, (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
        {
            //
            //  Check to see if you have proper access.
            //  You may get "ERROR_NOT_ALL_ASSIGNED".
            //
            bRet=(GetLastError() == ERROR_SUCCESS);
        }
		else
		{
			printf("AdjustTokenPrivileges Failed, err: %X\r\n",GetLastError());
		}
    }
	else
	{
		printf("LookupPrivilegeValue Failed, err: %X\r\n",GetLastError());
	}
    return bRet;
}


int _tmain(int argc, _TCHAR* argv[])
{


	HANDLE hTokenSelf = 0;
	OpenProcessToken(GetCurrentProcess(),GENERIC_ALL,&hTokenSelf);


	unsigned long Pid = 0;
	HANDLE hProcess = 0;
	HANDLE hToken = 0;
	

	wchar_t* Cmdline_X =0;
	if(argc > 1)
	{
		for(unsigned long cc=1;cc<argc;cc++)
		{
			Cmdline_X = argv[cc];
			if( wcsstr(Cmdline_X,L"/pid") )
			{
				if(cc+1 < argc)
				{
					wchar_t* sPID = argv[cc+1];
					Pid = _wtoi(sPID);
					printf("Pid: %X\r\n",Pid);
					hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,Pid);
					printf("hProcess: %I64X\r\n",hProcess);

					if(hProcess==0)
					{
						printf("OpenProcess Failed, err: %X\r\n",GetLastError());
						return -3;
					}
					else
					{
						bool bRet = OpenProcessToken(hProcess,TOKEN_ADJUST_PRIVILEGES,&hToken);
						printf("hToken: %I64X\r\n",hToken);
						if(!bRet)
						{
							printf("OpenProcessToken Failed, err: %X\r\n",GetLastError());
							CloseHandle(hProcess);
							return -2;
						}

					}
				}
			}
			else
			{
				for(unsigned long i=0;i<NUM_PRIVS_TOTAL;i++)
				{
					if( wcsicmp(Cmdline_X,sPriv[i]) == 0)
					{
						bool bR = SetPrivilege(hToken,sPriv[i],TRUE);
						if(bR)
						{
							wprintf(L"Privilege: %s was applied successfully\r\n",sPriv[i]);
						}
						else
						{
							//wprintf(L"%s\r\n",Cmdline_X);
							//wprintf(L"%s\r\n",sPriv[i]);
							wprintf(L"Error while applying Privilege: %s to the target process token\r\n",sPriv[i]);
							//Continue with next privs
						}
					}
				}
			}
		}
	}
	else
	{
		printf("Usage: TokenPrivilegeAssigner.exe /pid 200 SeDebugPrivilege\r\n");
		return -1;
	}


	if(hToken) CloseHandle(hToken);
	if(hProcess) CloseHandle(hProcess);
	printf("Done\r\n");
	return 0;
}

/*


if( wcsstr(Cmdline_X,L"/noaf") )
			{
				bSetAffinity = false;
				//printf("Yes\r\n");
			}
			else if( wcsstr(Cmdline_X,L"/shared") )
			{
				bShared = true;
				//printf("Yes\r\n");
			}
			else if( wcsstr(Cmdline_X,L"/verbose") )
			{
				bVerbose = 1;
				//printf("Yes\r\n");
			}
			else if( wcsstr(Cmdline_X,L"/nodefer") )
			{
				bDefer = false;
				//printf("Yes\r\n");
			}


			*/



/*	bool bSeAssignPrimaryTokenPrivilege = false;
	bool bSeAuditPrivilege = false;
	bool bSeBackupPrivilege = false;
	bool bSeChangeNotifyPrivilege = false;
	bool bSeCreateGlobalPrivilege = false;
	bool bSeCreatePagefilePrivilege = false;
	bool bSeCreatePermanentPrivilege = false;
	bool bSeCreateSymbolicLinkPrivilege = false;
	bool bSeCreateTokenPrivilege = false;
	bool bSeDebugPrivilege = false;
	bool bSeDelegateSessionUserImpersonatePrivilege = false;
	bool bSeEnableDelegationPrivilege = false;
	bool bSeImpersonatePrivilege = false;
	bool bSeIncreaseBasePriorityPrivilege = false;
	bool bSeIncreaseQuotaPrivilege = false;
	bool bSeIncreaseWorkingSetPrivilege = false;
	bool bSeLoadDriverPrivilege = false;
	bool bSeLockMemoryPrivilege = false;
	bool bSeMachineAccountPrivilege = false;
	bool bSeManageVolumePrivilege = false;
	bool bSeProfileSingleProcessPrivilege = false;
	bool bSeRelabelPrivilege = false;
	bool bSeRemoteShutdownPrivilege = false;
	bool bSeRestorePrivilege = false;
	bool bSeSecurityPrivilege = false;
	bool bSeShutdownPrivilege = false;
	bool bSeSyncAgentPrivilege = false;
	bool bSeSystemEnvironmentPrivilege = false;
	bool bSeSystemProfilePrivilege = false;
	bool bSeSystemtimePrivilege = false;
	bool bSeTakeOwnershipPrivilege = false;
	bool bSeTcbPrivilege = false;
	bool bSeTimeZonePrivilege = false;
	bool bSeTrustedCredManAccessPrivilege = false;
	bool bSeUndockPrivilege = false;
	bool bSeUnsolicitedInputPrivilege = false;

	*/