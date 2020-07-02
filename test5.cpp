#include <iostream>
#include <windows.h>
#include <tchar.h>
#include "accctrl.h"
#include "aclapi.h"
//C:/Users/Vicky/Documents/Software/abc.txt
//C:\37b73d3fbaad8b79db553b61f7b5f281\PkgInstallOrder.txt
using namespace std;

void DisplayAccessMask(ACCESS_MASK Mask)
{
      // This evaluation of the ACCESS_MASK is an example. 
      // Applications should evaluate the ACCESS_MASK as necessary.

   //printf("Effective Allowed Access Mask : %8X\n", Mask);
   if (((Mask & GENERIC_ALL) == GENERIC_ALL)
      || ((Mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS))
   {
         printf("Full Control\n");
         return;
   }
   if (((Mask & GENERIC_READ) == GENERIC_READ)
      || ((Mask & FILE_GENERIC_READ) == FILE_GENERIC_READ))
         printf("Read\n");
   if (((Mask & GENERIC_WRITE) == GENERIC_WRITE)
      || ((Mask & FILE_GENERIC_WRITE) == FILE_GENERIC_WRITE))
         printf("Write\n");
   if (((Mask & GENERIC_EXECUTE) == GENERIC_EXECUTE)
      || ((Mask & FILE_GENERIC_EXECUTE) == FILE_GENERIC_EXECUTE))
         printf("Execute\n");
}

int main()
{
DWORD dwRtnCode = 0;
PSID pSidOwner = NULL;
PSID GroupSID = NULL;
BOOL bRtnBool = TRUE;
LPTSTR AcctName = NULL;
LPTSTR DomainName = NULL;
DWORD dwAcctName = 1, dwDomainName = 1;
SID_NAME_USE eUse = SidTypeUnknown;
HANDLE hFile;
PSECURITY_DESCRIPTOR pSD = NULL;
ACL *pDACL = new ACL;
string input, ext = "";

wcout << "Enter the location : " << endl;
cin>>input;
LPCSTR file = input.c_str();
// Get the handle of the file object.
hFile = CreateFile(
                  file,
                  GENERIC_READ,
                  FILE_SHARE_READ,
                  NULL,
                  OPEN_EXISTING,
                  FILE_ATTRIBUTE_NORMAL,
                  NULL);
                  
// Check GetLastError for CreateFile error code.
if (hFile == INVALID_HANDLE_VALUE) {
          DWORD dwErrorCode = 0;
          dwErrorCode = GetLastError();
          cout << "CreateFile error = " << dwErrorCode;
          return -1;
}

// Get the SID of the file.
dwRtnCode = GetSecurityInfo(
                  hFile,
                  SE_FILE_OBJECT,
                  DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                  &pSidOwner,
                  NULL,
                  &pDACL,
                  NULL,
                  &pSD);

// Check GetLastError for GetSecurityInfo error condition.
if (dwRtnCode != ERROR_SUCCESS) {
          DWORD dwErrorCode = 0;
          dwErrorCode = GetLastError();
          cout << "GetSecurityInfo error = " << dwErrorCode;
          return -1;
}

else if (dwRtnCode == ERROR_SUCCESS) {
		cout << "\n\nGetSecurityInfo() Success, Number of ACE: " << pDACL->AceCount << "\n\n";
}

bRtnBool = LookupAccountSid(
                  NULL,           // local computer
                  pSidOwner,
                  AcctName,
                  (LPDWORD)&dwAcctName,
                  DomainName,
                  (LPDWORD)&dwDomainName,
                  &eUse);

	// Reallocate memory for the buffers.
	AcctName = (LPTSTR)GlobalAlloc(GMEM_FIXED,dwAcctName);
	DomainName = (LPTSTR)GlobalAlloc(GMEM_FIXED,dwDomainName);
	
    // Second call to LookupAccountSid to get the account name.
    bRtnBool = LookupAccountSid(
          NULL,                   // name of local or remote computer
          pSidOwner,              // security identifier
          AcctName,               // account name buffer
          (LPDWORD)&dwAcctName,   // size of account name buffer 
          DomainName,             // domain name
          (LPDWORD)&dwDomainName, // size of domain name buffer
          &eUse);                 // SID type
          
    // Print the account name.
    cout<<"Path\t: "<<input;
	cout<<"\nOwner\t: "<<AcctName<<endl;

PACL pAcl = pDACL;
int aceNum = pDACL->AceCount;
cout<<"Access";
for (int i = 0; i < aceNum; i++)
{
	PACCESS_ALLOWED_ACE AceItem;
    ACE_HEADER *aceAddr = NULL;
    if (GetAce(pDACL, i, (LPVOID*)&AceItem) && GetAce(pDACL, i, (LPVOID*)&aceAddr))
    {
    	LPTSTR AccountBuff = NULL;
        LPTSTR DomainBuff = NULL;
        DWORD AccountBufflength = 1;
        DWORD DomainBufflength = 1;
        PSID_NAME_USE peUse = new SID_NAME_USE;
        PSID Sid = &AceItem->SidStart;
        LookupAccountSid(NULL, Sid, AccountBuff, (LPDWORD)&AccountBufflength, DomainBuff, (LPDWORD)&DomainBufflength,peUse);
    	
		AccountBuff = (LPTSTR)GlobalAlloc(GMEM_FIXED,AccountBufflength);
    	DomainBuff = (LPTSTR)GlobalAlloc(GMEM_FIXED,DomainBufflength);
		
		LookupAccountSid(NULL, Sid, AccountBuff, &AccountBufflength, DomainBuff, &DomainBufflength,peUse);
        cout<<"\t: "<<DomainBuff<<"\\"<<AccountBuff<<"\t";
        DisplayAccessMask(AceItem->Mask);
    }
}
    return 0;
}
