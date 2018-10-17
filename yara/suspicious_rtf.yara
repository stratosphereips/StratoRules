

rule suspicious_rtf_1
{
	meta:
		author = "civilsphere, jowabels"
		date = "10/17/2018"
		description = "generic rule for suspicious rtf files, matching Win API byte strings inside rtf files. Also, possible CVE-2017-11882 exploit"

	strings:
		$rtf = "{\\rtf" ascii
		
		$api1 = "4c6f61644c696272617279" ascii //LoadLibrary
		$api2 = "47657450726f6341646472657373" ascii //GetProcAddress
		$api3 = "457870616e64456e7669726f6e6d656e74537472696e6773" ascii //ExpandEnvironmentStrings
		$api4  = "43726561746546696c65" ascii //CreateFile
		$api5 = "57696e48747470" ascii //WinHttp
		$api6 = "57696e487474704f70656e" ascii //WinHttpOpen
		$api7 = "57696e48747470436f6e6e656374" ascii //WinHttpConnect
		$api8 = "57696e487474704f70656e52657175657374" ascii //WinHttpOpenRequest
		$api9 = "57696e4874747053656e6452657175657374" ascii //WinHttpSendRequest
		$api10 = "57696e4874747052656365697665526573706f6e7365" ascii //WinHttpReceiveResponse
		$api11 = "577269746546696c65" ascii //WriteFile
		$api12 = "57696e48747470517565727944617461417661696c61626c65" ascii //WinHttpQueryDataAvailable
		$api13 = "57696e487474705265616444617461" ascii //WinHttpReadData
		$api14 = "436c6f736548616e646c65" ascii //CloseHandle
		$api15 = "47657453746172747570496e666f" ascii //GetStartupInfo
		$api16 = "43726561746550726f63657373417355736572" ascii //CreateProcessAsUser
		$api17 = "4578697450726f63657373" ascii //ExitProcess
		

	condition:
		$rtf in (0..5) and 15 of ($api*)

}

