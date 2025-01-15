rule wannacry_hardcoded_strings {
	meta:
		description = "Detect WannaCry tasksche.exe hardcoded strings"
	    
	strings:
		$stringWANACRY = "WANACRY!" fullword
		$stringWNcry = "WNcry@2ol7" fullword
		$stringwnryFileExt = ".wnry" nocase
		$stringExecutable = "tasksche.exe" fullword
	
	condition:
		any of them
}

rule suspicious_file_commands {

	meta:
		description = "Detect suspicious hiding of files or granting of rights"
		
	strings:
		$cmd1 = "attrib +h ." ascii
		$cmd2 = "icacls . /grant Everyone:F /T /C /Q" ascii
    
	condition:
		any of them
}

rule creating_services {
    meta:
        description = "Detect whether the program is creating services"
    
    strings:
        $createService = "CreateServiceA" ascii
        $startService = "StartServiceA" ascii
    
    condition:
        $createService or $startService
}

rule suspicious_API_Usage {
    meta:
        description = "Detect whether the program has suspicious API usage"
    
    strings:
        $cryptApi1 = "CryptEncrypt" // cryptography
        $cryptApi2 = "CryptGenKey"
        $cryptApi3 = "CryptImportKey"
        $cryptApi4 = "CryptDestroyKey"
        $cryptApi5 = "CryptAcquireContextA"
        $fileApi1 = "CreateFileA" // CRUD and files
        $fileApi2 = "DeleteFileA"
        $fileApi3 = "WriteFile"
        $fileApi4 = "SetCurrentDirectoryW"
        $processApi1 = "CreateProcessA"
    
    condition:
    	$processApi1 or (
        any of ($cryptApi*) or
        2 of ($fileApi*)
        )
}

rule suspicious_services_and_API_usage {
    meta:
	description = "Flag as suspicious if there's both suspicious API usage and creation of services"
    	
    condition:
    	creating_services and suspicious_API_Usage
}

rule main_rule {
    meta:
    	description = "Detect if the program is WannaCry or malware, based on the rules 'wannacry_hardcoded_strings', 'suspicious_file_commands', 'suspicious_services_and_API_usage'"
    	
    condition:
    	wannacry_hardcoded_strings or 
    	(suspicious_file_commands and 
    		suspicious_services_and_API_usage)
}