rule powershell_shellcode_loader {

    meta:
        author = "ethical.blue"
        filetype = "PowerShell Script"
        date = "2022-05-19"
        reference = "https://ethical.blue/textz/n/29"
    strings:
        $suspicious_base64 = "[System.Convert]::FromBase64String"
        $delegate_from_func_ptr = "[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer"
        $execute_func = ".Invoke([IntPtr]::Zero)"
    condition:
        all of them
}