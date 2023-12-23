rule win_x64_PEB_traverser {

    meta:
        author = "ethical.blue"
        filetype = "Binary File"
        date = "2022-05-19"
        reference = "https://ethical.blue/textz/n/29"
    strings:
        /* 6548:8B52 60 | mov rdx,qword ptr gs:[rdx+60] */
        $read_GS_register = { 65 48 8B ?? 60 }
        /* 48:8B52 18 | mov rdx,qword ptr ds:[rdx+18] */
        $read_18_offset = { 48 8B ?? 18 }
        /* 48:8B52 20 | mov rdx,qword ptr ds:[rdx+20] */
        $read_20_offset = { 48 8B ?? 20 }
    condition:
        all of them
}