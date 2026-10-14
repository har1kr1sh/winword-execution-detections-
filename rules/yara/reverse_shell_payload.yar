rule PowerShell_Obfuscated_Reverse_Shell {
    meta:
        description = "Detects common net.sockets or IEX reverse shell strings used in malicious Word documents"
        author = "Hari Krishnan"
        date = "2026-10-14"
        severity = "High"
    strings:
        $net_socket = "System.Net.Sockets.TCPClient" nocase
        $stream_read = "GetStream().Read" nocase
        $ascii_enc = "System.Text.ASCIIEncoding" nocase
        $iex_cmd = "IEX" nocase
        $cmd_shell = "cmd.exe" nocase
    condition:
        $net_socket and ($stream_read or $ascii_enc) and ($iex_cmd or $cmd_shell)
}
