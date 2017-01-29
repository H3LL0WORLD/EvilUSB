Function Set-WindowsPassword {
    Param (
        $Username = $env:USERNAME,
        $Password
    )
    Begin {
        if (-Not $Password) {
            $Password = '""'
        }
    }
    Process {
        cmd /c "net user $Username $Password" | Out-Null
    }
}