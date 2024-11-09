# adding these just for fun ;p
class NXCModule:
    """Module to extract Windows Defender exclusions from the event log."""

    name = "defender_exclusions"
    description = "Extracts Windows Defender exclusions from the event log."
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        """Process module options."""
        pass

    def on_admin_login(self, context, connection):
        """Main function to retrieve and analyze Windows Defender exclusions."""
        context.log.info("Retrieving Windows Defender exclusions...")
        command = (
            'powershell.exe "Get-WinEvent -LogName \'Microsoft-Windows-Windows Defender/Operational\' '
            '-FilterXPath \'*[System[(EventID=5007)]]\' | '
            'Where-Object { $_.Message -like \'*exclusions\\Path*\' } | '
            'Select-Object Message | Format-List"'
        )
        result = connection.execute(command, True)
        exclusions = result.splitlines() 
        new_value_lines = [
            line.strip() for line in exclusions if line.strip().startswith("New value:")
        ]

        if new_value_lines:
            for new_value in new_value_lines:
                cleaned_value = new_value.replace("New value: HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\", "").replace(" = 0x0", "")
                context.log.highlight(f"Excluded Path: {cleaned_value}")
        else:
            context.log.info("No Windows Defender exclusions found.")
