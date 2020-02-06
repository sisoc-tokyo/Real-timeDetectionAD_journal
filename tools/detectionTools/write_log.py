class Write_log:

    def create_message(self, result, attack, datetime, ip_src, eventid, accountname, clientaddr, servicename, processname, objectname, sharedname):
        msg = 'Suspicious activity was detected.\n' + str(result) + '\nATT&CK: ' + str(attack) + '\nTime: ' + str(datetime) + '\nSource_IP_address: ' + str(ip_src) + '\nAccount: ' + str(accountname) + '\nIP address: ' + str(clientaddr) + '\nService name: ' + str(servicename) + '\nProcess name : ' + str(processname) + '\nObject name: ' + str(objectname) + '\nShared name: ' + str(sharedname) + '\n\n'
        return msg

    def __init__(self, result='-', attack='-', datetime='-', ip_src='-', eventid='-', accountname='-', clientaddr='-', servicename='-', processname='-', objectname='-', sharedname='-'):
        msg = self.create_message(result, attack, datetime, ip_src, eventid, accountname, clientaddr, servicename, processname, objectname, sharedname)
        with open('./detection.log', mode='a') as f:
            f.write(msg)
