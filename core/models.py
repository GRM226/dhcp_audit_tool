class DHCPPacket:
    def __init__(self, message_type=None, server_id=None, xid=None, offered_ip=None, lease_time=None, router=None, dns=None, domain=None):
        self.message_type = message_type
        self.server_id = server_id
        self.xid = xid
        self.offered_ip = offered_ip
        self.lease_time = lease_time
        self.router = router
        self.dns = dns if dns else []
        self.domain = domain
        
    def get_message_type(self):
        return self.message_type
    