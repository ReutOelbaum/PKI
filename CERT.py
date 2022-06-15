class cert:
    def __init__(self, name, IP, PORT, signer_IP, signer_PORT, msg, signer_name, signature, public_key, start_date,
                 end_date, CA_FLAG):
        self.name = name
        self.signer_name = signer_name
        self.signer_IP = signer_IP
        self.signer_PORT = signer_PORT
        self.signature = signature
        self.msg = msg
        self.IP = IP
        self.PORT = PORT
        self.public_key = public_key
        self.start_date= start_date
        self.end_date= end_date
        self.CA_FLAG=CA_FLAG
        # self.date=?
    def print(self):
        print("The cert:")
        print(self.name)
        print(self.signer_name)
        print(self.signer_IP)
        print(self.signer_PORT)
        print(self.signature)
        print(self.msg)
        print(self.IP)
        print(self.PORT)
        print(self.public_key)
        print(self.start_date)
        print(self.end_date)
        print(self.CA_FLAG)
