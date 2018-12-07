import binascii
from bluepy.btle import Peripheral
from bluepy.btle import BTLEException
from bluepy.btle import DefaultDelegate
import sys
from time import sleep
import random, string
import configparser
from configparser import NoSectionError
from argparse import ArgumentParser
from os.path import expanduser

class MicroBotPush:
    class UUID():
        SVC1831 = '00001831-0000-1000-8000-00805f9b34fb'
        CHR2A90 = '00002a90-0000-1000-8000-00805f9b34fb'
        CHR2A98 = '00002a98-0000-1000-8000-00805f9b34fb'
        SVC1821 = '00001821-0000-1000-8000-00805f9b34fb'
        CHR2A11 = '00002a11-0000-1000-8000-00805f9b34fb'
        CHR2A12 = '00002a12-0000-1000-8000-00805f9b34fb'
        CHR2A35 = '00002a35-0000-1000-8000-00805f9b34fb'

    class MbpDelegate(DefaultDelegate):
        def __init__(self, params):
            DefaultDelegate.__init__(self)
            self.token = None
            self.bdaddr = None

        def handleNotification(self, cHandle, data):
            if cHandle == 0x31:
                tmp = binascii.b2a_hex(data)
                bdaddr = tmp[12:14]+ \
                         tmp[10:12]+ \
                         tmp[8:10]+ \
                         tmp[6:8]+ \
                         tmp[4:6]+ \
                         tmp[2:4]
                self.bdaddr = bdaddr.decode()
                print("notify: ack with bdaddr")
            elif cHandle == 0x2e:
                token = binascii.b2a_hex(data)[2:2+32]
                self.token = token.decode()
                print("notify: ack with token")
                # vulnerable protocol!
            else:
                print("notify: unknown")

        def getToken(self):
            return self.token

        def getBdaddr(self):
            return self.bdaddr
    # end of class

    def __init__(self, bdaddr, config):
        self.bdaddr = bdaddr
        self.retry = 5
        self.token = None
        self.p = None
        self.handler = None
        self.config = expanduser(config)
        self.__loadToken()

    def connect(self, init=False):
        retry = self.retry
        while True:
            try:
                print("connecting...\r", end='')
                self.p = Peripheral(self.bdaddr, "random")
                self.handler = MicroBotPush.MbpDelegate(0) 
                self.p.setDelegate(self.handler)
                print("connected    ")
                self.__setToken(init)
                break
            except BTLEException:
                if retry == 0:
                    print("failed")
                    break
                retry = retry - 1 
                sleep(1)

    def disconnect(self):
        if self.p == None:
            return
        try:
            self.p.disconnect()
            self.p = None
            print("disconnected")
        except BTLEException:
            print("failed")

    def __loadToken(self):
        config = configparser.ConfigParser()
        config.read(self.config)
        bdaddr = self.bdaddr.lower().replace(':', '')
        if config.has_option('tokens', bdaddr):
            self.token = config.get('tokens', bdaddr)

    def __storeToken(self):
        config = configparser.ConfigParser()
        config.read(self.config)
        if not config.has_section('tokens'):
            config.add_section('tokens')
        bdaddr = self.bdaddr.lower().replace(':', '')
        config.set('tokens', bdaddr, self.token)
        with open(self.config, 'w') as file:
            config.write(file)

    def hasToken(self):
        if self.token == None:
            return False
        else:
            return True

    def __initToken(self):
        s = self.p.getServiceByUUID(MicroBotPush.UUID.SVC1831)
        c = s.getCharacteristics(MicroBotPush.UUID.CHR2A98)[0]
        self.p.writeCharacteristic(c.getHandle()+1, b'\x01\x00')
        c.write(binascii.a2b_hex("00000167"+"00"*16))

        while True:
            bdaddr = self.handler.getBdaddr()
            if bdaddr != None:
                break
            if self.p.waitForNotifications(1.0):
                continue
            print("waiting...\r", end='')

    def __setToken(self, init):
        if init:
            self.__initToken()
        else:
            if self.hasToken():
                s = self.p.getServiceByUUID(MicroBotPush.UUID.SVC1831)
                c = s.getCharacteristics(MicroBotPush.UUID.CHR2A98)[0]
                c.write(binascii.a2b_hex("00000167"+self.token))

    def getToken(self):
        if self.p == None:
            return
        s = self.p.getServiceByUUID(MicroBotPush.UUID.SVC1831)
        c = s.getCharacteristics(MicroBotPush.UUID.CHR2A90)[0]
        self.p.writeCharacteristic(c.getHandle()+1, b'\x01\x00')
        rstr = " "+self.__randomstr(32)+"\x00"*7
        c.write(binascii.a2b_hex(binascii.b2a_hex(rstr.encode())))

        print('touch the button to get a token')

        while True:
            token = self.handler.getToken()
            if token != None:
                break
            if self.p.waitForNotifications(1.0):
                continue
            print("waiting...\r", end='')

        #print(token)
        self.token = token
        self.__storeToken()

    def setDepth(self, depth):
        if self.p == None:
            return
        s = self.p.getServiceByUUID(MicroBotPush.UUID.SVC1821)
        c = s.getCharacteristics(MicroBotPush.UUID.CHR2A35)[0]
        c.write(binascii.a2b_hex('{:02x}'.format(depth)))

    def push(self, period=1):
        if self.p == None:
            return
        retry = self.retry
        while True:
            try:
                s = self.p.getServiceByUUID(MicroBotPush.UUID.SVC1821)
                c = s.getCharacteristics(MicroBotPush.UUID.CHR2A11)[0]
                c.write(b'\x01')
                #sleep(period)
                #c = s.getCharacteristics(MicroBotPush.UUID.CHR2A12)[0]
                #c.write(b'\x01')
                break
            except BTLEDisconnectError:
                if retry == 0:
                    print("failed")
                    break
                retry = retry - 1 
                sleep(1)

    def __randomstr(self, n):
       randstr = [random.choice(string.printable) for i in range(n)]
       return ''.join(randstr)
    # end of class

def getArgs():
    usage = 'usage: python3 {} [-u] [-d #] xx:xx:xx:xx:xx:xx'.format(__file__)
    argparser = ArgumentParser(usage=usage)
    argparser.add_argument('bdaddr', type=str, help='bd address')
    argparser.add_argument('-u', '--update', action='store_true', dest='update', help='forcibly update token')
    argparser.add_argument('-d', '--depth', nargs='?', default=50, type=int, dest='depth', help='depth (0-100)')
    argparser.add_argument('-c', '--config', nargs='?', default='~/.microbot.conf', type=str, dest='config', help='config (~/.microbot.conf)')
    argparser.add_argument('-v', '--verbose', action='store_true', dest='verbose', help='verbose')
    return argparser.parse_args()

def main():
    args = getArgs()
    mbp = MicroBotPush(args.bdaddr, args.config)
    if mbp.hasToken() and not args.update:
        print('use existing token')
        mbp.connect()
        mbp.setDepth(args.depth)
        mbp.push()
        mbp.disconnect()
    else:
        print('update token')
        mbp.connect(init=True)
        mbp.getToken()
        mbp.disconnect()

if __name__ == "__main__":
    main()
