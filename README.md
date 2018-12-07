# Linux utility for MicroBot Push

This is a Linux utility for Naran MicroBot Push.

# Deps

    $ pip3 install bluepy

# Usage

Find your device's bdaddr by using hcitool.

    $ sudo hcitool lescan | grep mibp
    XX:XX:XX:XX:XX:XX mibp

You need to get a token from the device first time.

    $ python3 ./microbot.py XX:XX:XX:XX:XX:XX
    update token
    connected
    notify: ack with bdaddr
    touch the button to get a token
    waiting...

Touch the button on the device to continue the process.

    notify: ack with token
    disconnected

The token is stored in ~/.microbot.conf by default.
Now you can use the device by using the token.

    $ python3 ./microbot.py XX:XX:XX:XX:XX:XX
    use existing token
    connected
    disconnected
