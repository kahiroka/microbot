# Linux utility for MicroBot Push

This is a Linux utility for Naran MicroBot Push.

# Deps

    $ pip3 install bluepy

# Usage

Find your device's bdaddr by using hcitool.

    $ sudo hcitool lescan | grep mibp
    XX:XX:XX:XX:XX:XX mibp

You need to get a token from the device first time.
(Please add '-n' option in case of 1.x.x.x firmware.)

    $ python3 ./microbot.py [-n] XX:XX:XX:XX:XX:XX
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

    $ python3 ./microbot.py [-n] XX:XX:XX:XX:XX:XX
    use existing token
    connected
    disconnected

If you need to set mode, depth or press&hole duration in case of 1.x.x.x firmware, please use -s option to set them in advance.

    $ python3 ./microbot.py -n -s -m normal -d 25 -p 5 XX:XX:XX:XX:XX:XX
    and then,
    $ python3 ./microbot.py -n XX:XX:XX:XX:XX:XX

Simple server mode is added. This mode uses unix domain socket and its file path is /var/tmp/microbot-xxxxxxxxxxxx.

    On server side:
    $ python3 ./microbot.py -r -n XX:XX:XX:XX:XX:XX

    On client side:
    $ python3 ./microbot.py -n XX:XX:XX:XX:XX:XX
