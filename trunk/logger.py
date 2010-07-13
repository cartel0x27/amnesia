# import logging
# logname = "/tmp/amnesia.log"
# logging.basicConfig(filename=logname, level=logging.DEBUG, filemode="w")
# logging.debug("amnesia log starting")

def debug(s):
    f = open("/tmp/amnesia.log", "a")
    print "debug: %s"%s
    try:
        f.write(s+ "\n")
    except:
        pass
    f.close()