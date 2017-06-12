import frida
import sys
from optparse import OptionParser
import os

def on_message(message, data):
    try:
        if message:
            print("[*] {0}".format(message["payload"]))
    except Exception as e:
        print(message)
        print(e)

def banner():
    return """
    **************************************
    **                                  **
    ** KEYCHAIN HOOKING WITH FRIDA      **
    **                                  **
    **************************************
    """



def do_hook():

    # $methods: array containing native method names exposed by this object

    hook = """
	var className = "Security";
	var hookMethods = ["SecItemAdd", "SecItemUpdate", "SecItemDelete"];

	for (index = 0; index < hookMethods.length; index++) {
		var methodName = hookMethods[index];
		send("Hooking class : " + className);

		var ptr = null;
		Module.enumerateExports(className, {
			onMatch: function(imp) {
				if (imp.type == "function" && imp.name == methodName) {
					send("Found target method : " + methodName);

					try {
						Interceptor.attach(ptr(imp.address), {
							onEnter: function(args) {
								send("Hooking method : " + imp.name);
								var params = ObjC.Object(args[0]); // CFDictionaryRef => NSDictionary
								var keys = params.allKeys();
								for (index = 0; index < keys.count(); index++) {
									var k = keys.objectAtIndex_(index);
									var v = params.objectForKey_(k);
									if (k == "v_Data") {
										var string = ObjC.classes.NSString.alloc();
										v = string.initWithData_encoding_(v,4).toString();
									}
									if (k == "pdmn") {
										if (v == "ak") {
											v = "kSecAttrAccessibleWhenUnlocked";
										} else if (v == "ck") {
											v = "kSecAttrAccessibleAfterFirstUnlock";
										} else if (v == "dk") {
											v = "kSecAttrAccessibleAlways";
										} else if (v == "aku") {
											v = "kSecAttrAccessibleWhenUnlockedThisDeviceOnly"
										} else if (v == "cku") {
											v = "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly";
										} else {
											// v == dku
											v = "kSecAttrAccessibleAlwaysThisDeviceOnly";
										}
									}
									send("   " + k + "=" + v);
								}
							}
						});
					} catch (error) {
						console.log("Ignoring " + imp.name + ": " + error.message);
					}
				}
			},
			onComplete: function (e) {
					send("All methods loaded");
			}
		});
	}
	"""
    return hook

if __name__ == '__main__':
	print (banner())

	#To Attach to an iOS Simulator Process, attach to a Gadget Process

	try:
		parser = OptionParser(usage="usage: %prog [options] <process_to_hook>",version="%prog 1.0")
		parser.add_option("-A", "--attach", action="store_true", default=False,help="Attach to a running process")
		parser.add_option("-S", "--spawn", action="store_true", default=False,help="Spawn a new process and attach")
		(options, args) = parser.parse_args()
		if (options.spawn):
			print ("[*] Spawning "+ str(args[0]))
        		#Use frida.get_usb_device() to attach an iOS Device
			pid = frida.get_remote_device().spawn([args[0]])
			session = frida.get_remote_device().attach(pid)
		elif (options.attach):
			print ("[*] Attaching to "+str(args[0]))
			#Use frida.get_usb_device() to attach an iOS Device
			session = frida.get_remote_device().attach(str(args[0]))
		else:
			print ("Error")
			print ("[X] Option not selected. View --help option.")
			sys.exit(0)
		script = session.create_script(do_hook())
		script.on('message', on_message)
		script.load()
		sys.stdin.read()
	except KeyboardInterrupt:
		sys.exit(0)
