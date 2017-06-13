import frida
import sys
import os
from optparse import OptionParser

# Created by Murphy on 11/06/17.
# This is an exercise to Bypass a Login method detection. 
# First, Find the method to hook using class-dump or Radare2.
#  class-dump <bin>
#  echo 'ic' > classdump.r2; r2 -i classdump.r2 <bin>


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
    ** LOGIN BYPASS        WITH FRIDA   **
    **                                  **
    **************************************
    """

def do_hook_exercise ():
    hook = """
    if(ObjC.available) {
          send("Jailbreak Detection enabled");
          for(var className in ObjC.classes) {
              if (ObjC.classes.hasOwnProperty(className)) {
                  if(className == "<ToComplete>") {
                      send("Found our target class : " + className);

                      var hook = ObjC.classes.LoginViewController["- <ToComplete>"];
                      Interceptor.attach(hook.implementation, {
                      onEnter: function (args) {
                      },
                      onLeave: function (retval) {
                          retval.replace(<ToComplete>);
                          send("Login bypassed!");
                      }
                    });
                  } 
              }
          }
      } 
      else {
		    console.log("Objective-C Runtime is not available!");
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
    
    #----
    #Uncomment this for the exercise
		script = session.create_script(do_hook_exercise())
    #----

		script.on('message', on_message)
		script.load()
		sys.stdin.read()
	except KeyboardInterrupt:
		sys.exit(0)
