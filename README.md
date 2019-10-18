
# What is it
This repo is an educational reference of some useful tweaks I quickly threw together to log and analyze the loading and dynamic linking of iOS binaries. Was used for identifying an attack vector to bypass applications compiled with dyld basic integrity checks, on a per app basis for jailed tweaks.

## Requirements
- Theos
- Theos-Jailed (Extension of standard theos library for creating jailed tweaks)
- Decrypted Binary you'd like to poke at
- Fishook in case theos jailed fails to install it.

## How to use

It's assumed you will have basic Theos experiencs or other tweak creation tools. Update the Makefile to point to your target IPA, and set your bundle ID and Tweak name to whatever you're feeling today. Point at the `NAME_FILES = ` line in the Makefile to the target tweak you'd like to use for logging stuff.

The dyld tweak uses fishhook to rebind all methods provide by Dyld with verbose logged implementations. Use this to get an idea how Dyld touches stuff.

The Header Parser was just to play with parsing a MachO binary on the fly. You will need to set the target image that the application includes, by a string name. It will grab that image index, and parse the header and load commands I wanted to inspect. It is not exhaustive for possible load commands, but XNU is open source, so you have good examples in there if you'd like to add the additional commands just to better understand what's up. 
- To Be Fair, This is pretty much just what otool and jtool does when you provide it a static file. If you wanted to try and modify an application on runtime, you could play. 

I'll be pushing up an alternative repo (Remember to add a link TRGoCPftF!) to show how You can identify the segments of the original Binary, and properly bypass applications compiled with Dyld Integrity Checks enabled.
