-- The getopt-functionality is loaded from pm3/getopt.lua
-- Have a look there for further details
getopt = require('getopt')
bin = require('bin')
example = "script run dumptoemul-mfu -i dumpdata-foobar.bin"
author = "Martin Holst Swende \n @Marshmellow \n @iceman"
usage = "script run dumptoemul-mfu [-i <file>] [-o <file>] [-p <num_blocks>]"
desc =[[
This script takes a dumpfile from 'hf mfu dump' and converts it to a format that can be used
by the emulator

Arguments:
	-h              This help
	-i <file>       Specifies the dump-file (input). If omitted, 'dumpdata.bin' is used	
	-o <filename>   Specifies the output file. If omitted, <uid>.eml is used. 	
	-p <num_blocks> Pads with zeros for <num_blocks>

]]
--- 
-- A debug printout-function
function dbg(args)
	if DEBUG then
		print("###", args)
	end
end 
--- 
-- This is only meant to be used when errors occur
function oops(err)
	print("ERROR: ",err)
end

--- 
-- Usage help
function help()
	print(desc)
	print(author)
	print("Example usage")
	print(example)
end

local function convert_to_ascii(hexdata)
	if string.len(hexdata) % 8 ~= 0 then 
		return oops(("Bad data, length should be a multiple of 8 (was %d)"):format(string.len(hexdata)))
	end

	local js,i = "[";
	for i = 1, string.len(hexdata),8 do
		js = js .."'" ..string.sub(hexdata,i,i+7).."',\n"
	end
	js = js .. "]"
	return js
end

local function readdump(infile)
	 t = infile:read("*all")
	 len = string.len(t)
	 local len,hex = bin.unpack(("H%d"):format(len),t)
	 return hex
end

local function convert_to_emulform(hexdata)
	if string.len(hexdata) % 8 ~= 0 then 
		return oops(("Bad data, length should be a multiple of 8 (was %d)"):format(string.len(hexdata)))
	end
	local ascii,i = "";
	for i = 1, string.len(hexdata), 8 do
		ascii = ascii..string.sub(hexdata, i, i+7).."\n"
	end	
	return string.sub(ascii, 1, -2)
end

local function zero_padding(hexdata, num_blocks)
	local zeros = "00000000"
	local pad,i = "";
	pad = pad.."\n"
	for i = 1, num_blocks, 1 do
		pad = pad..zeros.."\n"
	end
	return hexdata..string.sub(pad, 1, -2)
end

local function main(args)

	local input = "dumpdata.bin"
	local output
	local padding = 0

	for o, a in getopt.getopt(args, 'i:o:p:h') do
		if o == "h" then return help() end		
		if o == "i" then input = a end
		if o == "o" then output = a end
		if o == "p" then padding = a end
	end
	-- Validate the parameters
	
	local infile = io.open(input, "rb")
	if infile == nil then 
		return oops("Could not read file ", input)
	end
	local dumpdata = readdump(infile)
	-- The hex-data is now in ascii-format,

	-- But first, check the uid
	-- lua uses start index and endindex,  not count.	
	-- UID is  3three skip bcc0 then 4bytes.
	-- 1 lua is one-index.
	-- 1 + 96 (48*2)  new dump format has version/signature/counter data here
	-- 97,98,99,100,101,102   UID first three bytes 
	-- 103,104 bcc0
	-- 105---  UID last four bytes
	local uid = string.sub(dumpdata, 97, 97+5)..string.sub(dumpdata, 97+8, 97+8+7)
	output = output or (uid .. ".eml")

	-- Format some linebreaks
	dumpdata = convert_to_emulform(dumpdata)
	
	-- Zero-padding
	if type(padding) == 'string' then padding = tonumber(padding, 10) end	
	if padding ~= nil and padding > 0 then
		print("Zero-padding "..padding.." blocks")
		dumpdata = zero_padding(dumpdata, padding)
	end

	local outfile = io.open(output, "w")
	if outfile == nil then 
		return oops("Could not write to file ", output)
	end
	
	outfile:write(dumpdata:lower())
	io.close(outfile)
	print(("Wrote an emulator-dump to the file %s"):format(output))
end

--[[
In the future, we may implement so that scripts are invoked directly 
into a 'main' function, instead of being executed blindly. For future
compatibility, I have done so, but I invoke my main from here.  
--]]
main(args)
