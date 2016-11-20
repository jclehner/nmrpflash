--
-- NMRP dissector for Wireshark
--
-- Copyright (C) 2016 Joseph C. Lehner
--
-- Licensed under the GNU GPL 3.0
--

nmrp_proto = Proto("nmrp", "NMRP")

src_f = ProtoField.string("nmrp.src", "Source")
dst_f = ProtoField.string("nmrp.dst", "Destination")
code_f = ProtoField.uint8("nmrp.code", "Code", base.HEX)
id_f = ProtoField.uint8("nmrp.id", "ID", base.HEX)
reserved_f = ProtoField.uint16("nmrp.reserved", "Reserved", base.HEX)
len_f = ProtoField.uint16("nmrp.len", "Length")
data_f = ProtoField.bytes("nmrp.opt", "Options")
opt_type_f = ProtoField.uint16("nmrp.opt.type", "Option", base.HEX)
opt_len_f = ProtoField.uint16("nmrp.opt.len", "Length")
opt_data_f = ProtoField.bytes("nmrp.opt.data", "Data")

nmrp_proto.fields = {
	code_f, reserved_f, len_f, data_f, id_f, opt_type_f, opt_len_f, opt_data_f
}

function nmrp_code(code)
	if code == 1 then return { "ADVERTISE", "Advertise" }
	elseif code == 2 then return { "CONF_REQ", "Configuration Request" }
	elseif code == 3 then return { "CONF_ACK", "Configuration" }
	elseif code == 4 then return { "CLOSE_REQ", "Close Request" }
	elseif code == 5 then return { "CLOSE_ACK", "Close Acknowledgement" }
	elseif code == 6 then return { "KEEP_ALIVE_REQ", "Keep-alive Request" }
	elseif code == 7 then return { "KEEP_ALIVE_ACK", "Keep-alive Acknowledgement" }
	elseif code == 16 then return { "TFTP_UL_REQ", "Upload Request" }
	else return { "#" .. code, "Unknown Opcode " .. code }
	end
end

function nmrp_opt(opt)
	if opt == 0x01 then return "Magic"
	elseif opt == 0x02 then return "IP Configuration"
	elseif opt == 0x04 then return "Region"
	elseif opt == 0x0101 then return "Update Firmware"
	elseif opt == 0x0102 then return "Update String Table"
	elseif opt == 0x0181 then return "Filename"
	else return "#" .. opt
	end
end

function nmrp_dissect_opt(opt, buffer, tree)
	if buffer:len() <= 4 then
		return
	end

	if opt == 0x01 or opt == 0x0181 then
		tree:add(buffer(4), "Value: " .. buffer(4):string())
	elseif opt == 0x02 then
		tree:add(buffer(4, 4), "Address: " .. tostring(buffer(4, 4):ipv4()))
		tree:add(buffer(8, 4), "Netmask: " .. tostring(buffer(8, 4):ipv4()))
	else
		tree:add(opt_len_f, buffer(2, 2))
		tree:add(opt_data_f, buffer(4, buffer:len() - 4))
	end
end


function nmrp_proto.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol = "NMRP"

	local code = buffer(2, 1)
	local len = buffer(4, 2)

	pinfo.cols.info = nmrp_code(code:uint())[2]

	local subtree = tree:add(nmrp_proto, buffer(0))
	subtree:add(code_f, code):append_text(" - " .. nmrp_code(code:uint())[2])
	subtree:add(id_f, buffer(3, 1))
	subtree:add(len_f, len)
	subtree:add(reserved_f, buffer(0, 2))

	local databuf = buffer(6, len:uint() - 6)

	while databuf:len() > 0 do
		local opt = databuf(0, 2):uint()
		local optlen = databuf(2, 2):uint()

		if databuf:len() < optlen then
			break
		end

		local optitem = subtree:add(opt_type_f, databuf(0, 2)):append_text(" - " .. nmrp_opt(opt))
		nmrp_dissect_opt(opt, databuf(0, optlen), optitem)

		if databuf:len() > optlen then
			databuf = databuf(optlen)
		else
			break
		end
	end
end

eth_table = DissectorTable.get("ethertype")
eth_table:add(0x0912, nmrp_proto)
