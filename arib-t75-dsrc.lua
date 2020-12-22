--------------------------------------------------------------------------------
-- dsrc protocol dissector
--------------------------------------------------------------------------------

-- protocol definition
dsrc_proto = Proto("dsrc","DSRC","DSRC protocol")
dsrc_sci_proto = Proto("dsrc.sci","DSRC SCI","DSRC SCI")

--------------------------------------------------------------------------------
-- constants
local uw1_string = {
    [0xd815d27c] = "FCMC in ASK mode"
}
local sig_pvi_string = {
    [0] = "Version 0", [1] = "Version 1", [2] = "Version 2", [3] = "Version 3"
}
local sig_ppi_string = {
    [0] = "Profile 0", [1] = "Profile 1", [2] = "Profile 2", [3] = "Profile 3",
    [4] = "Reserved",  [5] = "Reserved",  [6] = "Reserved",  [7] = "Reserved",
}
local sig_fti_string = {
    [0x0000] = "5795MHz/5835MHz (ETC)",
    [0x0003] = "5805MHz/5845MHz (ETC)",
    [0x0002] = "5800MHz/5840MHz",
    [0x8001] = "5775MHz/5815MHz",
    [0x4001] = "5780MHz/5820MHz",
    [0xc001] = "5795MHz/5825MHz",
    [0x2001] = "5785MHz/5830MHz"
}
local sig_ccz_string = {
    [0] = "Stand-alone type communication zone",
    [1] = "Series of different base stations in the traveling direction"
}
local sig_tri_string = {
    [0] = "Undefined",
    [1] = "First station",
    [2] = "Second station",
    [3] = "Reserved",
}
local sig_tdi_string = {
    [0] = "without Time Division Duplexing",
    [1] = "with Time Division Duplexing"
}
local sig_ati_string = {
    [0] = "Class 1 (Narrow Area)",
    [1] = "Experimental",
    [2] = "Reserved",
    [3] = "Class 2 (Wide Area)"
}
local fsi_cm_string = {
    [0] = "Full Duplex",
    [1] = "Half Duplex"
}
local fsi_sln_string = {
    [0] = "1 slot for half, 2 for full",
    [1] = "2 slots for half, 4 for full",
    [2] = "3 slots for half, 6 for full",
    [3] = "4 slots for half, 8 for full",
    [4] = "5 slots",
    [5] = "6 slots",
    [6] = "7 slots",
    [7] = "8 slots"
}
local rlt_unit_string = {
    [0] = "0.2 sec",
    [1] = "2 sec",
    [2] = "20 sec",
    [3] = "200 sec"
}
local sc_imi_string = {
    [0] = "Normal Association Procedure",
    [1] = "Simplified Association Procedure"
}
local sc_aid_string = {
    [0]  = "System",
    [1]  = "ISO14906 Application",
    [2]  = "ISO-DSRC Application",
    [3]  = "ISO-DSRC Application",
    [4]  = "ISO-DSRC Application",
    [5]  = "ISO-DSRC Application",
    [6]  = "ISO-DSRC Application",
    [7]  = "ISO-DSRC Application",
    [8]  = "ISO-DSRC Application",
    [9]  = "ISO-DSRC Application",
    [10] = "ISO-DSRC Application",
    [11] = "ISO-DSRC Application",
    [12] = "ISO-DSRC Application",
    [13] = "ISO-DSRC Application",
    [14] = "Multi-purpose Toll Collection system (ETC)",
    [15] = "ISO-DSRC Application",
    [16] = "Driving support system",
    [17] = "Multi-purpose information system",
    [18] = "ISO-DSRC Application",
    [19] = "ISO-DSRC Application",
    [20] = "ISO-DSRC Application",
    [21] = "ISO-DSRC Application",
    [29] = "ISO-DSRC Application",
    [30] = "ISO-DSRC Application",
}

--------------------------------------------------------------------------------
-- definition of bit fields
--------------------------------------------------------------------------------

--
-- Layer 2 messages in ASK mode
--
-- FCMC (Frame Control Message Channel) length 58octets
--    * 2bytes of preamble is assumed as truncated in dsrc2pcap
--  (0-3)   Unique Word 1 (UW1)                        : 0xd815d27c (indicates FCMC in ASK)
--  (4-5)   Transmission Channel Control Field (SIG)   :
--      (4)[1:0]             Protocol Version Identifier (PVI)
--      (4)[4:2]             Physical Profile Identifier (PPI)
--      {(5)[1:0], (4)[7:5]} Frequency Type Identifier (FTI)
--      (5)[2]               Continuous Communication Zone (CCZ)
--      (5)[4:3]             Transmitter / Receiver Identifier (TRI)
--      (5)[5]               Time Division Identifier (TDI)
--      (5)[7:6]             Area Type Identifier (ATI)
--  (6)     Fixed Equipment ID (FID)                   : (Station Unique Number)
--  (7)     Frame Structure Identifier (FSI)           :
--      (7)[0]   Communication Mode (CM) :
--      (7)[3:1] Slot Number (SLN)       : indicates assigned communication slot after FCMC
--      (7)[7:4] Reserved                : must be 4'b0000
--  (8)     Release Timer Information Field (RLT)      :
--      (8)[0]   valid :
--      (8)[2:1] unit  :
--      (8)[7:3] value :
--  (9-15)  Service Application Information Field (SC) :
--      (9)  Initialization Mode Identifier (IMI) :
--      (10) Application Identifier (API)          :
--           [0] Extension : 0 (continued) / 1 (not continued)
--           [2:1] must be 2'b0 / 2'b11 for Experiment
--           [7:3] Application Identifier (AID) or Element Identifier (EID)
--  (16)    Control Information Identifier 1 (CI_1)    :
--  (17-20) Link Address Field 1 (LID_1)               :
--  (21)    Control Information Identifier 1 (CI_2)    :
--  (22-25) Link Address Field 2 (LID_2)               :
--  (26)    Control Information Identifier 1 (CI_3)    :
--  (27-30) Link Address Field 3 (LID_3)               :
--  (31)    Control Information Identifier 1 (CI_4)    :
--  (32-35) Link Address Field 4 (LID_4)               :
--  (36)    Control Information Identifier 1 (CI_5)    :
--  (37-40) Link Address Field 5 (LID_5)               :
--  (41)    Control Information Identifier 1 (CI_6)    :
--  (42-45) Link Address Field 6 (LID_6)               :
--  (46)    Control Information Identifier 1 (CI_7)    :
--  (47-50) Link Address Field 7 (LID_7)               :
--  (51)    Control Information Identifier 1 (CI_8)    :
--  (52-55) Link Address Field 8 (LID_8)               :
--  (56-57) Cyclic Redundancy Check (CRC)              :
--------------------------------------------------------------------------------

-- ProtoField.new(name, abbr, type, [valuestring], [base], [mask], [descr])

dsrc_uw1_F       = ProtoField.new(
    "UW1 (Unique Word 1)",
    "dsrc.uw1",     ftypes.UINT32,   uw1_string,      base.HEX_DEC, nil)
dsrc_sig_F       = ProtoField.new(
    "SIG (Transmission Channel Control Field)",
    "dsrc.sig",     ftypes.UINT16,   nil,             base.HEX_DEC, nil)
dsrc_sig_pvi_F   = ProtoField.new(
    "PVI (Protocol Version Identifier)",
    "dsrc.sig.pvi", ftypes.UINT16,   sig_pvi_string,  base.HEX_DEC, 0x0300)
dsrc_sig_ppi_F   = ProtoField.new(
    "PPI (Physical Profile Identifier)",
    "dsrc.sig.ppi", ftypes.UINT16,   sig_ppi_string,  base.HEX_DEC, 0x1c00)
dsrc_sig_fti_F   = ProtoField.new(
    "FTI (Frequency Type Identifier)",
    "dsrc.sig.fti", ftypes.UINT16,   sig_fti_string,  base.HEX_DEC, 0xe003)
dsrc_sig_ccz_F   = ProtoField.new(
    "CCZ (Continuous Communication Zone)",
    "dsrc.sig.ccz", ftypes.UINT16,   sig_ccz_string,  base.HEX_DEC, 0x0004)
dsrc_sig_tri_F   = ProtoField.new(
    "TRI (Transmitter / Receiver Identifier)",
    "dsrc.sig.tri", ftypes.UINT16,   sig_tri_string,  base.HEX_DEC, 0x0018)
dsrc_sig_tdi_F   = ProtoField.new(
    "TDI (Time Division Identifier)",
    "dsrc.sig.tdi", ftypes.UINT16,   sig_tdi_string,  base.HEX_DEC, 0x0020)
dsrc_sig_ati_F   = ProtoField.new(
    "ATI (Area Type Identifier)",
    "dsrc.sig.ati", ftypes.UINT16,   sig_ati_string,  base.HEX_DEC, 0x00c0)
dsrc_fid_F       = ProtoField.new(
    "FID (Fixed Equipment ID)",
    "dsrc.fid",       ftypes.UINT8,  nil,             base.HEX_DEC, nil)
dsrc_fsi_F       = ProtoField.new(
    "FSI (Frame Structure Identifier)",
    "dsrc.fsi",       ftypes.UINT8,  nil,             base.HEX_DEC, nil)
dsrc_fsi_cm_F    = ProtoField.new(
    "CM (Communication Mode)",
    "dsrc.fsi.cm",    ftypes.UINT8,  fsi_cm_string,   base.HEX_DEC, 0x01)
dsrc_fsi_sln_F   = ProtoField.new(
    "SLN (Slot Number)",
    "dsrc.fsi.sln",   ftypes.UINT8,  fsi_sln_string,  base.HEX_DEC, 0x06)
dsrc_rlt_F       = ProtoField.new(
    "RLT (Release Timer Information Field)",
    "dsrc.rlt",       ftypes.UINT8,  nil,             base.HEX_DEC, nil)
dsrc_rlt_valid_F = ProtoField.new(
    "RLT Valid",
    "dsrc.rlt.valid", ftypes.UINT8,  nil,             base.HEX_DEC, 0x01)
dsrc_rlt_unit_F  = ProtoField.new(
    "RLT Unit",
    "dsrc.rlt.unit",  ftypes.UINT8,  rlt_unit_string, base.HEX_DEC, 0x06)
dsrc_rlt_value_F = ProtoField.new(
    "RLT Value",
    "dsrc.rlt.value", ftypes.UINT8,  nil,             base.HEX_DEC, 0xf8)
dsrc_sc_F        = ProtoField.new(
    "SC",
    "dsrc.sc",        ftypes.BYTES,  nil,             nil,          nil)
dsrc_sc_imi_F    = ProtoField.new(
    "IMI (Initialization Mode Identifier)",
    "dsrc.sc.imi",    ftypes.UINT8,  sc_imi_string,   base.HEX_DEC, 0x01)
dsrc_sc_aid1_F   = ProtoField.new(
    "AID1 (Application Identifier 1)",
    "dsrc.sc.aid1",   ftypes.UINT8,  sc_aid_string,   base.HEX_DEC, nil)
dsrc_sc_aid2_F   = ProtoField.new(
    "AID2 (Application Identifier 2)",
    "dsrc.sc.aid2",   ftypes.UINT8,  sc_aid_string,   base.HEX_DEC, nil)
dsrc_sc_aid3_F   = ProtoField.new(
    "AID3 (Application Identifier 3)",
    "dsrc.sc.aid3",   ftypes.UINT8,  sc_aid_string,   base.HEX_DEC, nil)
dsrc_sc_aid4_F   = ProtoField.new(
    "AID4 (Application Identifier 4)",
    "dsrc.sc.aid4",  ftypes.UINT8,   sc_aid_string,   base.HEX_DEC, nil)
dsrc_sc_aid5_F   = ProtoField.new(
    "AID5 (Application Identifier 5)",
    "dsrc.sc.aid5",  ftypes.UINT8,   sc_aid_string,   base.HEX_DEC, nil)
dsrc_sc_aid6_F   = ProtoField.new(
    "AID6 (Application Identifier 6)",
    "dsrc.sc.aid6",  ftypes.UINT8,   sc_aid_string,   base.HEX_DEC, nil)

dsrc_crc_F       = ProtoField.new(
    "CRC (Cyclic Redundancy Check)",
    "dsrc.crc",      ftypes.STRING,  nil,             nil,          nil)

dsrc_uw2_F       = ProtoField.new(
    "UW2 (Unique Word 2)",
    "dsrc.uw2",      ftypes.UINT16,  nil,             base.HEX_DEC, nil)
dsrc_sequence_F  = ProtoField.new(
    "Sequence Number",
    "dsrc.seqnum",   ftypes.UINT32,  nil,             base.HEX_DEC, nil)

dsrc_proto.fields = {
    dsrc_uw1_F,
    dsrc_sig_F, dsrc_sig_pvi_F, dsrc_sig_ppi_F, dsrc_sig_fti_F, dsrc_sig_ccz_F, dsrc_sig_tri_F, dsrc_sig_tdi_F, dsrc_sig_ati_F,
    dsrc_fid_F,
    dsrc_fsi_F, dsrc_fsi_cm_F, dsrc_fsi_sln_F,
    dsrc_rlt_F, dsrc_rlt_valid_F, dsrc_rlt_unit_F, dsrc_rlt_value_F,
    dsrc_sc_F, dsrc_sc_imi_F, dsrc_sc_aid1_F, dsrc_sc_aid2_F, dsrc_sc_aid3_F, dsrc_sc_aid4_F, dsrc_sc_aid5_F, dsrc_sc_aid6_F,
    dsrc_crc_F,

    dsrc_uw2_F,
    dsrc_sequence_F
}

dsrc_sci_ci_F = ProtoField.new("CI", "dsrc.sci.ci", ftypes.UINT8, nil, base.HEX_DEC)
dsrc_sci_lid_F = ProtoField.new("LID", "dsrc.sci.lid", ftypes.UINT32, nil, base.HEX_DEC)

dsrc_sci_proto.fields = {
    dsrc_sci_ci_F, dsrc_sci_lid_F,
}

function dsrc_sci_proto.dissector(buffer, pinfo, tree)
    tree:add(dsrc_sci_ci_F, buffer(0, 1))
    tree:add(dsrc_sci_lid_F, buffer(1, 4))
end

--------------------------------------------------------------------------------
-- parser fuctions
--------------------------------------------------------------------------------

function dsrc_proto.dissector(buffer, pinfo, tree)
    test_16bit = nil
    test_32bit = nil
    if buffer:len() >= 2 then
        test_16bit = buffer(0,2):le_uint()
    end
    if buffer:len() >= 4 then
        test_32bit = buffer(0,4):le_uint()
    end

    if test_32bit ~= nil and test_32bit == 0x7cd215d8 then
        pinfo.cols.protocol = "DSRC (FCMC)"
        pinfo.cols.info = ""
        if buffer:len() ~= 58 then
            pinfo.cols.info = "invalid length"
        end
        local subtree = tree:add(dsrc_proto, buffer(), "DSRC FCMC")

        if buffer:len() >= 4 then
            subtree:add(dsrc_uw1_F, buffer(0, 4))
        end

        if buffer:len() >= 6 then
            subtree:add(dsrc_sig_F, buffer(4, 2))
            subtree:add(dsrc_sig_pvi_F, buffer(4, 2))
            subtree:add(dsrc_sig_ppi_F, buffer(4, 2))
            subtree:add(dsrc_sig_fti_F, buffer(4, 2))
            subtree:add(dsrc_sig_ccz_F, buffer(4, 2))
            subtree:add(dsrc_sig_tri_F, buffer(4, 2))
            subtree:add(dsrc_sig_tdi_F, buffer(4, 2))
            subtree:add(dsrc_sig_ati_F, buffer(4, 2))
        end

        if buffer:len() >= 7 then
            subtree:add(dsrc_fid_F, buffer(6, 1))
        end

        if buffer:len() >= 8 then
            subtree:add(dsrc_fsi_F, buffer(7, 1))
            subtree:add(dsrc_fsi_cm_F, buffer(7, 1))
            subtree:add(dsrc_fsi_sln_F, buffer(7, 1))
        end

        if buffer:len() >= 9 then
            subtree:add(dsrc_rlt_F, buffer(8, 1))
            subtree:add(dsrc_rlt_valid_F, buffer(8, 1))
            subtree:add(dsrc_rlt_unit_F, buffer(8, 1))
            subtree:add(dsrc_rlt_value_F, buffer(8, 1))
        end

        if buffer:len() >= 10 then
            subtree:add(dsrc_sc_F, buffer(9, 7))
            subtree:add(dsrc_sc_imi_F, buffer(9, 1))
        end

        if buffer:len() >= 16 then
            subtree:add(dsrc_sc_aid1_F, buffer(10, 1))
            subtree:add(dsrc_sc_aid2_F, buffer(11, 1))
            subtree:add(dsrc_sc_aid3_F, buffer(12, 1))
            subtree:add(dsrc_sc_aid4_F, buffer(13, 1))
            subtree:add(dsrc_sc_aid5_F, buffer(14, 1))
            subtree:add(dsrc_sc_aid6_F, buffer(15, 1))
        end

        for i = 1, 8 do
            if buffer:len() >= 16 + i*5 then
                local sciTree = subtree:add(dsrc_sci_proto, buffer(16+5*(i-1), 5))
                sciTree:add(dsrc_sci_ci_F, buffer(16+5*(i-1), 1))
                sciTree:add(dsrc_sci_lid_F, buffer(16+5*(i-1)+1, 4))
            end
        end

        if buffer:len() >= 58 then
            csum = 0x0000ffff
            for i = 4, 55 do
                csum = bit32.bxor(csum, buffer(i, 1):le_uint())
                for j = 0, 7 do
                    if (bit32.band(csum, 0x00000001)) == 0x00000001 then
                        csum = bit32.bxor(bit32.rshift(csum, 1), 0x00008408)
                    else
                        csum = bit32.rshift(csum, 1)
                    end
                end
            end
            csum = bit32.band(bit32.bnot(csum), 0x0000ffff)


            if csum == buffer(56, 2):le_uint() then
                subtree:add(dsrc_crc_F, "matched (0x" .. string.format("%04x", buffer(56, 2):le_uint()) .. ")")
            else
                subtree:add(dsrc_crc_F, "unmatched (ref : 0x" .. string.format("%04x", buffer(56, 2):le_uint()) .. ", calc : 0x" .. string.format("%04x", csum) .. ")")
            end
        end
    end

    if test_16bit == 0x5555 then
        pinfo.cols.protocol = "DSRC (WCNC)"
        pinfo.cols.info = ""
        -- not supported
    end

    if test_16bit == 0x7cd2 then
        if buffer:len() == 5 then
            pinfo.cols.protocol = "DSRC (ACTC)"
            pinfo.cols.info = ""
        else
            pinfo.cols.protocol = "DSRC (MDC)"
            pinfo.cols.info = ""
            if buffer:len() ~= 71 then
                pinfo.cols.info = "invalid length"
            end
        end
        local subtree = tree:add(dsrc_proto, buffer(), "DSRC MDC")
        subtree:add(dsrc_uw2_F, buffer(0, 2))
    end
end

-- register protocols
register_postdissector(dsrc_proto)
