-- Decode param=value from "application/x-www-form-urlencoded" type http body  
-- Author: Huang Qiangxiong (qiangxiong.huang@gmail.com)  
-- change log:  
--      2010-04-20  
--          Just can play.  
--      2010-04-24     
--          Add option "Turn on/off debug tree item" to preference window.  
--          Add option "add_orig_item" to preference window.  
------------------------------------------------------------------------------------------------  
do  
    local form_urlencoded_proto = Proto("my_form_urlencoded",   
                   "MIME Encapsulation: application/x-www-form-urlencoded")  
  
    --setup options that could be found in preferences->MY_FORM_URLENCODED  
    local prefs = form_urlencoded_proto.prefs  
    prefs.debug_flag = Pref.bool("Turn on debug (a [DEBUG Tree proto: my_form_urlencoded] item will appear in Package Details tree)",   
                                 false,   
                                 "If you turn of debug, (a [DEBUG Tree proto: my_form_urlencoded] item will appear in Package Details tree)")  
    prefs.add_orig_item = Pref.bool("Show orignal wireshark's data-text-lines dissection item in Package Details tree",   
                                    false,   
                                    "Show orignal wireshark's data-text-lines dissection item in Package Details tree")  
    -----------DEBUG Function ------------------------------------------------  
    --local debug_flag = true  
    local dmap = {}  
    function d(tree, msg)  
        if prefs.debug_flag and tree then  
            local dt = dmap[tree]  
            if dt == nil then   
                dt = tree:add("[DEBUG Tree for " .. form_urlencoded_proto.name .. "]")  
                dmap[tree] = dt  
            end  
            dt:add("[DEBUG] " .. msg)   
        end  
    end  
    ---------------------------------------------------------------------------------  
      
    ---- url decode (from www.lua.org guide)  
    function unescape (s)  
        s = string.gsub(s, "+", " ")  
        s = string.gsub(s, "%%(%x%x)", function (h)  
            return string.char(tonumber(h, 16))  
        end)  
        return s  
    end  
     
    ---- save old dissector  
    local media_type_table = DissectorTable.get("media_type")  
    local old_dissector = media_type_table:get_dissector("application/x-www-form-urlencoded")  
  
    ---- my dissector  
    function form_urlencoded_proto.dissector(tvb, pinfo, tree)  
        d(tree, "pinfo.curr_proto=" .. pinfo.curr_proto)  
        d(tree, "tvb:offset()=" .. tvb:offset())   
        d(tree, "tvb:len()=" .. tvb:len())   
          
        if prefs.add_orig_item then  
            old_dissector:call(tvb, pinfo, tree)  
        end  
          
        -- begin build my tree  
        local tvb_range = tvb()  
        local content = tvb_range:string()  
          
        -- add proto item to tree  
        local subtree = tree:add(form_urlencoded_proto, tvb_range)  
          
        -- add raw data to tree  
        subtree:add(tvb_range, "[Raw Data] (" .. tvb_range:len() .. " bytes)"):add(tvb_range, content)  
  
        -- add param value pair to tree  
        local pairs_tree = subtree:add(tvb_range, "[Decoded Data]")  
        local si = 1  
        local ei = 0  
        local count = 0  
        while ei do  
            si = ei + 1  
            ei = string.find(content, "&", si)  
            local xlen = (ei and (ei - si)) or (content:len() - si + 1)  
            if xlen > 0 then  
                pairs_tree:add(tvb(si-1, xlen), unescape(content:sub(si, si+xlen-1)))  
                count = count + 1  
            end  
        end  
        pairs_tree:append_text(" (" .. count .. ")")  
          
    end  
  
    -- register this dissector  
    media_type_table:add("application/x-www-form-urlencoded", form_urlencoded_proto)  
  
end  
