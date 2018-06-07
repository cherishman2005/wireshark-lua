do

    --[[  
        创建一个新的协议结构 foo_proto  
        第一个参数是协议名称会体现在过滤器中  
        第二个参数是协议的描述信息，无关紧要  
    --]]  
    local foo_proto = Proto("FOO", "FOO Protocol")  
      
    --[[  
        下面定义字段  
    --]]  
    local foo_protocol_len = ProtoField.uint16("foo.protocollen", "Message Length", base.DEC)  
    local foo_message_id = ProtoField.uint8("foo.messageid", "Message ID", base.DEC)  
    local foo_session_id = ProtoField.uint32("foo.sessionid", "Session ID", base.DEC)  
    local foo_data = ProtoField.bytes("foo.data","Data")  
      
    -- 将字段添加都协议中  
    foo_proto.fields = {  
        foo_protocol_len,  
        foo_message_id,  
        foo_session_id,  
        foo_data  
    }  
      
    --[[  
        下面定义 foo 解析器的主函数，这个函数由 wireshark调用  
        第一个参数是 Tvb 类型，表示的是需要此解析器解析的数据  
        第二个参数是 Pinfo 类型，是协议解析树上的信息，包括 UI 上的显示  
        第三个参数是 TreeItem 类型，表示上一级解析树  
    --]]  
    function foo_proto.dissector(tvb, pinfo, treeitem)  
          
        -- 设置一些 UI 上面的信息  
        pinfo.cols.protocol:set("FOO")  
        pinfo.cols.info:set("FOO Protocol")  
          
        local offset = 0  
        local tvb_len = tvb:len()  
      
        -- 在上一级解析树上创建 foo 的根节点  
        local foo_tree = treeitem:add(foo_proto, tvb:range(tvb_len))  
        foo_tree:add(foo_protocol_len, tvb(0, 2))   --表示从0开始二个字节  
        foo_tree:add(foo_message_id, tvb(2, 1))  
        foo_tree:add(foo_session_id, tvb(4, 4))  
        foo_tree:add(foo_data,tvb(10,tvb_len-10))  
          
    end  
      
    -- 向 wireshark 注册协议插件被调用的条件  
    local tcp_port_table = DissectorTable.get("tcp.port")  
    tcp_port_table:add(7001, foo_proto)  

end