# wireshark-lua

		操作步骤：
		（1）进入安装路径..\Wireshark\init.lua
		确认disable_lua = false

		（2）在init.lua的最下方增加路径dofile(DATA_DIR.."foo.lua")



#解析示例
		（1）对TCP协议解析foo.lua

		（2）对HTTP协议解析form_urlencoded.lua:

		用Wireshark抓包查看HTTP POST消息，Content-Type为application/x-www-form-urlencoded。解析post请求：
		curl http://172.18.169.15:8888/hello -d 'account=bob&total_fee=100.01' -v

		HTML Form URL Encoded: application/x-www-form-urlencoded
			Form item: "account" = "bob"
			Form item: "total_fee" = "100.01"

#参考资料
		https://blog.csdn.net/jasonhwang/article/details/5525700 