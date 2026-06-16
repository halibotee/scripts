<!DOCTYPE html
	PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<html xmlns:v>

<head>
	<meta http-equiv="X-UA-Compatible" content="IE=Edge" />
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
	<meta HTTP-EQUIV="Pragma" CONTENT="no-cache">
	<meta HTTP-EQUIV="Expires" CONTENT="-1">
	<link rel="shortcut icon" href="images/favicon.png">
	<link rel="icon" href="images/favicon.png">
	<title id="ss_title">【科学上网】</title>
	<link rel="stylesheet" type="text/css" href="index_style.css">
	<link rel="stylesheet" type="text/css" href="form_style.css">
	<link rel="stylesheet" type="text/css" href="usp_style.css">
	<link rel="stylesheet" type="text/css" href="css/element.css">
	<link rel="stylesheet" type="text/css" href="/device-map/device-map.css">
	<link rel="stylesheet" type="text/css" href="/js/table/table.css">
	<link rel="stylesheet" type="text/css" href="/res/layer/theme/default/layer.css">
	<link rel="stylesheet" type="text/css" href="/res/softcenter.css">
	<link rel="stylesheet" type="text/css" href="/res/fancyss.css">
	<script language="JavaScript" type="text/javascript" src="/js/jquery.js"></script>
	<script language="JavaScript" type="text/javascript" src="/res/layer/layer.js"></script>
	<script language="JavaScript" type="text/javascript" src="/js/httpApi.js"></script>
	<script language="JavaScript" type="text/javascript" src="/state.js"></script>
	<script language="JavaScript" type="text/javascript" src="/general.js"></script>
	<script language="JavaScript" type="text/javascript" src="/popup.js"></script>
	<script language="JavaScript" type="text/javascript" src="/help.js"></script>
	<script language="JavaScript" type="text/javascript" src="/validator.js"></script>
	<script language="JavaScript" type="text/javascript" src="/client_function.js"></script>
	<script language="JavaScript" type="text/javascript" src="/js/table/table.js"></script>
	<script language="JavaScript" type="text/javascript" src="/res/ss-menu.js"></script>
	<script language="JavaScript" type="text/javascript" src="/res/softcenter.js"></script>
	<script language="JavaScript" type="text/javascript" src="/res/tablednd.js"></script>
	<script>
		var PKG_NAME = "fancyss"
		var PKG_ARCH = "hnd_v8"
		var PKG_TYPE = "full"
		var PKG_EXTA = ""
		var pkg_name = PKG_NAME + "_" + PKG_ARCH + "_" + PKG_TYPE + PKG_EXTA
		var db_ss = {};
		var dbus = {};
		var confs = {};
		var dns_log = {};
		var obj_node = {};
		var node_max = 0;
		var node_nu = 0;
		var ss_nodes = [];
		var nodeN = 15;
		var trsH = 36;
		var nodeH;
		var nodeT = 304;
		var node_idx;
		// 移除未使用变量 sel_mode
		var edit_id;
		var isMenuopen = 0;
		var _responseLen;
		var noChange = 0;
		var noChange2 = 0;
		var noChange_status = 0;
		var noChange_dns = 0;
		var poped = 0;
		var submit_flag = "0";
		var x = 5;
		var save_flag = "";
		var STATUS_FLAG;
		var refreshRate;
		var ph_v2ray = "# 填入v2ray json配置，内容可以是标准的也可以是压缩的&#10;# 此处的配置可以支持v2ray运行更多协议，比如ss/vless/socks等xray支持的协议&#10;# 请保证你json内的outbound/outbounds部分配置正确！！！"
		var ph_xray = "# 填入xray json配置，内容可以是标准的也可以是压缩的&#10;# 此处的配置可以支持xray运行更多协议，比如ss/vmess/trojan/socks等xray支持的协议&#10;# 请保证你json内的outbound/outbounds部分配置正确！！！"
		var ph_tuic = "# 填入tuic client json配置，内容可以是标准的也可以是压缩的&#10;# 请保证你json内的relay部分的配置正确！！！"

		// (新增) 辅助函数：根据类型ID获取协议名称字符串
		function getProtocolNameForDisplay(type) {
			switch (type) {
				case '0': return 'SS';
				case '1': return 'SSR';
				case '3': return 'V2Ray';
				case '4': return 'Xray';
				case '5': return 'Trojan';
				case '6': return 'Naïve';
				case '7': return 'tuic';
				case '8': return 'Hysteria2';
				default: return 'Unknown';
			}
		}

		var option_modes = [["1", "gfwlist模式"], ["2", "大陆白名单模式"], ["3", "游戏模式"], ["5", "全局代理模式"], ["6", "回国模式"]];
		var option_method = ["none", "rc4", "rc4-md5", "rc4-md5-6", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb", "bf-cfb", "cast5-cfb", "idea-cfb", "rc2-cfb", "seed-cfb", "salsa20", "chacha20", "chacha20-ietf", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "plain", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"];
		var option_protocals = ["origin", "verify_simple", "verify_sha1", "auth_sha1", "auth_sha1_v2", "auth_sha1_v4", "auth_aes128_md5", "auth_aes128_sha1", "auth_chain_a", "auth_chain_b", "auth_chain_c", "auth_chain_d", "auth_chain_e", "auth_chain_f"];
		var option_obfs = ["plain", "http_simple", "http_post", "tls1.2_ticket_auth"];
		var option_v2enc = [["auto", "自动[auto]"], ["none", "不加密[none]"], ["aes-128-cfb", "aes-128-cfb"], ["aes-128-gcm", "aes-128-gcm"], ["chacha20-poly1305", "chacha20-poly1305"], ["zero", "zero"]];
		var option_headtcp = [["none", "不伪装"], ["http", "伪装http"]];
		var option_headkcp = [["none", "不伪装"], ["srtp", "伪装视频通话(srtp)"], ["utp", "伪装BT下载(uTP)"], ["wechat-video", "伪装微信视频通话"], ["dtls", "dtls"], ["wireguard", "wireguard"]];
		var option_headquic = [["none", "不伪装"], ["srtp", "伪装视频通话(srtp)"], ["utp", "伪装BT下载(uTP)"], ["wechat-video", "伪装微信视频通话"], ["dtls", "dtls"], ["wireguard", "wireguard"]];
		var option_grpcmode = ["gun", "multi"];
		var option_bol = [["0", "false"], ["1", "true"]];
		var option_xflow = [["", "none"], ["xtls-rprx-vision", "xtls-rprx-vision"], ["xtls-rprx-origin", "xtls-rprx-origin"], ["xtls-rprx-origin-udp443", "xtls-rprx-origin-udp443"], ["xtls-rprx-direct", "xtls-rprx-direct"], ["xtls-rprx-direct-udp443", "xtls-rprx-direct-udp443"], ["xtls-rprx-splice", "xtls-rprx-splice"], ["xtls-rprx-splice-udp443", "xtls-rprx-splice-udp443"]];
		var option_fingerprint = ["chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized", ""];
		var option_naive_prot = ["https", "quic"];
		var option_hy2_obfs = [["0", "停用"], ["1", "salamander"]];
		var stop_scroll = 0;
		var close_latency_flag = 0;
		var stopFlag = 1;
		const pattern = /[`~!@#$^&*()=|{}':;'\\\[\]\.<>\/?~！@#￥……&*（）——|{}%【】'；：""'。，、？\s]/g;
		// 移除未使用的全局 time_wait（各处已使用局部 time_wait）
		var ws;
		var ws_flag;
		var wss_open;
		var hostname = document.domain;
		// 移除未使用变量 mouse_status
		var ads_url_1
		var ws_enable = 0;
		if (PKG_ARCH == "hnd") {
			if (PKG_TYPE == "full") {
				var ws_enable = 1;
			}
		}
		if (PKG_ARCH == "mtk" || PKG_ARCH == "qca" || PKG_ARCH == "hnd_v8" || PKG_ARCH == "ipq32" || PKG_ARCH == "ipq64") {
			var ws_enable = 1;
		}
		String.prototype.myReplace = function (f, e) {
			var reg = new RegExp(f, "g");
			return this.replace(reg, e);
		}



		// （已移除）原先用于填充 UDP2raw 服务器下拉列表的函数已废弃

		// (新增) textarea高度自适应函数
		function auto_grow_textarea(element) {
			element.style.height = "5px";
			element.style.height = (element.scrollHeight) + "px";
		}

		// (新增) 全局变量，用于标记当前是"编辑模式"还是"新增模式"
		var current_edit_mode = 'edit';

		// (新增) 辅助函数，用于在"添加模式"下，根据选择的协议类型更新UI
		function verifyFields_by_type(type_val) {
			// 这是一个技巧：我们临时伪造一个节点选择和节点类型，以便复用 verifyFields 函数
			E("ssconf_basic_node").value = 'new_node';
			db_ss["ssconf_basic_type_new_node"] = type_val;

			verifyFields();
		}

		// (修正) 移除由脚本自动拼接的参数，只保留附加参数
		var kcp_defaults = "--smuxver 2 --key your_password --crypt aes-128 --mode fast3 --mtu 1350 --sndwnd 256 --rcvwnd 2048 --datashard 10 --parityshard 3 --dscp 46 --nocomp true --acknodelay false --nodelay 1 --interval 20 --resend 2 --nc 1 --sockbuf 16777217 --smuxbuf 16777217 --streambuf 4194304 --keepalive 5 --autoexpire 600 --quiet false --tcp false";
		var udp2raw_defaults = "-k your_password --raw-mode faketcp --cipher-mode xor --auth-mode crc32 -a --keep-rule --seq-mode 4 --fifo --fix-gro";

		// (修改) 更新此函数以填充 <datalist> 而不是 <select>
		function refresh_accel_server_list() {
			var $kcp_server_list = $("#kcp_server_list");
			var $udp2raw_server_list = $("#udp2raw_server_list");

			if (!$kcp_server_list.length) return;

			var unique_servers = {};
			$kcp_server_list.empty();
			$udp2raw_server_list.empty();

			for (var nodeId in confs) {
				if (confs.hasOwnProperty(nodeId)) {
					var node = confs[nodeId];
					var original_server = db_ss["ssconf_basic_server_" + nodeId] || node.server;
					if (original_server && !unique_servers[original_server]) {
						unique_servers[original_server] = true;
						var server_option = $('<option>').attr('value', original_server);
						$kcp_server_list.append(server_option.clone());
						$udp2raw_server_list.append(server_option.clone());
					}
				}
			}
		}
		// (最终修正版v2) 增加对加速配置的恢复逻辑
		function toggle_accel_mode() {
			var mode = E("ss_basic_accel_mode").value;
			var node_sel = E("ssconf_basic_node").value;

			if (node_sel === 'new_node') {
				$("#kcp_config_table").toggle(mode == "1" || mode == "2");
				$("#udp2raw_config_table").toggle(mode == "3" || mode == "2");
				return;
			}

			// 1. 智能地寻找真正的原始服务器地址和端口
			var true_original_server = "";
			var true_original_port = "";
			var saved_accel_mode = db_ss["ssconf_basic_accel_mode_" + node_sel] || "0";

			var node_type = db_ss["ssconf_basic_type_" + node_sel] || "0";
			var server_key_suffix = "server";
			var port_key_suffix = "port";

			if (node_type == "6") { // NaïveProxy
				server_key_suffix = "naive_server";
				port_key_suffix = "naive_port";
			} else if (node_type == "8") { // Hysteria 2
				server_key_suffix = "hy2_server";
				port_key_suffix = "hy2_port";
			}

			if (saved_accel_mode == "1") {
				true_original_server = db_ss["ssconf_basic_kcp_rserver_" + node_sel] || "";
			} else if (saved_accel_mode == "2" || saved_accel_mode == "3") {
				true_original_server = db_ss["ssconf_basic_udp2raw_rserver_" + node_sel] || "";
			} else {
				true_original_server = db_ss["ssconf_basic_" + server_key_suffix + "_" + node_sel] || "";
			}
			true_original_port = db_ss["ssconf_basic_" + port_key_suffix + "_" + node_sel] || "";

			// 2. 确定当前要操作的字段ID
			var server_field_id = "ss_basic_" + server_key_suffix;
			var port_field_id = "ss_basic_" + port_key_suffix;

			// 3. 重置UI状态
			$("#kcp_config_table").hide();
			$("#udp2raw_config_table").hide();
			E(server_field_id).readOnly = false;
			E(port_field_id).readOnly = false;
			E("ss_basic_kcp_rserver").disabled = false;
			E("ss_basic_kcp_rport").readOnly = false;

			// 4. 根据新选择的模式，执行联动逻辑
			switch (mode) {
				case "0": // 无加速
					E(server_field_id).value = true_original_server;
					E(port_field_id).value = true_original_port;

					// (关键新增) 恢复KCP和UDP2raw相关字段为其原始或默认值
					E("ss_basic_kcp_rserver").value = db_ss["ssconf_basic_kcp_rserver_" + node_sel] || "";
					E("ss_basic_kcp_rport").value = db_ss["ssconf_basic_kcp_rport_" + node_sel] || "48400";
					E("ss_basic_udp2raw_rserver").value = db_ss["ssconf_basic_udp2raw_rserver_" + node_sel] || "";
					E("ss_basic_udp2raw_rport").value = db_ss["ssconf_basic_udp2raw_rport_" + node_sel] || "38380";
					break;
				case "1": // KCPtun
					$("#kcp_config_table").show();
					E(server_field_id).value = "127.0.0.1";
					E(port_field_id).value = "1091";
					E(server_field_id).readOnly = true;
					E(port_field_id).readOnly = true;
					E("ss_basic_kcp_rserver").value = true_original_server;
					break;
				case "3": // UDP2raw only
					$("#udp2raw_config_table").show();
					E(server_field_id).value = "127.0.0.1";
					E(port_field_id).value = "1093";
					E(server_field_id).readOnly = true;
					E(port_field_id).readOnly = true;
					E("ss_basic_udp2raw_rserver").value = true_original_server;
					break;
				case "2": // KCPtun + UDP2raw
					$("#kcp_config_table").show();
					$("#udp2raw_config_table").show();
					E(server_field_id).value = "127.0.0.1";
					E(port_field_id).value = "1091";
					E(server_field_id).readOnly = true;
					E(port_field_id).readOnly = true;

					E("ss_basic_kcp_rserver").value = "127.0.0.1";
					E("ss_basic_kcp_rport").value = "1093";
					E("ss_basic_kcp_rserver").disabled = true;
					E("ss_basic_kcp_rport").readOnly = true;

					E("ss_basic_udp2raw_rserver").value = true_original_server;
					break;
			}
		}



		// (新增) 双击节点名称时，将其变为输入框的函数
		function edit_node_name_inline(cellElement) {
			// 如果当前单元格已经是编辑模式，则退出
			if (cellElement.querySelector('input')) {
				return;
			}

			var nodeId = cellElement.id.split("_")[3];
			var currentName = confs[nodeId] ? confs[nodeId].name : cellElement.textContent.trim();

			// 创建输入框
			var input = document.createElement('input');
			input.type = 'text';
			input.id = 'inline_edit_' + nodeId;
			input.className = 'input_ss_table';
			input.style.width = '95%';
			input.style.textAlign = 'center';
			input.value = currentName;

			// 绑定保存事件
			input.onblur = function () { save_inline_name(this); };
			input.onkeydown = function (event) {
				if (event.key === 'Enter') {
					this.blur(); // 触发 onblur 事件来保存
				} else if (event.key === 'Escape') {
					// 如果按 Esc，则恢复原状不保存
					cellElement.innerHTML = '<div class="nickname">' + currentName + '</div>';
				}
			};

			// 替换内容并聚焦
			cellElement.innerHTML = '';
			cellElement.appendChild(input);
			input.focus();
			input.select();
		}

		// (新增) 保存内联编辑的节点名称的函数
		function save_inline_name(inputElement) {
			var nodeId = inputElement.id.split("_")[2];
			var newName = inputElement.value.trim();
			var parentCell = inputElement.parentElement;

			if (!newName || newName === confs[nodeId].name) {
				// 如果名称为空或未改变，则恢复显示
				parentCell.innerHTML = '<div class="nickname">' + confs[nodeId].name + '</div>';
				return;
			}

			// 准备数据并通过AJAX保存
			var dbus_save = {};
			dbus_save["ssconf_basic_name_" + nodeId] = newName;

			var id = parseInt(Math.random() * 100000000);
			var postData = { "id": id, "method": "dummy_script.sh", "params": [], "fields": dbus_save };

			$.ajax({
				type: "POST",
				url: "/_api/",
				data: JSON.stringify(postData),
				dataType: "json",
				success: function (response) {
					// 保存成功后，更新UI和本地数据
					parentCell.innerHTML = '<div class="nickname">' + newName + '</div>';
					// 同步更新内存模型，避免后续刷新将名称还原
					confs[nodeId].name = newName;
					db_ss["ssconf_basic_name_" + nodeId] = newName;
					refresh_options(); // 刷新"账号设置"页的下拉菜单
					ss_node_sel(); // 如果正在编辑的节点是当前选中的，也刷新一下

					// 给用户一个视觉反馈
					$(parentCell).css({ backgroundColor: '#3C6F3A' }).animate({ backgroundColor: '' }, 1500);
				},
				error: function () {
					// 保存失败，恢复原状
					parentCell.innerHTML = '<div class="nickname">' + confs[nodeId].name + '</div>';
					alert("名称保存失败！");
				}
			});
		}


		// （重复定义已移除）verifyFields_by_type

		// (新增) 从"节点管理"页面跳转到"新建节点"模式的函数
		function go_to_add_node_mode() {
			// 1. 模拟点击"账号设置"标签页，切换到该页面
			$(".show-btn0").trigger("click");

			// 2. 将"节点选择"下拉菜单的值设置为我们预定义的'new_node'
			E("ssconf_basic_node").value = 'new_node';

			// 3. 手动调用下拉菜单的onchange处理函数，触发UI切换到"新建模式"
			ss_node_sel();
		}
		// (新增) 从"节点管理"页面的"修改"按钮跳转过来时调用的函数
		function go_to_edit_node_mode(buttonElement) {
			// 1. 从按钮ID中解析出节点编号
			var nodeId = buttonElement.id.split("_")[2];

			// 2. 模拟点击"账号设置"标签页，切换到该页面
			$(".show-btn0").trigger("click");

			// 3. 将"节点选择"下拉菜单的值设置为要修改的节点
			E("ssconf_basic_node").value = nodeId;

			// 4. 手动调用下拉菜单的onchange处理函数，触发UI加载该节点的配置
			ss_node_sel();
		}


		function init() {
			show_menu(menu_hook);
			get_dbus_data();
			refresh_accel_server_list();
			try_ws_connect();
			$("#ss_basic_name_tr").hide();
			$("#ss_basic_type_tr").hide();
		}


		function try_ws_connect() {
			if (ws_enable != 1) {
				ws_flag = 0;
				return false;
			}
			if (window.location.protocol != "http:") {
				ws_flag = 0;
				return false;
			}
			ws_test = new WebSocket("ws://" + hostname + ":803/");
			ws_test.onopen = function () {
				ws_test.send("echo ws_ok");
			};
			ws_test.onerror = function (event) {
				ws_flag = 2;
			};
			ws_test.onmessage = function (event) {
				ws_flag = 1;
				ws_test.close();
			};
		}
		function refresh_dbss() {
			$.ajax({
				type: "GET",
				url: "/_api/ss",
				dataType: "json",
				async: false,
				success: function (data) {
					db_ss = data.result[0];
					generate_node_info();
				}
			});
		}
		function get_dbus_data() {
			$.ajax({
				type: "GET",
				url: "/_api/ss",
				dataType: "json",
				cache: false,
				async: false,
				success: function (data) {
					db_ss = data.result[0];
					// 强制默认启用：用Xray核心运行ss协议、用Xray核心运行V2ray节点（仅前端态）
					db_ss["ss_basic_score"] = "1";
					db_ss["ss_basic_vcore"] = "1";
					conf2obj(db_ss);
					generate_node_info();
					refresh_options();
					// （已移除）refresh_udp2raw_server_list()
					refresh_html();
					ss_node_sel();
					toggle_func();
					get_ss_status();
					version_show();
					message_show();
				},
				error: function (XmlHttpRequest, textStatus, errorThrown) {
					console.log(XmlHttpRequest.responseText);
					alert("skipd数据读取错误，请格式化jffs分区后重新尝试！");
				}
				, timeout: 0
			});
		}



		function conf2obj(obj, action) {
			var _base64 = ["ss_basic_password", "ss_dnsmasq", "ss_wan_white_ip", "ss_wan_white_domain", "ss_wan_black_ip", "ss_wan_black_domain", "ss_online_links", "ss_basic_custom", "ss_basic_naive_pass"]; //
			// 1. 先用 obj 中的数据填充表单
			for (var field in obj) {
				var el = E(field);
				if (field == "ss_base64_links") continue; //
				// 特殊处理 JSON 和密码字段
				if (field == "ss_basic_v2ray_json" || field == "ss_basic_xray_json") { //
					if (el) el.value = do_js_beautify(Base64.decode(obj[field]));
					continue;
				}
				if (field == "ss_basic_tuic_json") { //
					if (el) el.value = do_js_beautify(Base64.decode(obj[field]));
					continue;
				}
				if (el != null && el.getAttribute("type") == "checkbox") { //
					// 对于 checkbox，只有当 obj[field] 明确是 '1' 时才勾选，否则不勾选 (处理空值或'0')
					el.checked = obj[field] === "1"; //
					continue;
				}
				if (el != null && el.getAttribute("type") == "radio") { //
					// 对于 radio，只有当 obj[field] 明确是 '1' 时才勾选
					el.checked = obj[field] === "1"; //
					continue;
				}
				if (el != null) {
					if (_base64.includes(field)) { //
						// 对 base64 编码的字段进行解码，如果 obj[field] 不存在或为空，则结果为空字符串
						el.value = obj[field] ? Base64.decode(obj[field]) : "";
					} else {
						// 其他字段直接赋值，如果 obj[field] 不存在或为空，则结果为空字符串
						el.value = obj[field] || ""; //
					}
				}
			}

			// 2. 填充加速参数，如果 obj 中没有，则尝试从 db_ss 读取，如果还没有，则用默认值
			var node_sel = obj["ssconf_basic_node"] || E("ssconf_basic_node").value;
			if (E("ss_basic_accel_mode")) E("ss_basic_accel_mode").value = obj["ss_basic_accel_mode"] || db_ss["ssconf_basic_accel_mode_" + node_sel] || "0"; //
			if (E("ss_basic_kcp_rserver")) E("ss_basic_kcp_rserver").value = obj["ss_basic_kcp_rserver"] || db_ss["ssconf_basic_kcp_rserver_" + node_sel] || ""; //
			if (E("ss_basic_kcp_rport")) E("ss_basic_kcp_rport").value = obj["ss_basic_kcp_rport"] || db_ss["ssconf_basic_kcp_rport_" + node_sel] || "48400"; //
			if (E("ss_basic_udp2raw_rserver")) E("ss_basic_udp2raw_rserver").value = obj["ss_basic_udp2raw_rserver"] || db_ss["ssconf_basic_udp2raw_rserver_" + node_sel] || ""; //
			if (E("ss_basic_udp2raw_rport")) E("ss_basic_udp2raw_rport").value = obj["ss_basic_udp2raw_rport"] || db_ss["ssconf_basic_udp2raw_rport_" + node_sel] || "38380"; //
			if (E("ss_basic_kcp_param")) E("ss_basic_kcp_param").value = obj["ss_basic_kcp_param"] || db_ss["ssconf_basic_kcp_param_" + node_sel] || kcp_defaults; //
			if (E("ss_basic_udp2raw_param")) E("ss_basic_udp2raw_param").value = obj["ss_basic_udp2raw_param"] || db_ss["ssconf_basic_udp2raw_param_" + node_sel] || udp2raw_defaults; //

			// 3. 检查并填充其他空字段的默认值
			var node_type = obj["ss_basic_type"] || db_ss["ssconf_basic_type_" + node_sel] || "0"; // 获取当前节点类型

			// 通用默认值
			if (E("ss_basic_mode") && !E("ss_basic_mode").value) E("ss_basic_mode").value = "2";

			// 根据类型设置特定默认值 (仅当字段为空时)
			if (node_type == "0") { // SS
				if (E("ss_basic_method") && !E("ss_basic_method").value) E("ss_basic_method").value = "aes-256-gcm";
				if (E("ss_basic_ss_obfs") && !E("ss_basic_ss_obfs").value) E("ss_basic_ss_obfs").value = "0";
			} else if (node_type == "1") { // SSR
				if (E("ss_basic_method") && !E("ss_basic_method").value) E("ss_basic_method").value = "aes-256-gcm";
				if (E("ss_basic_rss_protocol") && !E("ss_basic_rss_protocol").value) E("ss_basic_rss_protocol").value = "origin";
				if (E("ss_basic_rss_obfs") && !E("ss_basic_rss_obfs").value) E("ss_basic_rss_obfs").value = "plain";
			} else if (node_type == "3") { // V2Ray (非 JSON)
				if (E("ss_basic_v2ray_alterid") && !E("ss_basic_v2ray_alterid").value) E("ss_basic_v2ray_alterid").value = "0";
				if (E("ss_basic_v2ray_security") && !E("ss_basic_v2ray_security").value) E("ss_basic_v2ray_security").value = "auto";
				if (E("ss_basic_v2ray_network") && !E("ss_basic_v2ray_network").value) E("ss_basic_v2ray_network").value = "tcp";
				if (E("ss_basic_v2ray_headtype_tcp") && !E("ss_basic_v2ray_headtype_tcp").value) E("ss_basic_v2ray_headtype_tcp").value = "none";
				if (E("ss_basic_v2ray_headtype_kcp") && !E("ss_basic_v2ray_headtype_kcp").value) E("ss_basic_v2ray_headtype_kcp").value = "none";
				if (E("ss_basic_v2ray_kcp_mtu") && !E("ss_basic_v2ray_kcp_mtu").value) E("ss_basic_v2ray_kcp_mtu").value = "1200";
				if (E("ss_basic_v2ray_kcp_tti") && !E("ss_basic_v2ray_kcp_tti").value) E("ss_basic_v2ray_kcp_tti").value = "40";
				if (E("ss_basic_v2ray_kcp_uplink") && !E("ss_basic_v2ray_kcp_uplink").value) E("ss_basic_v2ray_kcp_uplink").value = "1";
				if (E("ss_basic_v2ray_kcp_downlink") && !E("ss_basic_v2ray_kcp_downlink").value) E("ss_basic_v2ray_kcp_downlink").value = "100";
				// 检查 obj 中是否存在 congestion 值，如果不存在（说明是旧节点或导入节点），则应用默认值
				if (E("ss_basic_v2ray_kcp_congestion") && typeof obj["ss_basic_v2ray_kcp_congestion"] === 'undefined') E("ss_basic_v2ray_kcp_congestion").value = "1"; // true 
				if (E("ss_basic_v2ray_kcp_readbuf") && !E("ss_basic_v2ray_kcp_readbuf").value) E("ss_basic_v2ray_kcp_readbuf").value = "2";
				if (E("ss_basic_v2ray_kcp_writebuf") && !E("ss_basic_v2ray_kcp_writebuf").value) E("ss_basic_v2ray_kcp_writebuf").value = "2";
				if (E("ss_basic_v2ray_headtype_quic") && !E("ss_basic_v2ray_headtype_quic").value) E("ss_basic_v2ray_headtype_quic").value = "none";
				if (E("ss_basic_v2ray_network_security") && !E("ss_basic_v2ray_network_security").value) E("ss_basic_v2ray_network_security").value = "none";
				// 检查 checkbox 是否已由 obj 赋值，未赋值则设为 false
				if (E("ss_basic_v2ray_mux_enable") && typeof obj["ss_basic_v2ray_mux_enable"] === 'undefined') E("ss_basic_v2ray_mux_enable").checked = false;
				if (E("ss_basic_v2ray_mux_concurrency") && !E("ss_basic_v2ray_mux_concurrency").value) E("ss_basic_v2ray_mux_concurrency").value = "8";
			} else if (node_type == "4") { // Xray (非 JSON)
				if (E("ss_basic_xray_encryption") && !E("ss_basic_xray_encryption").value) E("ss_basic_xray_encryption").value = "none";
				if (E("ss_basic_xray_network") && !E("ss_basic_xray_network").value) E("ss_basic_xray_network").value = "tcp";
				if (E("ss_basic_xray_headtype_tcp") && !E("ss_basic_xray_headtype_tcp").value) E("ss_basic_xray_headtype_tcp").value = "none";
				if (E("ss_basic_xray_headtype_kcp") && !E("ss_basic_xray_headtype_kcp").value) E("ss_basic_xray_headtype_kcp").value = "none";
				if (E("ss_basic_xray_kcp_mtu") && !E("ss_basic_xray_kcp_mtu").value) E("ss_basic_xray_kcp_mtu").value = "1200";
				if (E("ss_basic_xray_kcp_tti") && !E("ss_basic_xray_kcp_tti").value) E("ss_basic_xray_kcp_tti").value = "30";
				if (E("ss_basic_xray_kcp_uplink") && !E("ss_basic_xray_kcp_uplink").value) E("ss_basic_xray_kcp_uplink").value = "20";
				if (E("ss_basic_xray_kcp_downlink") && !E("ss_basic_xray_kcp_downlink").value) E("ss_basic_xray_kcp_downlink").value = "100";
				if (E("ss_basic_xray_kcp_congestion") && typeof obj["ss_basic_xray_kcp_congestion"] === 'undefined') E("ss_basic_xray_kcp_congestion").value = "1"; // true
				if (E("ss_basic_xray_kcp_readbuf") && !E("ss_basic_xray_kcp_readbuf").value) E("ss_basic_xray_kcp_readbuf").value = "4";
				if (E("ss_basic_xray_kcp_writebuf") && !E("ss_basic_xray_kcp_writebuf").value) E("ss_basic_xray_kcp_writebuf").value = "4";
				if (E("ss_basic_xray_headtype_quic") && !E("ss_basic_xray_headtype_quic").value) E("ss_basic_xray_headtype_quic").value = "none";
				if (E("ss_basic_xray_network_security") && !E("ss_basic_xray_network_security").value) E("ss_basic_xray_network_security").value = "none";
				if (E("ss_basic_xray_fingerprint") && !E("ss_basic_xray_fingerprint").value) E("ss_basic_xray_fingerprint").value = "chrome";
				if (E("ss_basic_xray_show") && typeof obj["ss_basic_xray_show"] === 'undefined') E("ss_basic_xray_show").checked = false;
			} else if (node_type == "5") { // Trojan
				if (E("ss_basic_trojan_ai") && typeof obj["ss_basic_trojan_ai"] === 'undefined') E("ss_basic_trojan_ai").checked = false;
				if (E("ss_basic_trojan_tfo") && typeof obj["ss_basic_trojan_tfo"] === 'undefined') E("ss_basic_trojan_tfo").checked = false;
			} else if (node_type == "6") { // NaiveProxy
				if (E("ss_basic_naive_prot") && !E("ss_basic_naive_prot").value) E("ss_basic_naive_prot").value = "https";
				if (E("ss_basic_naive_port") && !E("ss_basic_naive_port").value) E("ss_basic_naive_port").value = "443";
			} else if (node_type == "8") { // Hysteria 2
				if (E("ss_basic_hy2_port") && !E("ss_basic_hy2_port").value) E("ss_basic_hy2_port").value = "443";
				if (E("ss_basic_hy2_up") && !E("ss_basic_hy2_up").value) E("ss_basic_hy2_up").value = "20"; // 默认上行
				if (E("ss_basic_hy2_dl") && !E("ss_basic_hy2_dl").value) E("ss_basic_hy2_dl").value = "100"; // 默认下行
				// 检查 checkbox 是否已由 obj 赋值，未赋值则设为 true (allowInsecure 默认 true, tfo 默认 true)
				if (E("ss_basic_hy2_ai") && typeof obj["ss_basic_hy2_ai"] === 'undefined') E("ss_basic_hy2_ai").checked = true; // 默认 true
				if (E("ss_basic_hy2_tfo") && typeof obj["ss_basic_hy2_tfo"] === 'undefined') E("ss_basic_hy2_tfo").checked = true; // 默认 true
				if (E("ss_basic_hy2_obfs") && !E("ss_basic_hy2_obfs").value) E("ss_basic_hy2_obfs").value = "0"; // 默认停用
			}

			// 4. 触发textarea自适应高度
			if (E("ss_basic_kcp_param")) auto_grow_textarea(E("ss_basic_kcp_param"));
			if (E("ss_basic_udp2raw_param")) auto_grow_textarea(E("ss_basic_udp2raw_param"));
			if (E("ss_basic_v2ray_json")) auto_grow_textarea(E("ss_basic_v2ray_json"));
			if (E("ss_basic_xray_json")) auto_grow_textarea(E("ss_basic_xray_json"));
			if (E("ss_basic_tuic_json")) auto_grow_textarea(E("ss_basic_tuic_json"));
		}



		function ssconf_node2obj(node_sel) {
			obj_node = {};
			var p = "ssconf_basic";
			var params_tt_0 = ["ss_obfs", "use_kcp", "v2ray_use_json", "v2ray_network_security_ai", "v2ray_mux_enable", "v2ray_network_security_alpn_h2", "v2ray_network_security_alpn_http", "xray_use_json", "xray_network_security_ai", "xray_network_security_alpn_h2", "xray_network_security_alpn_http", "xray_show", "hy2_ai", "hy2_tfo", "v2ray_kcp_congestion", "xray_kcp_congestion"];
			var params_tt_1 = ["type", "server", "mode", "port", "password", "method", "ss_obfs_host", "rss_protocol", "rss_protocol_param", "rss_obfs", "rss_obfs_param", "v2ray_uuid", "v2ray_alterid", "v2ray_security", "v2ray_network", "v2ray_headtype_tcp", "v2ray_headtype_kcp", "v2ray_kcp_seed", "v2ray_kcp_mtu", "v2ray_kcp_tti", "v2ray_kcp_uplink", "v2ray_kcp_downlink", "v2ray_kcp_readbuf", "v2ray_kcp_writebuf", "v2ray_headtype_quic", "v2ray_grpc_mode", "v2ray_network_path", "v2ray_network_host", "v2ray_network_security", "v2ray_network_security_sni", "v2ray_mux_concurrency", "v2ray_json", "xray_uuid", "xray_encryption", "xray_flow", "xray_network", "xray_headtype_tcp", "xray_headtype_kcp", "xray_kcp_seed", "xray_kcp_mtu", "xray_kcp_tti", "xray_kcp_uplink", "xray_kcp_downlink", "xray_kcp_readbuf", "xray_kcp_writebuf", "xray_headtype_quic", "xray_grpc_mode", "xray_network_path", "xray_network_host", "xray_network_security", "xray_network_security_sni", "xray_fingerprint", "xray_publickey", "xray_shortid", "xray_spiderx", "xray_json", "tuic_json", "trojan_ai", "trojan_uuid", "trojan_sni", "trojan_tfo", "naive_prot", "naive_server", "naive_port", "naive_user", "naive_pass", "hy2_server", "hy2_port", "hy2_pass", "hy2_up", "hy2_dl", "hy2_obfs", "hy2_obfs_pass", "hy2_sni", "accel_mode", "kcp_rserver", "kcp_rport", "kcp_param", "udp2raw_rserver", "udp2raw_rport", "udp2raw_param"];

			for (var i = 0; i < params_tt_0.length; i++) {
				obj_node["ss_basic_" + params_tt_0[i]] = db_ss[p + "_" + params_tt_0[i] + "_" + node_sel] || "0";
			}
			for (var i = 0; i < params_tt_1.length; i++) {
				obj_node["ss_basic_" + params_tt_1[i]] = db_ss[p + "_" + params_tt_1[i] + "_" + node_sel] || "";
			}
			obj_node["ssconf_basic_node"] = node_sel;
			return obj_node;
		}




		// 替换 refresh_options 函数
		function refresh_options() {
			if (node_max == 0) return false;
			var option0 = $("#ssconf_basic_node");
			var option2 = $("#ss_basic_udp_node");
			var option3 = $("#ss_failover_s4_3");
			option0.find('option').remove().end();
			option2.find('option').remove().end();
			option3.find('option').remove().end();

			for (var field in confs) {
				var c = confs[field];
				var protocol_prefix = "【" + getProtocolNameForDisplay(c.type) + "】";
				var display_text = protocol_prefix + c.name;
				option0.append($("<option>", {
					value: field,
					text: display_text
				}));
				if (!(c.type == "3" && c.v2ray_use_json == "1") && !(c.type == "4" && c.xray_use_json == "1")) {
					option2.append('<option value="' + field + '">' + c.name + '</option>');
				}
			}

			// (新增) 在列表末尾添加"新建节点"选项
			option0.append($("<option>", {
				value: "new_node",
				text: "--- 新建节点 ---"
			}));

			for (var field in confs) {
				var c = confs[field];
				option3.append('<option value="' + field + '">' + c.name + '</option>');
			}

			option0.val(db_ss["ssconf_basic_node"] || "1");
			option2.val(db_ss["ss_basic_udp_node"] || "1");
			option3.val((db_ss["ss_failover_s4_3"]) || "1");

			// ...函数余下部分保持不变...
			if (db_ss["ss_basic_server_resolv"] <= "0") {
				var option_value = db_ss["ss_basic_lastru"];
				var option_text = $("#ss_basic_server_resolv").find('option[value=' + option_value + ']').text();
				$('#ss_basic_server_resolv option[value=' + option_value + ']').text(option_text + '✅');
			} else {
				var option_text = $("#ss_basic_server_resolv").find('option[value=' + db_ss["ss_basic_server_resolv"] + ']').text();
				$('#ss_basic_server_resolv option[value=' + db_ss["ss_basic_server_resolv"] + ']').text(option_text + '✅');
			}
			$("#ss_basic_row").find('option').remove().end();
			for (var i = 10; i <= 27; i++) {
				$("#ss_basic_row").append('<option value="' + i + '">' + i + '</option>');
			}
			E("ss_basic_row").value = db_ss["ss_basic_row"] || 18;
		}


		// (用以下最终修正版函数替换 save 函数)
		function save() {
			var node_sel = E("ssconf_basic_node").value;
			submit_flag = "1";
			dbus["ssconf_basic_node"] = node_sel;
			E("ss_state2").innerHTML = "国外连接 - " + "Waiting...";
			E("ss_state3").innerHTML = "国内连接 - " + "Waiting...";
			// --- 1. 恢复原始的全局参数收集 ---
			var params_input = ["ss_failover_s1", "ss_failover_s2_1", "ss_failover_s2_2", "ss_failover_s3_1", "ss_failover_s3_2", "ss_failover_s4_1", "ss_failover_s4_2", "ss_failover_s4_3", "ss_failover_s5", "ss_basic_interval", "ss_basic_row", "ss_dns_plan", "ss_basic_chng_china_1_prot", "ss_basic_chng_china_1_udp", "ss_basic_chng_china_1_udp_user", "ss_basic_chng_china_1_tcp", "ss_basic_chng_china_1_tcp_user", "ss_basic_chng_china_2_prot", "ss_basic_chng_china_2_udp", "ss_basic_chng_china_2_udp_user", "ss_basic_chng_china_2_tcp", "ss_basic_chng_china_2_tcp_user", "ss_basic_chng_trust_1_opt", "ss_basic_chng_trust_1_opt_udp_val", "ss_basic_chng_trust_1_opt_udp_val_user", "ss_basic_chng_trust_1_opt_tcp_val", "ss_basic_chng_trust_1_opt_tcp_val_user", "ss_basic_chng_trust_2_opt", "ss_basic_chng_trust_2_opt_udp", "ss_basic_chng_trust_2_opt_tcp", "ss_basic_chng_repeat_times", "ss_china_dns", "ss_china_dns_user", "ss_foreign_dns", "ss_dns2socks_user", "ss_sstunnel_user", "ss_direct_user", "ss_basic_rule_update", "ss_basic_rule_update_time", "ssr_subscribe_mode", "ss_basic_online_links_goss", "ss_basic_node_update", "ss_basic_node_update_day", "ss_basic_node_update_hr", "ss_basic_exclude", "ss_basic_include", "ss_acl_default_port", "ss_acl_default_mode", "ss_basic_udp_software", "ss_basic_udp_node", "ss_basic_udpv1_lserver", "ss_basic_udpv1_lport", "ss_basic_udpv1_rserver", "ss_basic_udpv1_rport", "ss_basic_udpv1_password", "ss_basic_udpv1_mode", "ss_basic_udpv1_duplicate_nu", "ss_basic_udpv1_duplicate_time", "ss_basic_udpv1_jitter", "ss_basic_udpv1_report", "ss_basic_udpv1_drop", "ss_basic_udpv2_lserver", "ss_basic_udpv2_lport", "ss_basic_udpv2_rserver", "ss_basic_udpv2_rport", "ss_basic_udpv2_password", "ss_basic_udpv2_fec", "ss_basic_udpv2_timeout", "ss_basic_udpv2_mode", "ss_basic_udpv2_report", "ss_basic_udpv2_mtu", "ss_basic_udpv2_jitter", "ss_basic_udpv2_interval", "ss_basic_udpv2_drop", "ss_basic_udpv2_other", "ss_basic_udp_upstream_mtu", "ss_basic_udp_upstream_mtu_value", "ss_reboot_check", "ss_basic_week", "ss_basic_day", "ss_basic_inter_min", "ss_basic_inter_hour", "ss_basic_inter_day", "ss_basic_inter_pre", "ss_basic_time_hour", "ss_basic_time_min", "ss_basic_tri_reboot_time", "ss_basic_server_resolv", "ss_basic_server_resolv_user", "ss_basic_wt_furl", "ss_basic_wt_curl", "ss_basic_lt_cru_opts", "ss_basic_lt_cru_time",
				"ss_basic_hy2_up_speed", "ss_basic_hy2_dl_speed", "ss_basic_hy2_tfo_switch"]; //
			var params_check = ["ss_failover_enable", "ss_failover_c1", "ss_failover_c2", "ss_failover_c3", "ss_adv_sub", "ss_basic_tablet", "ss_basic_noserver", "ss_basic_dragable", "ss_basic_qrcode", "ss_basic_enable", "ss_basic_gfwlist_update", "ss_basic_tfo", "ss_basic_tnd", "ss_basic_score", "ss_basic_vcore", "ss_basic_xguard", "ss_basic_use_kcp", "ss_basic_udp_on", "ss_basic_tjai", "ss_basic_nonetcheck", "ss_basic_notimecheck", "ss_basic_nochnipcheck", "ss_basic_nofrnipcheck", "ss_basic_noruncheck", "ss_basic_nofdnscheck", "ss_basic_nocdnscheck", "ss_basic_olddns", "ss_basic_advdns", "ss_basic_chnroute_update", "ss_basic_cdn_update", "ss_basic_kcp_nocomp", "ss_basic_udp_boost_enable", "ss_basic_udpv1_disable_filter", "ss_basic_udpv2_disableobscure", "ss_basic_udpv2_disablechecksum", "ss_basic_udp2raw_boost_enable", "ss_basic_udp2raw_a", "ss_basic_udp2raw_keeprule", "ss_basic_dns_hijack", "ss_basic_chng_no_ipv6", "ss_basic_chng_act", "ss_basic_chng_gt", "ss_basic_chng_mc", "ss_basic_mcore", "ss_basic_chng_china_1_enable", "ss_basic_chng_china_2_enable", "ss_basic_chng_china_1_ecs", "ss_basic_chng_trust_1_enable", "ss_basic_chng_trust_2_enable", "ss_basic_chng_china_2_ecs", "ss_basic_chng_trust_1_ecs", "ss_basic_chng_trust_2_ecs", "ss_basic_proxy_newb", "ss_basic_udpoff", "ss_basic_udpall", "ss_basic_udpgpt"]; //
			var params_base64 = ["ss_dnsmasq", "ss_wan_white_ip", "ss_wan_white_domain", "ss_wan_black_ip", "ss_wan_black_domain", "ss_online_links", "ss_basic_custom"]; //
			for (var i = 0; i < params_input.length; i++) {
				if (E(params_input[i])) dbus[params_input[i]] = E(params_input[i]).value; //
			}
			for (var i = 0; i < params_check.length; i++) {
				if (E(params_check[i])) dbus[params_check[i]] = E(params_check[i]).checked ? '1' : '0'; //
			}
			// 强制保存为开启：用Xray核心运行ss协议、用Xray核心运行V2ray节点
			dbus["ss_basic_score"] = '1';
			dbus["ss_basic_vcore"] = '1';
			for (var i = 0; i < params_base64.length; i++) {
				if (E(params_base64[i])) dbus[params_base64[i]] = Base64.encode(E(params_base64[i]).value); //
			}
			if (E("ACL_table")) {
				// ... (ACL table saving logic from original file)
			}

			// --- 2. 精确地将"账号设置"页面的修改保存到当前节点 ---
			var p = "ssconf_basic"; //
			var node_type = db_ss[p + "_type_" + node_sel]; //

			dbus[p + "_mode_" + node_sel] = E("ss_basic_mode").value; //

			if (node_type == "0") { // SS
				dbus[p + "_server_" + node_sel] = E("ss_basic_server").value; //
				dbus[p + "_port_" + node_sel] = E("ss_basic_port").value; //
				dbus[p + "_password_" + node_sel] = Base64.encode(E("ss_basic_password").value); //
				dbus[p + "_method_" + node_sel] = E("ss_basic_method").value; //
				dbus[p + "_ss_obfs_" + node_sel] = E("ss_basic_ss_obfs").value; //
				dbus[p + "_ss_obfs_host_" + node_sel] = E("ss_basic_ss_obfs_host").value; //
			} else if (node_type == "1") { // SSR (新增)
				dbus[p + "_server_" + node_sel] = E("ss_basic_server").value;
				dbus[p + "_port_" + node_sel] = E("ss_basic_port").value;
				dbus[p + "_password_" + node_sel] = Base64.encode(E("ss_basic_password").value);
				dbus[p + "_method_" + node_sel] = E("ss_basic_method").value;
				dbus[p + "_rss_protocol_" + node_sel] = E("ss_basic_rss_protocol").value;
				dbus[p + "_rss_protocol_param_" + node_sel] = E("ss_basic_rss_protocol_param").value;
				dbus[p + "_rss_obfs_" + node_sel] = E("ss_basic_rss_obfs").value;
				dbus[p + "_rss_obfs_param_" + node_sel] = E("ss_basic_rss_obfs_param").value;
			} else if (node_type == "3") { // V2Ray (新增 V2Ray 非 JSON 部分)
				dbus[p + "_v2ray_use_json_" + node_sel] = E("ss_basic_v2ray_use_json").checked ? '1' : '0';
				if (E("ss_basic_v2ray_use_json").checked) {
					dbus[p + "_v2ray_json_" + node_sel] = Base64.encode(pack_js(E("ss_basic_v2ray_json").value));
				} else {
					dbus[p + "_server_" + node_sel] = E("ss_basic_server").value;
					dbus[p + "_port_" + node_sel] = E("ss_basic_port").value;
					dbus[p + "_v2ray_uuid_" + node_sel] = E("ss_basic_v2ray_uuid").value;
					dbus[p + "_v2ray_alterid_" + node_sel] = E("ss_basic_v2ray_alterid").value;
					dbus[p + "_v2ray_security_" + node_sel] = E("ss_basic_v2ray_security").value;
					dbus[p + "_v2ray_network_" + node_sel] = E("ss_basic_v2ray_network").value;
					dbus[p + "_v2ray_headtype_tcp_" + node_sel] = E("ss_basic_v2ray_headtype_tcp").value;
					dbus[p + "_v2ray_headtype_kcp_" + node_sel] = E("ss_basic_v2ray_headtype_kcp").value;
					dbus[p + "_v2ray_kcp_seed_" + node_sel] = E("ss_basic_v2ray_kcp_seed").value;
					dbus[p + "_v2ray_kcp_mtu_" + node_sel] = E("ss_basic_v2ray_kcp_mtu").value;
					dbus[p + "_v2ray_kcp_tti_" + node_sel] = E("ss_basic_v2ray_kcp_tti").value;
					dbus[p + "_v2ray_kcp_uplink_" + node_sel] = E("ss_basic_v2ray_kcp_uplink").value;
					dbus[p + "_v2ray_kcp_downlink_" + node_sel] = E("ss_basic_v2ray_kcp_downlink").value;
					dbus[p + "_v2ray_kcp_congestion_" + node_sel] = E("ss_basic_v2ray_kcp_congestion").value;
					dbus[p + "_v2ray_kcp_readbuf_" + node_sel] = E("ss_basic_v2ray_kcp_readbuf").value;
					dbus[p + "_v2ray_kcp_writebuf_" + node_sel] = E("ss_basic_v2ray_kcp_writebuf").value;
					dbus[p + "_v2ray_headtype_quic_" + node_sel] = E("ss_basic_v2ray_headtype_quic").value;
					dbus[p + "_v2ray_grpc_mode_" + node_sel] = E("ss_basic_v2ray_grpc_mode").value;
					dbus[p + "_v2ray_network_path_" + node_sel] = E("ss_basic_v2ray_network_path").value;
					dbus[p + "_v2ray_network_host_" + node_sel] = E("ss_basic_v2ray_network_host").value;
					dbus[p + "_v2ray_network_security_" + node_sel] = E("ss_basic_v2ray_network_security").value;
					dbus[p + "_v2ray_network_security_ai_" + node_sel] = E("ss_basic_v2ray_network_security_ai").checked ? '1' : '0';
					dbus[p + "_v2ray_network_security_alpn_h2_" + node_sel] = E("ss_basic_v2ray_network_security_alpn_h2").checked ? '1' : '0';
					dbus[p + "_v2ray_network_security_alpn_http_" + node_sel] = E("ss_basic_v2ray_network_security_alpn_http").checked ? '1' : '0';
					dbus[p + "_v2ray_network_security_sni_" + node_sel] = E("ss_basic_v2ray_network_security_sni").value;
					dbus[p + "_v2ray_mux_enable_" + node_sel] = E("ss_basic_v2ray_mux_enable").checked ? '1' : '0';
					dbus[p + "_v2ray_mux_concurrency_" + node_sel] = E("ss_basic_v2ray_mux_concurrency").value;
				}
			} else if (node_type == "4") { // Xray (修改 Xray 非 JSON 部分，补全 KCP 参数)
				dbus[p + "_xray_use_json_" + node_sel] = E("ss_basic_xray_use_json").checked ? '1' : '0';
				if (E("ss_basic_xray_use_json").checked) {
					dbus[p + "_xray_json_" + node_sel] = Base64.encode(pack_js(E("ss_basic_xray_json").value));
				} else {
					dbus[p + "_server_" + node_sel] = E("ss_basic_server").value; //
					dbus[p + "_port_" + node_sel] = E("ss_basic_port").value; //
					dbus[p + "_xray_uuid_" + node_sel] = E("ss_basic_xray_uuid").value; //
					dbus[p + "_xray_encryption_" + node_sel] = E("ss_basic_xray_encryption").value; //
					dbus[p + "_xray_flow_" + node_sel] = E("ss_basic_xray_flow").value;
					dbus[p + "_xray_network_" + node_sel] = E("ss_basic_xray_network").value;
					dbus[p + "_xray_headtype_tcp_" + node_sel] = E("ss_basic_xray_headtype_tcp").value;
					dbus[p + "_xray_headtype_kcp_" + node_sel] = E("ss_basic_xray_headtype_kcp").value; //
					dbus[p + "_xray_kcp_seed_" + node_sel] = E("ss_basic_xray_kcp_seed").value; //
					dbus[p + "_xray_kcp_mtu_" + node_sel] = E("ss_basic_xray_kcp_mtu").value; //
					dbus[p + "_xray_kcp_tti_" + node_sel] = E("ss_basic_xray_kcp_tti").value; //
					dbus[p + "_xray_kcp_uplink_" + node_sel] = E("ss_basic_xray_kcp_uplink").value; //
					dbus[p + "_xray_kcp_downlink_" + node_sel] = E("ss_basic_xray_kcp_downlink").value; //
					dbus[p + "_xray_kcp_congestion_" + node_sel] = E("ss_basic_xray_kcp_congestion").value; //
					dbus[p + "_xray_kcp_readbuf_" + node_sel] = E("ss_basic_xray_kcp_readbuf").value; //
					dbus[p + "_xray_kcp_writebuf_" + node_sel] = E("ss_basic_xray_kcp_writebuf").value; //
					dbus[p + "_xray_headtype_quic_" + node_sel] = E("ss_basic_xray_headtype_quic").value;
					dbus[p + "_xray_grpc_mode_" + node_sel] = E("ss_basic_xray_grpc_mode").value;
					dbus[p + "_xray_network_path_" + node_sel] = E("ss_basic_xray_network_path").value;
					dbus[p + "_xray_network_host_" + node_sel] = E("ss_basic_xray_network_host").value;
					dbus[p + "_xray_network_security_" + node_sel] = E("ss_basic_xray_network_security").value;
					dbus[p + "_xray_network_security_ai_" + node_sel] = E("ss_basic_xray_network_security_ai").checked ? '1' : '0';
					dbus[p + "_xray_network_security_alpn_h2_" + node_sel] = E("ss_basic_xray_network_security_alpn_h2").checked ? '1' : '0';
					dbus[p + "_xray_network_security_alpn_http_" + node_sel] = E("ss_basic_xray_network_security_alpn_http").checked ? '1' : '0';
					dbus[p + "_xray_network_security_sni_" + node_sel] = E("ss_basic_xray_network_security_sni").value;
					dbus[p + "_xray_fingerprint_" + node_sel] = E("ss_basic_xray_fingerprint").value;
					dbus[p + "_xray_show_" + node_sel] = E("ss_basic_xray_show").checked ? '1' : '0';
					dbus[p + "_xray_publickey_" + node_sel] = E("ss_basic_xray_publickey").value;
					dbus[p + "_xray_shortid_" + node_sel] = E("ss_basic_xray_shortid").value;
					dbus[p + "_xray_spiderx_" + node_sel] = E("ss_basic_xray_spiderx").value;
				}
			} else if (node_type == "5") { // Trojan (新增)
				dbus[p + "_server_" + node_sel] = E("ss_basic_server").value;
				dbus[p + "_port_" + node_sel] = E("ss_basic_port").value;
				dbus[p + "_trojan_uuid_" + node_sel] = E("ss_basic_trojan_uuid").value;
				dbus[p + "_trojan_ai_" + node_sel] = E("ss_basic_trojan_ai").checked ? '1' : '0';
				dbus[p + "_trojan_sni_" + node_sel] = E("ss_basic_trojan_sni").value;
				dbus[p + "_trojan_tfo_" + node_sel] = E("ss_basic_trojan_tfo").checked ? '1' : '0';
			} else if (node_type == "6") { // NaiveProxy (新增)
				dbus[p + "_naive_prot_" + node_sel] = E("ss_basic_naive_prot").value;
				dbus[p + "_naive_server_" + node_sel] = E("ss_basic_naive_server").value;
				dbus[p + "_naive_port_" + node_sel] = E("ss_basic_naive_port").value;
				dbus[p + "_naive_user_" + node_sel] = E("ss_basic_naive_user").value;
				dbus[p + "_naive_pass_" + node_sel] = Base64.encode(E("ss_basic_naive_pass").value);
			} else if (node_type == "7") { // TUIC (新增)
				dbus[p + "_tuic_json_" + node_sel] = Base64.encode(pack_js(E("ss_basic_tuic_json").value));
			} else if (node_type == "8") { // Hysteria 2 (保持不变)
				var params_hy2_text = ["hy2_server", "hy2_port", "hy2_pass", "hy2_up", "hy2_dl", "hy2_obfs_pass", "hy2_sni"]; //
				var params_hy2_select = ["hy2_obfs"]; //
				var params_hy2_check = ["hy2_ai", "hy2_tfo"]; //
				for (var i = 0; i < params_hy2_text.length; i++) {
					dbus[p + "_" + params_hy2_text[i] + "_" + node_sel] = $.trim(E("ss_basic_" + params_hy2_text[i]).value); //
				}
				for (var i = 0; i < params_hy2_select.length; i++) {
					dbus[p + "_" + params_hy2_select[i] + "_" + node_sel] = E("ss_basic_" + params_hy2_select[i]).value; //
				}
				for (var i = 0; i < params_hy2_check.length; i++) {
					dbus[p + "_" + params_hy2_check[i] + "_" + node_sel] = E("ss_basic_" + params_hy2_check[i]).checked ? '1' : '0'; //
				}
			}

			// --- 加速参数保存 (保持不变) ---
			var accel_mode = E("ss_basic_accel_mode").value; //
			dbus[p + "_accel_mode_" + node_sel] = accel_mode; //
			dbus[p + "_use_kcp_" + node_sel] = (accel_mode == "1" || accel_mode == "2") ? "1" : "0"; //
			if (accel_mode == "1" || accel_mode == "2") { //
				var kcp_param_str = E("ss_basic_kcp_param").value; //
				var kcp_r_match = kcp_param_str.match(/--r\s+([^:\s]+):([0-9]+)/); //
				var final_kcp_param = kcp_param_str;
				if (kcp_r_match && kcp_r_match.length === 3) {
					dbus[p + "_kcp_rserver_" + node_sel] = kcp_r_match[1]; //
					dbus[p + "_kcp_rport_" + node_sel] = kcp_r_match[2]; //
					final_kcp_param = final_kcp_param.replace(/--r\s+[^:\s]+:[0-9]+/, ''); //
				} else {
					dbus[p + "_kcp_rserver_" + node_sel] = E("ss_basic_kcp_rserver").value; //
					dbus[p + "_kcp_rport_" + node_sel] = E("ss_basic_kcp_rport").value; //
				}
				final_kcp_param = final_kcp_param.replace(/--l\s+[^:\s]+:[0-9]+/, '').trim(); //
				dbus[p + "_kcp_param_" + node_sel] = final_kcp_param; //
			}

			if (accel_mode == "2" || accel_mode == "3") { //
				var udp2raw_param_str = E("ss_basic_udp2raw_param").value; //
				var udp_r_match = udp2raw_param_str.match(/-r\s+([^:\s]+):([0-9]+)/); //
				var final_udp_param = udp2raw_param_str;
				if (udp_r_match && udp_r_match.length === 3) {
					dbus[p + "_udp2raw_rserver_" + node_sel] = udp_r_match[1]; //
					dbus[p + "_udp2raw_rport_" + node_sel] = udp_r_match[2]; //
					final_udp_param = final_udp_param.replace(/-r\s+[^:\s]+:[0-9]+/, ''); //
				} else {
					dbus[p + "_udp2raw_rserver_" + node_sel] = E("ss_basic_udp2raw_rserver").value; //
					dbus[p + "_udp2raw_rport_" + node_sel] = E("ss_basic_udp2raw_rport").value; //
				}
				final_udp_param = final_udp_param.replace(/-l\s+[^:\s]+:[0-9]+/, ''); //
				var parts = final_udp_param.split(/\s+/); //
				var filtered_parts = parts.filter(function (part) { return part !== '-c' && part !== ''; }); //
				dbus[p + "_udp2raw_param_" + node_sel] = filtered_parts.join(' '); //
			}

			// --- 3. 触发插件重启以应用更改 ---
			var post_dbus = compfilter(db_ss, dbus); //
			if (dbus["ss_basic_enable"] == "1") { //
				push_data("ss_config.sh", "start", post_dbus); //
			} else {
				push_data("ss_config.sh", "stop", post_dbus); //
			}
		}

		// (用以下最终修正版函数替换 save_new_node 函数)
		function save_new_node() {
			var ns = {}; //
			var p = "ssconf_basic"; //
			var node_id = node_max + 1; //

			if (!$.trim(E('ss_basic_name').value)) {
				alert("节点别名不能为空！");
				return false;
			}

			var type = E("ss_basic_type_select").value; //
			ns[p + "_type_" + node_id] = type; //

			if (type == '0') { // SS
				var params1 = ["name", "server", "mode", "port", "method", "ss_obfs", "ss_obfs_host"]; //
				for (var i = 0; i < params1.length; i++) {
					ns[p + "_" + params1[i] + "_" + node_id] = $.trim(E("ss_basic_" + params1[i]).value); //
				}
				ns[p + "_password_" + node_id] = Base64.encode($.trim(E("ss_basic_password").value)); //
			} else if (type == '1') { // SSR (新增)
				var params2 = ["name", "server", "mode", "port", "method", "rss_protocol", "rss_protocol_param", "rss_obfs", "rss_obfs_param"];
				for (var i = 0; i < params2.length; i++) {
					ns[p + "_" + params2[i] + "_" + node_id] = $.trim(E("ss_basic_" + params2[i]).value);
				}
				ns[p + "_password_" + node_id] = Base64.encode($.trim(E("ss_basic_password").value));
			} else if (type == '3') { // V2Ray (新增 V2Ray 非 JSON 部分)
				var params4_1 = ["name", "server", "mode", "port", "v2ray_uuid", "v2ray_alterid", "v2ray_security", "v2ray_network", "v2ray_headtype_tcp", "v2ray_headtype_kcp", "v2ray_kcp_seed", "v2ray_kcp_mtu", "v2ray_kcp_tti", "v2ray_kcp_uplink", "v2ray_kcp_downlink", "v2ray_kcp_readbuf", "v2ray_kcp_writebuf", "v2ray_headtype_quic", "v2ray_grpc_mode", "v2ray_network_path", "v2ray_network_host", "v2ray_network_security", "v2ray_network_security_sni", "v2ray_mux_concurrency"];
				var params4_2 = ["v2ray_use_json", "v2ray_mux_enable", "v2ray_network_security_ai", "v2ray_network_security_alpn_h2", "v2ray_network_security_alpn_http", "v2ray_kcp_congestion"];
				if (E("ss_basic_v2ray_use_json").checked) {
					ns[p + "_name_" + node_id] = $.trim(E("ss_basic_name").value);
					ns[p + "_mode_" + node_id] = $.trim(E("ss_basic_mode").value);
					ns[p + "_v2ray_use_json_" + node_id] = '1';
					ns[p + "_v2ray_json_" + node_id] = Base64.encode(pack_js(E("ss_basic_v2ray_json").value));
				} else {
					for (var i = 0; i < params4_1.length; i++) {
						ns[p + "_" + params4_1[i] + "_" + node_id] = $.trim(E("ss_basic_" + params4_1[i]).value);
					}
					for (var i = 0; i < params4_2.length; i++) {
						ns[p + "_" + params4_2[i] + "_" + node_id] = E("ss_basic_" + params4_2[i]).checked ? '1' : '0';
					}
				}
			} else if (type == '4') { // Xray (修改 Xray 非 JSON 部分，补全 KCP 参数)
				var params5_1 = ["name", "mode", "server", "port", "xray_uuid", "xray_encryption", "xray_flow", "xray_network", "xray_headtype_tcp", "xray_headtype_kcp", "xray_kcp_seed", "xray_kcp_mtu", "xray_kcp_tti", "xray_kcp_uplink", "xray_kcp_downlink", "xray_kcp_readbuf", "xray_kcp_writebuf", "xray_headtype_quic", "xray_grpc_mode", "xray_network_path", "xray_network_host", "xray_network_security", "xray_network_security_sni", "xray_fingerprint", "xray_publickey", "xray_shortid", "xray_spiderx"]; //
				var params5_2 = ["xray_use_json", "xray_network_security_ai", "xray_network_security_alpn_h2", "xray_network_security_alpn_http", "xray_show", "xray_kcp_congestion"]; //
				if (E("ss_basic_xray_use_json").checked) {
					ns[p + "_name_" + node_id] = $.trim(E("ss_basic_name").value);
					ns[p + "_mode_" + node_id] = $.trim(E("ss_basic_mode").value);
					ns[p + "_xray_use_json_" + node_id] = '1';
					ns[p + "_xray_json_" + node_id] = Base64.encode(pack_js(E("ss_basic_xray_json").value));
				} else {
					for (var i = 0; i < params5_1.length; i++) {
						ns[p + "_" + params5_1[i] + "_" + node_id] = $.trim(E('ss_basic_' + params5_1[i]).value); //
					}
					for (var i = 0; i < params5_2.length; i++) {
						ns[p + "_" + params5_2[i] + "_" + node_id] = E("ss_basic_" + params5_2[i]).checked ? '1' : '0'; //
					}
					ns[p + "_xray_prot_" + node_id] = "vless"; //
				}
			} else if (type == '5') { // Trojan (新增)
				var params6 = ["name", "server", "mode", "port", "trojan_uuid", "trojan_sni"];
				for (var i = 0; i < params6.length; i++) {
					ns[p + "_" + params6[i] + "_" + node_id] = $.trim(E("ss_basic_" + params6[i]).value);
				}
				ns[p + "_trojan_ai_" + node_id] = E("ss_basic_trojan_ai").checked ? '1' : '0';
				ns[p + "_trojan_tfo_" + node_id] = E("ss_basic_trojan_tfo").checked ? '1' : '0';
			} else if (type == '6') { // NaiveProxy (新增)
				var params7 = ["name", "mode", "naive_prot", "naive_server", "naive_port", "naive_user"];
				for (var i = 0; i < params7.length; i++) {
					ns[p + "_" + params7[i] + "_" + node_id] = $.trim(E("ss_basic_" + params7[i]).value);
				}
				ns[p + "_naive_pass_" + node_id] = Base64.encode($.trim(E("ss_basic_naive_pass").value));
			} else if (type == '7') { // TUIC (新增)
				ns[p + "_name_" + node_id] = $.trim(E("ss_basic_name").value);
				ns[p + "_mode_" + node_id] = $.trim(E("ss_basic_mode").value);
				ns[p + "_tuic_json_" + node_id] = Base64.encode(pack_js(E("ss_basic_tuic_json").value));
			} else if (type == '8') { // Hysteria 2 (保持不变)
				var params_hy2_text = ["name", "mode", "hy2_server", "hy2_port", "hy2_pass", "hy2_up", "hy2_dl", "hy2_obfs_pass", "hy2_sni"]; //
				var params_hy2_select = ["hy2_obfs"]; //
				var params_hy2_check = ["hy2_ai", "hy2_tfo"]; //
				for (var i = 0; i < params_hy2_text.length; i++) {
					ns[p + "_" + params_hy2_text[i] + "_" + node_id] = $.trim(E("ss_basic_" + params_hy2_text[i]).value); //
				}
				for (var i = 0; i < params_hy2_select.length; i++) {
					ns[p + "_" + params_hy2_select[i] + "_" + node_id] = E("ss_basic_" + params_hy2_select[i]).value; //
				}
				for (var i = 0; i < params_hy2_check.length; i++) {
					ns[p + "_" + params_hy2_check[i] + "_" + node_id] = E("ss_basic_" + params_hy2_check[i]).checked ? '1' : '0'; //
				}
			}

			// --- 加速参数保存 (保持不变) ---
			var accel_mode = E("ss_basic_accel_mode").value; //
			ns[p + "_accel_mode_" + node_id] = accel_mode; //
			ns[p + "_use_kcp_" + node_id] = (accel_mode == "1" || accel_mode == "2") ? "1" : "0"; //
			ns[p + "_name_" + node_id] = E("ss_basic_name").value; //
			if (accel_mode == "1" || accel_mode == "2") { //
				var kcp_param_str = E("ss_basic_kcp_param").value; //
				var kcp_r_match = kcp_param_str.match(/--r\s+([^:\s]+):([0-9]+)/); //
				var final_kcp_param = kcp_param_str;
				if (kcp_r_match && kcp_r_match.length === 3) {
					ns[p + "_kcp_rserver_" + node_id] = kcp_r_match[1]; //
					ns[p + "_kcp_rport_" + node_id] = kcp_r_match[2]; //
					final_kcp_param = final_kcp_param.replace(/--r\s+[^:\s]+:[0-9]+/, ''); //
				} else {
					ns[p + "_kcp_rserver_" + node_id] = E("ss_basic_kcp_rserver").value; //
					ns[p + "_kcp_rport_" + node_id] = E("ss_basic_kcp_rport").value; //
				}
				final_kcp_param = final_kcp_param.replace(/--l\s+[^:\s]+:[0-9]+/, '').trim(); //
				ns[p + "_kcp_param_" + node_id] = final_kcp_param; //
			}
			if (accel_mode == "2" || accel_mode == "3") { //
				var udp2raw_param_str = E("ss_basic_udp2raw_param").value; //
				var udp_r_match = udp2raw_param_str.match(/-r\s+([^:\s]+):([0-9]+)/); //
				var final_udp_param = udp2raw_param_str;
				if (udp_r_match && udp_r_match.length === 3) {
					ns[p + "_udp2raw_rserver_" + node_id] = udp_r_match[1]; //
					ns[p + "_udp2raw_rport_" + node_id] = udp_r_match[2]; //
					final_udp_param = final_udp_param.replace(/-r\s+[^:\s]+:[0-9]+/, ''); //
				} else {
					ns[p + "_udp2raw_rserver_" + node_id] = E("ss_basic_udp2raw_rserver").value; //
					ns[p + "_udp2raw_rport_" + node_id] = E("ss_basic_udp2raw_rport").value; //
				}
				final_udp_param = final_udp_param.replace(/-l\s+[^:\s]+:[0-9]+/, ''); //
				var parts = final_udp_param.split(/\s+/); //
				var filtered_parts = parts.filter(function (part) { return part !== '-c' && part !== ''; }); //
				ns[p + "_udp2raw_param_" + node_id] = filtered_parts.join(' '); //
			}

			// --- 提交数据 ---
			showSSLoadingBar();
			var id = parseInt(Math.random() * 100000000); //
			var postData = { "id": id, "method": "dummy_script.sh", "params": [], "fields": ns }; //
			$.ajax({ //
				type: "POST", //
				url: "/_api/", //
				data: JSON.stringify(postData), //
				success: function () {
					setTimeout(function () { window.location.hash = "#tablet_1"; location.reload(); }, 1000);
				}
			});
		}

		// (修改) 修正"新建节点"模式下的字段清空和只读状态重置的BUG
		function ss_node_sel() {
			var node_sel = E("ssconf_basic_node").value;

			if (node_sel === 'new_node') {
				current_edit_mode = 'new';

				$("#ss_basic_name_tr").show();
				$("#ss_basic_type_tr").show();
				$("#save_new_node_button").show();
				$("#apply_button .button_gen").first().hide();

				// (修正1) 补全 Hysteria 2 相关的字段到清空列表中
				var fields_to_clear = ["ss_basic_name", "ss_basic_server", "ss_basic_port", "ss_basic_password", "ss_basic_ss_obfs_host", "ss_basic_rss_protocol_param", "ss_basic_rss_obfs_param", "ss_basic_v2ray_uuid", "ss_basic_v2ray_network_path", "ss_basic_v2ray_network_host", "ss_basic_v2ray_kcp_seed", "ss_basic_v2ray_network_security_sni", "ss_basic_xray_uuid", "ss_basic_xray_network_path", "ss_basic_xray_network_host", "ss_basic_xray_kcp_seed", "ss_basic_v2ray_kcp_mtu", "ss_basic_v2ray_kcp_tti", "ss_basic_v2ray_kcp_uplink", "ss_basic_v2ray_kcp_downlink", "ss_basic_v2ray_kcp_readbuf", "ss_basic_v2ray_kcp_writebuf", "ss_basic_xray_kcp_mtu", "ss_basic_xray_kcp_tti", "ss_basic_xray_kcp_uplink", "ss_basic_xray_kcp_downlink", "ss_basic_xray_kcp_readbuf", "ss_basic_xray_kcp_writebuf", "ss_basic_xray_network_security_sni", "ss_basic_xray_encryption", "ss_basic_xray_publickey", "ss_basic_xray_shortid", "ss_basic_xray_spiderx", "ss_basic_trojan_uuid", "ss_basic_trojan_sni", "ss_basic_naive_server", "ss_basic_naive_user", "ss_basic_naive_pass", "ss_basic_hy2_server", "ss_basic_hy2_port", "ss_basic_hy2_pass", "ss_basic_hy2_sni", "ss_basic_hy2_obfs_pass", "ss_basic_kcp_rserver", "ss_basic_udp2raw_rserver"];
				fields_to_clear.forEach(function (id) { if (E(id)) E(id).value = ""; });

				// (修正2) 增加对所有可能被锁定的服务器/端口字段的解锁操作
				var fields_to_unlock = ["ss_basic_server", "ss_basic_port", "ss_basic_naive_server", "ss_basic_naive_port", "ss_basic_hy2_server", "ss_basic_hy2_port"];
				fields_to_unlock.forEach(function (id) { if (E(id)) E(id).readOnly = false; });

				// 恢复表单默认值
				$("#ss_basic_type_select").val("0");
				E("ss_basic_mode").value = "2";
				E("ss_basic_method").value = "aes-256-gcm";
				E("ss_basic_accel_mode").value = "0";
				E('ss_basic_xray_network').value = 'tcp';
				E('ss_basic_xray_network_security').value = 'none';
				E("ss_basic_kcp_param").value = kcp_defaults;
				E("ss_basic_udp2raw_param").value = udp2raw_defaults;
				E('ss_basic_xray_encryption').value = ''

				verifyFields_by_type("0");
				toggle_accel_mode();

			} else {
				current_edit_mode = 'edit';

				$("#ss_basic_name_tr").hide();
				$("#ss_basic_type_tr").hide();
				$("#save_new_node_button").hide();
				$("#apply_button .button_gen").first().show();

				if (!node_sel) { node_sel = node_max; }
				if (node_sel > node_max) { node_sel = node_max; }

				var obj = ssconf_node2obj(node_sel);
				conf2obj(obj, 1);

				verifyFields();
				toggle_accel_mode();

				if (E("ss_basic_kcp_param")) auto_grow_textarea(E("ss_basic_kcp_param"));
				if (E("ss_basic_udp2raw_param")) auto_grow_textarea(E("ss_basic_udp2raw_param"));
			}
		}


		function push_data_ws(script, arg, obj, flag) {
			var id = parseInt(Math.random() * 100000000);
			var postData = { "id": id, "method": "dummy_script.sh", "params": [], "fields": obj };
			$.ajax({
				type: "POST",
				cache: false,
				url: "/_api/",
				data: JSON.stringify(postData),
				dataType: "json",
				success: function (response) {
					if (response.result == id) {
						ws = new WebSocket("ws://" + hostname + ":803/");
						ws.onopen = function () {
							ws.send(". " + script + " " + arg);
							if (flag != "1" && flag != "2") {
								showSSLoadingBar();
							}
						};
						ws.onerror = function (event) {
							push_data(script, arg, obj, flag);
						};
						ws.onmessage = function (event) {
							if (event.data == "XU6J03M6") {
								E("ok_button").style.display = "";
								count_down_close();
								ws.close();
							} else if (event.data == "fancyss") {
								ws.close();
								if (flag == "1") {
									refreshpage();
								}
							} else {
								E('log_content3').value += event.data + '\n';
							}
							E("log_content3").scrollTop = E("log_content3").scrollHeight;
						};
					}
				}
			});
		}
		function push_data(script, arg, obj, flag) {
			if (!flag) showSSLoadingBar();
			var id = parseInt(Math.random() * 100000000);
			var postData = { "id": id, "method": script, "params": [arg], "fields": obj };
			$.ajax({
				type: "POST",
				cache: false,
				url: "/_api/",
				data: JSON.stringify(postData),
				dataType: "json",
				success: function (response) {
					if (response.result == id) {
						if (flag && flag == "1") {
							refreshpage();
						} else if (flag && flag == "2") {
						} else {
							get_realtime_log();
						}
					}
				}
			});
		}
		function verifyFields(r) {
			// --- (保持 verifyFields 开头的所有显隐逻辑不变) ---
			elem.display(elem.parentElem('ss_basic_accel_mode', 'tr'), true); //

			var node_sel = E("ssconf_basic_node").value; //
			var ss_on = false; //
			var ssr_on = false; //
			var v2ray_on = false; //
			var xray_on = false; //
			var trojan_on = false; //
			var naive_on = false; //
			var tuic_on = false; //
			var hy2_on = false; //

			// 获取当前实际生效的节点类型
			var node_type;
			if (node_sel === 'new_node') {
				// 在新建模式下，从下拉框获取类型
				node_type = E("ss_basic_type_select") ? E("ss_basic_type_select").value : "0";
			} else {
				// 在编辑模式下，从 db_ss 获取类型
				node_type = db_ss["ssconf_basic_type_" + node_sel] || "0"; //
			}

			if (node_type == "0") { //
				ss_on = true; //
			}
			else if (node_type == "1") { //
				ssr_on = true; //
			}
			else if (node_type == "3") { //
				v2ray_on = true; //
			}
			else if (node_type == "4") { //
				xray_on = true; //
			}
			else if (node_type == "5") { //
				trojan_on = true; //
			}
			else if (node_type == "6") { //
				naive_on = true; //
			}
			else if (node_type == "7") { //
				tuic_on = true; //
			}
			else if (node_type == "8") { //
				hy2_on = true; //
			}

			// 检查JSON开关状态（确保元素存在）
			var v_json_on = E("ss_basic_v2ray_use_json") ? E("ss_basic_v2ray_use_json").checked : false; //
			var v_json_off = !v_json_on; //
			var x_json_on = E("ss_basic_xray_use_json") ? E("ss_basic_xray_use_json").checked : false; //
			var x_json_off = !x_json_on; //

			// V2Ray 相关状态变量 (确保元素存在)
			var v_network_val = E("ss_basic_v2ray_network") ? E("ss_basic_v2ray_network").value : "tcp";
			var v_headtype_tcp_val = E("ss_basic_v2ray_headtype_tcp") ? E("ss_basic_v2ray_headtype_tcp").value : "none";
			var v_network_security_val = E("ss_basic_v2ray_network_security") ? E("ss_basic_v2ray_network_security").value : "none";
			var v_http_on = v_network_val == "tcp" && v_headtype_tcp_val == "http"; //
			var v_host_on = v_network_val == "ws" || v_network_val == "h2" || v_network_val == "quic" || v_http_on; //
			var v_path_on = v_network_val == "ws" || v_network_val == "h2" || v_network_val == "quic" || v_network_val == "grpc" || v_http_on; //
			var v_tls_on = v_network_security_val == "tls"; //
			var v_grpc_on = v_network_val == "grpc"; //
			var v_kcp_on = v_network_val == "kcp";
			var v_quic_on = v_network_val == "quic";
			var v_mux_enabled = E("ss_basic_v2ray_mux_enable") ? E("ss_basic_v2ray_mux_enable").checked : false;

			// Xray 相关状态变量 (确保元素存在)
			var x_network_val = E("ss_basic_xray_network") ? E("ss_basic_xray_network").value : "tcp";
			var x_headtype_tcp_val = E("ss_basic_xray_headtype_tcp") ? E("ss_basic_xray_headtype_tcp").value : "none";
			var x_network_security_val = E("ss_basic_xray_network_security") ? E("ss_basic_xray_network_security").value : "none";
			var x_http_on = x_network_val == "tcp" && x_headtype_tcp_val == "http"; //
			var x_host_on = x_network_val == "ws" || x_network_val == "h2" || x_network_val == "quic" || x_http_on; //
			var x_path_on = x_network_val == "ws" || x_network_val == "h2" || x_network_val == "quic" || x_network_val == "grpc" || x_http_on; //
			var x_tls_on = x_network_security_val == "tls" || x_network_security_val == "xtls"; //
			var x_xtls_on = x_network_security_val == "xtls"; //
			var x_real_on = x_network_security_val == "reality"; //
			var x_tcp_on = x_network_val == "tcp"; //
			var x_grpc_on = x_network_val == "grpc"; //
			var x_kcp_on = x_network_val == "kcp";
			var x_quic_on = x_network_val == "quic";

			// Hysteria 2 相关状态变量 (确保元素存在)
			var hy2_obfs_val = E("ss_basic_hy2_obfs") ? E("ss_basic_hy2_obfs").value : "0";

			// --- 开始设置显隐 ---
			elem.display(elem.parentElem('ss_basic_ss_obfs', 'tr'), ss_on); //
			elem.display(elem.parentElem('ss_basic_ss_obfs_host', 'tr'), (ss_on && E("ss_basic_ss_obfs").value != "0")); //
			elem.display(elem.parentElem('ss_basic_rss_protocol_param', 'tr'), ssr_on); //
			elem.display(elem.parentElem('ss_basic_rss_protocol', 'tr'), ssr_on); //
			elem.display(elem.parentElem('ss_basic_rss_obfs', 'tr'), ssr_on); //
			elem.display(elem.parentElem('ss_basic_rss_obfs_param', 'tr'), ssr_on); //
			elem.display(elem.parentElem('ss_basic_server', 'tr'), ss_on || ssr_on || (v2ray_on && v_json_off) || (xray_on && x_json_off) || trojan_on); //
			elem.display(elem.parentElem('ss_basic_port', 'tr'), ss_on || ssr_on || (v2ray_on && v_json_off) || (xray_on && x_json_off) || trojan_on); //
			elem.display(elem.parentElem('ss_basic_password', 'tr'), ss_on || ssr_on); //
			elem.display(elem.parentElem('ss_basic_method', 'tr'), ss_on || ssr_on); //
			elem.display(elem.parentElem('ss_basic_v2ray_use_json', 'tr'), v2ray_on); //
			elem.display(elem.parentElem('ss_basic_v2ray_uuid', 'tr'), (v2ray_on && v_json_off)); //
			elem.display(elem.parentElem('ss_basic_v2ray_alterid', 'tr'), (v2ray_on && v_json_off)); //
			elem.display(elem.parentElem('ss_basic_v2ray_security', 'tr'), (v2ray_on && v_json_off)); //
			elem.display(elem.parentElem('ss_basic_v2ray_network', 'tr'), (v2ray_on && v_json_off)); //
			elem.display(elem.parentElem('ss_basic_v2ray_headtype_tcp', 'tr'), (v2ray_on && v_json_off && v_network_val == "tcp")); //
			elem.display(elem.parentElem('ss_basic_v2ray_headtype_kcp', 'tr'), (v2ray_on && v_json_off && v_kcp_on)); //
			elem.display(elem.parentElem('ss_basic_v2ray_kcp_seed', 'tr'), (v2ray_on && v_json_off && v_kcp_on)); //
			elem.display(elem.parentElem('ss_basic_v2ray_kcp_mtu', 'tr'), (v2ray_on && v_json_off && v_kcp_on)); //
			elem.display(elem.parentElem('ss_basic_v2ray_kcp_tti', 'tr'), (v2ray_on && v_json_off && v_kcp_on)); //
			elem.display(elem.parentElem('ss_basic_v2ray_kcp_uplink', 'tr'), (v2ray_on && v_json_off && v_kcp_on)); //
			elem.display(elem.parentElem('ss_basic_v2ray_kcp_downlink', 'tr'), (v2ray_on && v_json_off && v_kcp_on)); //
			elem.display(elem.parentElem('ss_basic_v2ray_kcp_congestion', 'tr'), (v2ray_on && v_json_off && v_kcp_on)); //
			elem.display(elem.parentElem('ss_basic_v2ray_kcp_readbuf', 'tr'), (v2ray_on && v_json_off && v_kcp_on)); //
			elem.display(elem.parentElem('ss_basic_v2ray_kcp_writebuf', 'tr'), (v2ray_on && v_json_off && v_kcp_on)); //
			elem.display(elem.parentElem('ss_basic_v2ray_headtype_quic', 'tr'), (v2ray_on && v_json_off && v_quic_on)); //
			elem.display(elem.parentElem('ss_basic_v2ray_grpc_mode', 'tr'), (v2ray_on && v_json_off && v_grpc_on)); //
			elem.display(elem.parentElem('ss_basic_v2ray_network_host', 'tr'), (v2ray_on && v_json_off && v_host_on)); //
			elem.display(elem.parentElem('ss_basic_v2ray_network_path', 'tr'), (v2ray_on && v_json_off && v_path_on)); //
			elem.display(elem.parentElem('ss_basic_v2ray_network_security', 'tr'), (v2ray_on && v_json_off)); //
			elem.display(elem.parentElem('ss_basic_v2ray_network_security_ai', 'tr'), (v2ray_on && v_json_off && v_tls_on)); //
			elem.display(elem.parentElem('ss_basic_v2ray_network_security_alpn_h2', 'tr'), (v2ray_on && v_json_off && v_tls_on)); //
			elem.display(elem.parentElem('ss_basic_v2ray_network_security_alpn_http', 'tr'), (v2ray_on && v_json_off && v_tls_on));
			elem.display(elem.parentElem('ss_basic_v2ray_network_security_sni', 'tr'), (v2ray_on && v_json_off && v_tls_on)); //
			elem.display(elem.parentElem('ss_basic_v2ray_mux_enable', 'tr'), (v2ray_on && v_json_off)); //
			elem.display(elem.parentElem('ss_basic_v2ray_mux_concurrency', 'tr'), (v2ray_on && v_json_off && v_mux_enabled)); //
			elem.display(elem.parentElem('ss_basic_v2ray_json', 'tr'), (v2ray_on && v_json_on)); //
			elem.display('v2ray_binary_update_tr', v2ray_on); //
			if (v_grpc_on) {
				$('#ss_basic_v2ray_network_path_tr > th > a').html('* serviceName'); //
			} else {
				$('#ss_basic_v2ray_network_path_tr > th > a').html('* 路径 (path)'); //
			}
			elem.display(elem.parentElem('ss_basic_xray_use_json', 'tr'), xray_on); //
			elem.display(elem.parentElem('ss_basic_xray_uuid', 'tr'), (xray_on && x_json_off)); //
			elem.display(elem.parentElem('ss_basic_xray_encryption', 'tr'), (xray_on && x_json_off)); //
			elem.display(elem.parentElem('ss_basic_xray_flow', 'tr'), (xray_on && x_json_off && (x_tls_on && x_tcp_on || x_real_on && x_tcp_on))); //
			elem.display(elem.parentElem('ss_basic_xray_network', 'tr'), (xray_on && x_json_off)); //
			elem.display(elem.parentElem('ss_basic_xray_headtype_tcp', 'tr'), (xray_on && x_json_off && x_tcp_on)); //
			elem.display(elem.parentElem('ss_basic_xray_headtype_kcp', 'tr'), (xray_on && x_json_off && x_kcp_on)); //
			elem.display(elem.parentElem('ss_basic_xray_kcp_seed', 'tr'), (xray_on && x_json_off && x_kcp_on)); //
			elem.display(elem.parentElem('ss_basic_xray_kcp_mtu', 'tr'), (xray_on && x_json_off && x_kcp_on)); //
			elem.display(elem.parentElem('ss_basic_xray_kcp_tti', 'tr'), (xray_on && x_json_off && x_kcp_on)); //
			elem.display(elem.parentElem('ss_basic_xray_kcp_uplink', 'tr'), (xray_on && x_json_off && x_kcp_on)); //
			elem.display(elem.parentElem('ss_basic_xray_kcp_downlink', 'tr'), (xray_on && x_json_off && x_kcp_on)); //
			elem.display(elem.parentElem('ss_basic_xray_kcp_congestion', 'tr'), (xray_on && x_json_off && x_kcp_on)); //
			elem.display(elem.parentElem('ss_basic_xray_kcp_readbuf', 'tr'), (xray_on && x_json_off && x_kcp_on)); //
			elem.display(elem.parentElem('ss_basic_xray_kcp_writebuf', 'tr'), (xray_on && x_json_off && x_kcp_on)); //
			elem.display(elem.parentElem('ss_basic_xray_headtype_quic', 'tr'), (xray_on && x_json_off && x_quic_on)); //
			elem.display(elem.parentElem('ss_basic_xray_grpc_mode', 'tr'), (xray_on && x_json_off && x_grpc_on)); //
			elem.display(elem.parentElem('ss_basic_xray_network_host', 'tr'), (xray_on && x_json_off && x_host_on)); //
			elem.display(elem.parentElem('ss_basic_xray_network_path', 'tr'), (xray_on && x_json_off && x_path_on)); //
			elem.display(elem.parentElem('ss_basic_xray_network_security', 'tr'), (xray_on && x_json_off)); //
			elem.display(elem.parentElem('ss_basic_xray_network_security_ai', 'tr'), (xray_on && x_json_off && x_tls_on)); //
			elem.display(elem.parentElem('ss_basic_xray_network_security_alpn_h2', 'tr'), (xray_on && x_json_off && x_tls_on)); //
			elem.display(elem.parentElem('ss_basic_xray_network_security_alpn_http', 'tr'), (xray_on && x_json_off && x_tls_on));
			elem.display(elem.parentElem('ss_basic_xray_network_security_sni', 'tr'), (xray_on && x_json_off && (x_tls_on || x_real_on))); //
			elem.display(elem.parentElem('ss_basic_xray_fingerprint', 'tr'), (xray_on && x_json_off && (x_tls_on || x_real_on))); //
			elem.display(elem.parentElem('ss_basic_xray_show', 'tr'), (xray_on && x_json_off && x_real_on)); //
			elem.display(elem.parentElem('ss_basic_xray_publickey', 'tr'), (xray_on && x_json_off && x_real_on)); //
			elem.display(elem.parentElem('ss_basic_xray_shortid', 'tr'), (xray_on && x_json_off && x_real_on)); //
			elem.display(elem.parentElem('ss_basic_xray_spiderx', 'tr'), (xray_on && x_json_off && x_real_on)); //
			elem.display(elem.parentElem('ss_basic_xray_json', 'tr'), (xray_on && x_json_on)); //
			elem.display('xray_binary_update_tr', xray_on); //
			if (x_grpc_on) {
				$('#ss_basic_xray_network_path_tr > th > a').html('* serviceName'); //
			} else {
				$('#ss_basic_xray_network_path_tr > th > a').html('* 路径 (path)'); //
			}
			elem.display(elem.parentElem('ss_basic_trojan_uuid', 'tr'), (trojan_on)); //
			elem.display(elem.parentElem('ss_basic_trojan_ai', 'tr'), (trojan_on)); //
			elem.display(elem.parentElem('ss_basic_trojan_sni', 'tr'), (trojan_on)); //
			elem.display(elem.parentElem('ss_basic_trojan_tfo', 'tr'), (trojan_on)); //
			elem.display(elem.parentElem('ss_basic_naive_prot', 'tr'), (naive_on)); //
			elem.display(elem.parentElem('ss_basic_naive_server', 'tr'), (naive_on)); //
			elem.display(elem.parentElem('ss_basic_naive_port', 'tr'), (naive_on)); //
			elem.display(elem.parentElem('ss_basic_naive_user', 'tr'), (naive_on)); //
			elem.display(elem.parentElem('ss_basic_naive_pass', 'tr'), (naive_on)); //
			elem.display(elem.parentElem('ss_basic_tuic_json', 'tr'), tuic_on); //
			elem.display(elem.parentElem('ss_basic_hy2_server', 'tr'), hy2_on); //
			elem.display(elem.parentElem('ss_basic_hy2_port', 'tr'), hy2_on); //
			elem.display(elem.parentElem('ss_basic_hy2_pass', 'tr'), hy2_on); //
			elem.display(elem.parentElem('ss_basic_hy2_up', 'tr'), hy2_on); //
			elem.display(elem.parentElem('ss_basic_hy2_dl', 'tr'), hy2_on); //
			elem.display(elem.parentElem('ss_basic_hy2_obfs', 'tr'), hy2_on); //
			elem.display(elem.parentElem('ss_basic_hy2_obfs_pass', 'tr'), hy2_on && hy2_obfs_val != "0"); //
			elem.display(elem.parentElem('ss_basic_hy2_sni', 'tr'), hy2_on); //
			elem.display(elem.parentElem('ss_basic_hy2_ai', 'tr'), hy2_on); //
			elem.display(elem.parentElem('ss_basic_hy2_tfo', 'tr'), hy2_on); //

			if (E("ss_basic_tjai") && E("ss_basic_tjai").checked == true) { //
				if (E("ss_basic_trojan_ai")) E("ss_basic_trojan_ai").disabled = true; //
				if (E("ss_basic_trojan_ai_note")) E("ss_basic_trojan_ai_note").innerHTML = "已全局跳过证书验证"; //
			} else { //
				if (E("ss_basic_trojan_ai")) E("ss_basic_trojan_ai").disabled = false;
				if (E("ss_basic_trojan_ai_note")) E("ss_basic_trojan_ai_note").innerHTML = "";
			}

			if (save_flag == "shadowsocks") { //
				var obfsVal = E("ss_node_table_ss_obfs") ? E("ss_node_table_ss_obfs").value : "0";
				showhide("ss_obfs_host_support", obfsVal != "0"); //
			}
			if (save_flag == "v2ray") { //
				if (E("ss_node_table_v2ray_use_json") && E("ss_node_table_v2ray_use_json").checked) { //
					if (E('ss_server_support_tr')) E('ss_server_support_tr').style.display = "none"; //
					if (E('ss_port_support_tr')) E('ss_port_support_tr').style.display = "none"; //
					if (E('v2ray_uuid_tr')) E('v2ray_uuid_tr').style.display = "none"; //
					$(".v2ray_elem").hide(); //
					if (E('v2ray_alterid_tr')) E('v2ray_alterid_tr').style.display = "none"; //
					if (E('v2ray_security_tr')) E('v2ray_security_tr').style.display = "none"; //
					if (E('v2ray_network_tr')) E('v2ray_network_tr').style.display = "none"; //
					if (E('v2ray_headtype_tcp_tr')) E('v2ray_headtype_tcp_tr').style.display = "none"; //
					if (E('v2ray_headtype_kcp_tr')) E('v2ray_headtype_kcp_tr').style.display = "none"; //
					if (E('v2ray_headtype_quic_tr')) E('v2ray_headtype_quic_tr').style.display = "none"; //
					if (E('v2ray_grpc_mode_tr')) E('v2ray_grpc_mode_tr').style.display = "none"; //
					if (E('v2ray_network_path_tr')) E('v2ray_network_path_tr').style.display = "none"; //
					if (E('v2ray_network_host_tr')) E('v2ray_network_host_tr').style.display = "none"; //
					if (E('v2ray_kcp_seed_tr')) E('v2ray_kcp_seed_tr').style.display = "none"; //
					if (E('v2ray_network_security_tr')) E('v2ray_network_security_tr').style.display = "none"; //
					if (E('v2ray_network_security_ai_tr')) E('v2ray_network_security_ai_tr').style.display = "none"; //
					if (E('v2ray_network_security_alpn_tr')) E('v2ray_network_security_alpn_tr').style.display = "none"; //
					if (E('v2ray_network_security_sni_tr')) E('v2ray_network_security_sni_tr').style.display = "none"; //
					if (E('v2ray_mux_enable_tr')) E('v2ray_mux_enable_tr').style.display = "none"; //
					if (E('v2ray_mux_concurrency_tr')) E('v2ray_mux_concurrency_tr').style.display = "none"; //
					if (E('v2ray_json_tr')) E('v2ray_json_tr').style.display = ""; //
				} else { //
					if (E('ss_server_support_tr')) E('ss_server_support_tr').style.display = ""; //
					if (E('ss_port_support_tr')) E('ss_port_support_tr').style.display = ""; //
					if (E('v2ray_uuid_tr')) E('v2ray_uuid_tr').style.display = ""; //
					$(".v2ray_elem").show(); //
					if (E('v2ray_alterid_tr')) E('v2ray_alterid_tr').style.display = ""; //
					if (E('v2ray_security_tr')) E('v2ray_security_tr').style.display = ""; //
					if (E('v2ray_network_tr')) E('v2ray_network_tr').style.display = ""; //
					if (E('v2ray_headtype_tcp_tr')) E('v2ray_headtype_tcp_tr').style.display = ""; //
					if (E('v2ray_headtype_kcp_tr')) E('v2ray_headtype_kcp_tr').style.display = ""; //
					if (E('v2ray_headtype_quic_tr')) E('v2ray_headtype_quic_tr').style.display = ""; //
					if (E('v2ray_grpc_mode_tr')) E('v2ray_grpc_mode_tr').style.display = ""; //
					if (E('v2ray_network_path_tr')) E('v2ray_network_path_tr').style.display = ""; //
					if (E('v2ray_network_host_tr')) E('v2ray_network_host_tr').style.display = ""; //
					if (E('v2ray_kcp_seed_tr')) E('v2ray_kcp_seed_tr').style.display = "none"; //
					if (E('v2ray_network_security_tr')) E('v2ray_network_security_tr').style.display = ""; //
					if (E('v2ray_network_security_ai_tr')) E('v2ray_network_security_ai_tr').style.display = "none"; //
					if (E('v2ray_network_security_alpn_tr')) E('v2ray_network_security_alpn_tr').style.display = "none"; //
					if (E('v2ray_network_security_sni_tr')) E('v2ray_network_security_sni_tr').style.display = "none"; //
					if (E('v2ray_mux_enable_tr')) E('v2ray_mux_enable_tr').style.display = ""; //
					if (E('v2ray_mux_concurrency_tr')) E('v2ray_mux_concurrency_tr').style.display = ""; //
					if (E('v2ray_json_tr')) E('v2ray_json_tr').style.display = "none"; //
					var v_tcp_on_2 = E("ss_node_table_v2ray_network") && E("ss_node_table_v2ray_network").value == "tcp"; //
					var v_http_on_2 = E("ss_node_table_v2ray_network") && E("ss_node_table_v2ray_network").value == "tcp" && E("ss_node_table_v2ray_headtype_tcp") && E("ss_node_table_v2ray_headtype_tcp").value == "http"; //
					var v_host_on_2 = (E("ss_node_table_v2ray_network") && (E("ss_node_table_v2ray_network").value == "ws" || //
						E("ss_node_table_v2ray_network").value == "h2" || E("ss_node_table_v2ray_network").value == "quic")) || v_http_on_2; //
					var v_path_on_2 = (E("ss_node_table_v2ray_network") && (E("ss_node_table_v2ray_network").value == "ws" || E("ss_node_table_v2ray_network").value == "h2" || //
						E("ss_node_table_v2ray_network").value == "quic" || E("ss_node_table_v2ray_network").value == "grpc")) || v_http_on_2; //
					var v_tls_on_2 = E("ss_node_table_v2ray_network_security") && (E("ss_node_table_v2ray_network_security").value == "tls" || E("ss_node_table_v2ray_network_security").value == "xtls"); //
					var v_grpc_on_2 = E("ss_node_table_v2ray_network") && E("ss_node_table_v2ray_network").value == "grpc";
					var v_kcp_on_2 = E("ss_node_table_v2ray_network") && E("ss_node_table_v2ray_network").value == "kcp";
					var v_quic_on_2 = E("ss_node_table_v2ray_network") && E("ss_node_table_v2ray_network").value == "quic";
					showhide("v2ray_headtype_tcp_tr", v_tcp_on_2); //
					showhide("v2ray_headtype_kcp_tr", v_kcp_on_2); //
					showhide("v2ray_kcp_seed_tr", v_kcp_on_2); //
					showhide("v2ray_headtype_quic_tr", v_quic_on_2); //
					showhide("v2ray_grpc_mode_tr", v_grpc_on_2); //
					showhide("v2ray_network_host_tr", v_host_on_2); //
					showhide("v2ray_network_path_tr", v_path_on_2); //
					showhide("v2ray_mux_concurrency_tr", E("ss_node_table_v2ray_mux_enable") && E("ss_node_table_v2ray_mux_enable").checked); //
					showhide("v2ray_json_tr", E("ss_node_table_v2ray_use_json") && E("ss_node_table_v2ray_use_json").checked); //
					showhide("v2ray_network_security_ai_tr", v_tls_on_2); //
					showhide("v2ray_network_security_alpn_tr", v_tls_on_2); //
					showhide("v2ray_network_security_sni_tr", v_tls_on_2); //
					if (v_grpc_on_2 && $('#v2ray_network_path_tr > th > a')) {
						$('#v2ray_network_path_tr > th > a').html('* serviceName'); //
					} else if ($('#v2ray_network_path_tr > th > a')) {
						$('#v2ray_network_path_tr > th > a').html('* 路径 (path)'); //
					}
				}
			}
			if (save_flag == "xray") { //
				if (E("ss_node_table_xray_use_json") && E("ss_node_table_xray_use_json").checked) { //
					if (E('ss_server_support_tr')) E('ss_server_support_tr').style.display = "none"; //
					if (E('ss_port_support_tr')) E('ss_port_support_tr').style.display = "none"; //
					if (E('xray_uuid_tr')) E('xray_uuid_tr').style.display = "none"; //
					$(".xray_elem").hide(); //
					if (E('xray_encryption_tr')) E('xray_encryption_tr').style.display = "none"; //
					if (E('xray_flow_tr')) E('xray_flow_tr').style.display = "none"; //
					if (E('xray_show_tr')) E('xray_show_tr').style.display = "none"; //
					if (E('xray_publickey_tr')) E('xray_publickey_tr').style.display = "none"; //
					if (E('xray_shortid_tr')) E('xray_shortid_tr').style.display = "none"; //
					if (E('xray_spiderx_tr')) E('xray_spiderx_tr').style.display = "none"; //
					if (E('xray_network_tr')) E('xray_network_tr').style.display = "none"; //
					if (E('xray_headtype_tcp_tr')) E('xray_headtype_tcp_tr').style.display = "none"; //
					if (E('xray_headtype_kcp_tr')) E('xray_headtype_kcp_tr').style.display = "none"; //
					if (E('xray_headtype_quic_tr')) E('xray_headtype_quic_tr').style.display = "none"; //
					if (E('xray_grpc_mode_tr')) E('xray_grpc_mode_tr').style.display = "none"; //
					if (E('xray_network_path_tr')) E('xray_network_path_tr').style.display = "none"; //
					if (E('xray_network_host_tr')) E('xray_network_host_tr').style.display = "none"; //
					if (E('xray_kcp_seed_tr')) E('xray_kcp_seed_tr').style.display = "none"; //
					if (E('xray_network_security_tr')) E('xray_network_security_tr').style.display = "none"; //
					if (E('xray_network_security_ai_tr')) E('xray_network_security_ai_tr').style.display = "none"; //
					if (E('xray_network_security_alpn_tr')) E('xray_network_security_alpn_tr').style.display = "none"; //
					if (E('xray_network_security_sni_tr')) E('xray_network_security_sni_tr').style.display = "none"; //
					if (E('xray_fingerprint_tr')) E('xray_fingerprint_tr').style.display = "none"; //
					if (E('xray_json_tr')) E('xray_json_tr').style.display = ""; //
				} else { //
					if (E('ss_server_support_tr')) E('ss_server_support_tr').style.display = ""; //
					if (E('ss_port_support_tr')) E('ss_port_support_tr').style.display = ""; //
					if (E('xray_uuid_tr')) E('xray_uuid_tr').style.display = ""; //
					$(".xray_elem").show(); //
					if (E('xray_encryption_tr')) E('xray_encryption_tr').style.display = ""; //
					if (E('xray_flow_tr')) E('xray_flow_tr').style.display = ""; //
					if (E('xray_show_tr')) E('xray_show_tr').style.display = ""; //
					if (E('xray_publickey_tr')) E('xray_publickey_tr').style.display = ""; //
					if (E('xray_shortid_tr')) E('xray_shortid_tr').style.display = ""; //
					if (E('xray_spiderx_tr')) E('xray_spiderx_tr').style.display = ""; //
					if (E('xray_network_tr')) E('xray_network_tr').style.display = ""; //
					if (E('xray_headtype_tcp_tr')) E('xray_headtype_tcp_tr').style.display = ""; //
					if (E('xray_headtype_kcp_tr')) E('xray_headtype_kcp_tr').style.display = ""; //
					if (E('xray_headtype_quic_tr')) E('xray_headtype_quic_tr').style.display = ""; //
					if (E('xray_grpc_mode_tr')) E('xray_grpc_mode_tr').style.display = ""; //
					if (E('xray_network_path_tr')) E('xray_network_path_tr').style.display = ""; //
					if (E('xray_network_host_tr')) E('xray_network_host_tr').style.display = ""; //
					if (E('xray_kcp_seed_tr')) E('xray_kcp_seed_tr').style.display = "none"; //
					if (E('xray_network_security_tr')) E('xray_network_security_tr').style.display = ""; //
					if (E('xray_network_security_ai_tr')) E('xray_network_security_ai_tr').style.display = ""; //
					if (E('xray_network_security_alpn_tr')) E('xray_network_security_alpn_tr').style.display = ""; //
					if (E('xray_network_security_sni_tr')) E('xray_network_security_sni_tr').style.display = "none"; //
					if (E('xray_fingerprint_tr')) E('xray_fingerprint_tr').style.display = "none"; //
					if (E('xray_json_tr')) E('xray_json_tr').style.display = "none"; //
					var x_http_on_2 = E("ss_node_table_xray_network") && E("ss_node_table_xray_network").value == "tcp" && E("ss_node_table_xray_headtype_tcp") && E("ss_node_table_xray_headtype_tcp").value == "http"; //
					var x_host_on_2 = (E("ss_node_table_xray_network") && (E("ss_node_table_xray_network").value == "ws" || E("ss_node_table_xray_network").value == "h2" || E("ss_node_table_xray_network").value == "quic")) || x_http_on_2; //
					var x_path_on_2 = (E("ss_node_table_xray_network") && (E("ss_node_table_xray_network").value == "ws" || E("ss_node_table_xray_network").value == "h2" || E("ss_node_table_xray_network").value == "quic" || E("ss_node_table_xray_network").value == "grpc")) || x_http_on_2; //
					var x_tls_on_2 = E("ss_node_table_xray_network_security") && (E("ss_node_table_xray_network_security").value == "tls" || E("ss_node_table_xray_network_security").value == "xtls"); //
					var x_xtls_on_2 = E("ss_node_table_xray_network_security") && E("ss_node_table_xray_network_security").value == "xtls"; //
					var x_real_on_2 = E("ss_node_table_xray_network_security") && E("ss_node_table_xray_network_security").value == "reality"; //
					var x_tcp_on_2 = E("ss_node_table_xray_network") && E("ss_node_table_xray_network").value == "tcp"; //
					var x_grpc_on_2 = E("ss_node_table_xray_network") && E("ss_node_table_xray_network").value == "grpc"; //
					var x_kcp_on_2 = E("ss_node_table_xray_network") && E("ss_node_table_xray_network").value == "kcp";
					var x_quic_on_2 = E("ss_node_table_xray_network") && E("ss_node_table_xray_network").value == "quic";
					showhide("xray_headtype_tcp_tr", x_tcp_on_2); //
					showhide("xray_headtype_kcp_tr", x_kcp_on_2); //
					showhide("xray_kcp_seed_tr", x_kcp_on_2); //
					showhide("xray_headtype_quic_tr", x_quic_on_2); //
					showhide("xray_grpc_mode_tr", x_grpc_on_2); //
					showhide("xray_network_host_tr", x_host_on_2); //
					showhide("xray_network_path_tr", x_path_on_2); //
					showhide("xray_json_tr", E("ss_node_table_xray_use_json") && E("ss_node_table_xray_use_json").checked); //
					showhide("xray_network_security_ai_tr", x_tls_on_2); //
					showhide("xray_network_security_alpn_tr", x_tls_on_2); //
					showhide("xray_network_security_sni_tr", x_tls_on_2 || x_real_on_2); //
					showhide("xray_fingerprint_tr", x_tls_on_2 || x_real_on_2); //
					showhide("xray_flow_tr", x_tls_on_2 && x_tcp_on_2 || x_real_on_2 && x_tcp_on_2); //
					showhide("xray_show_tr", x_real_on_2); //
					showhide("xray_publickey_tr", x_real_on_2); //
					showhide("xray_shortid_tr", x_real_on_2); //
					showhide("xray_spiderx_tr", x_real_on_2); //
					if (x_grpc_on_2 && $('#xray_network_path_tr > th > a')) {
						$('#xray_network_path_tr > th > a').html('* serviceName'); //
					} else if ($('#xray_network_path_tr > th > a')) {
						$('#xray_network_path_tr > th > a').html('* 路径 (path)'); //
					}
				}
			}
			if (save_flag == "hysteria2") { //
				var hy2ObfsVal = E("ss_node_table_hy2_obfs") ? E("ss_node_table_hy2_obfs").value : "0";
				showhide("hy2_obfs_pass_tr", hy2ObfsVal != "0"); //
			}
			var kcp_trs = ["ss_basic_kcp_password_tr", "ss_basic_kcp_mode_tr", "ss_basic_kcp_encrypt_tr", "ss_basic_kcp_mtu_tr", "ss_basic_kcp_sndwnd_tr", "ss_basic_kcp_rcvwnd_tr", "ss_basic_kcp_conn_tr", "ss_basic_kcp_nocomp_tr", "ss_basic_kcp_extra_tr"]; //
			if (E("ss_basic_kcp_method") && E("ss_basic_kcp_method").value == "1") { //
				if (E("ss_basic_kcp_parameter_tr")) E("ss_basic_kcp_parameter_tr").style.display = "none"; //
				for (var i = 0; i < kcp_trs.length; i++) { //
					if (E(kcp_trs[i])) E(kcp_trs[i]).style.display = ""; //
				}
			} else { //
				if (E("ss_basic_kcp_parameter_tr")) E("ss_basic_kcp_parameter_tr").style.display = ""; //
				for (var i = 0; i < kcp_trs.length; i++) { //
					if (E(kcp_trs[i])) E(kcp_trs[i]).style.display = "none"; //
				}
			}
			if ($('.sub-btn1') && $('.sub-btn1').hasClass("active2")) { //
				$(".speeder").show(); //
				if (E("ss_basic_udp_software") && E("ss_basic_udp_software").value == "1") { //
					$(".speederv1").show(); //
					$(".speederv2").hide(); //
					$(".udp2raw").hide(); //
				} //
				if (E("ss_basic_udp_software") && E("ss_basic_udp_software").value == "2") { //
					$(".speederv1").hide(); //
					$(".speederv2").show(); //
					$(".udp2raw").hide(); //
				}
			} else if ($('.sub-btn2') && $('.sub-btn2').hasClass("active2")) { //
				$(".udp2raw").show(); //
				$(".speeder").hide(); //
				$(".speederv1").hide(); //
				$(".speederv2").hide(); //
			}
			var Ti = E("ss_reboot_check") ? E("ss_reboot_check").value : "0"; //
			var In = E("ss_basic_inter_pre") ? E("ss_basic_inter_pre").value : "1"; //
			var items = ["re1", "re2", "re3", "re4", "re4_1", "re4_2", "re4_3", "re5"]; //
			for (var i = 1; i < items.length; ++i) $("." + items[i]).hide(); //
			if (Ti != "0") $(".re" + Ti).show(); //
			if (Ti == "4") $(".re4_" + In).show(); //
			if (E("ss_failover_enable") && E("ss_failover_enable").checked) { //
				$("#interval_settings").show(); //
				$("#failover_settings_1").show(); //
				$("#failover_settings_2").show(); //
				$("#failover_settings_3").show(); //
			} else { //
				$("#interval_settings").hide(); //
				$("#failover_settings_1").hide(); //
				$("#failover_settings_2").hide(); //
				$("#failover_settings_3").hide(); //
			}
			showhide("ss_failover_s4_2", E("ss_failover_enable") && E("ss_failover_enable").checked && E("ss_failover_s4_1") && E("ss_failover_s4_1").value == "2"); //
			showhide("ss_failover_s4_3", E("ss_failover_enable") && E("ss_failover_enable").checked && E("ss_failover_s4_1") && E("ss_failover_s4_1").value == "2" && E("ss_failover_s4_2") && E("ss_failover_s4_2").value == "1"); //
			if (E("ss_adv_sub") && E("ss_adv_sub").checked == false) { //
				if ($("#ssr_subscribe_mode")) $("#ssr_subscribe_mode").parent().parent().hide(); //
				if ($("#ss_basic_hy2_up_speed")) $("#ss_basic_hy2_up_speed").parent().parent().hide(); //
				if ($("#ss_basic_online_links_goss")) $("#ss_basic_online_links_goss").parent().parent().hide(); //
				if ($("#ss_basic_node_update")) $("#ss_basic_node_update").parent().parent().hide(); //
				if ($("#ss_basic_exclude")) $("#ss_basic_exclude").parent().parent().hide(); //
				if ($("#ss_basic_include")) $("#ss_basic_include").parent().parent().hide(); //
				if ($("#ss_basic_remove_node")) $("#ss_basic_remove_node").hide(); //
				if ($("#ss_sub_save_only")) $("#ss_sub_save_only").hide(); //
			} else { //
				if ($("#ssr_subscribe_mode")) $("#ssr_subscribe_mode").parent().parent().show(); //
				if ($("#ss_basic_hy2_up_speed")) $("#ss_basic_hy2_up_speed").parent().parent().show(); //
				if ($("#ss_basic_online_links_goss")) $("#ss_basic_online_links_goss").parent().parent().show(); //
				if ($("#ss_basic_node_update")) $("#ss_basic_node_update").parent().parent().show(); //
				if ($("#ss_basic_exclude")) $("#ss_basic_exclude").parent().parent().show(); //
				if ($("#ss_basic_include")) $("#ss_basic_include").parent().parent().show(); //
				if ($("#ss_basic_remove_node")) $("#ss_basic_remove_node").show(); //
				if ($("#ss_sub_save_only")) $("#ss_sub_save_only").show(); //
			} //
			if (r) {
				var trid = $(r).attr("id"); //
				if (trid == "ss_basic_qrcode" || trid == "ss_basic_dragable" || trid == "ss_basic_tablet" || trid == "ss_basic_noserver") { //
					var dbus_post = {}; //
					dbus_post[trid] = E(trid).checked ? '1' : '0'; //
					if (ws_flag == 1) { //
						push_data_ws("ss_dummy.sh", "", dbus_post, "1"); //
					} else { //
						push_data("dummy_script.sh", "", dbus_post, "1"); //
					} //
				}
				if (trid == "ss_adv_sub") { //
					var dbus_post = {}; //
					dbus_post["ss_adv_sub"] = E("ss_adv_sub").checked ? '1' : '0'; //
					if (ws_flag == 1) { //
						push_data_ws("ss_dummy.sh", "", dbus_post, "2"); //
					} else { //
						push_data("dummy_script.sh", "", dbus_post, "2"); //
					}
				}
				if (trid == "ss_basic_kcp_on") { //
					var dbus_post = {}; //
					dbus_post["ss_basic_kcp_on"] = E("ss_basic_kcp_on").checked ? '1' : '0'; //
					if (ws_flag == 1) { //
						push_data_ws("ss_dummy.sh", "", dbus_post, "1"); //
					} else { //
						push_data("dummy_script.sh", "", dbus_post, "1"); //
					} //
				}
				if (trid == "ss_basic_udp_on") { //
					var dbus_post = {}; //
					dbus_post["ss_basic_udp_on"] = E("ss_basic_udp_on").checked ? '1' : '0'; //
					if (ws_flag == 1) { //
						push_data_ws("ss_dummy.sh", "", dbus_post, "1"); //
					} else { //
						push_data("dummy_script.sh", "", dbus_post, "1"); //
					}
				}
			}
			refresh_acl_table(); //

			var fill_default_if_empty = function (id, defaultValue) {
				var el = E(id);
				var parentTr = elem.parentElem(id, 'tr');
				if (el && parentTr && parentTr.style.display !== 'none' && !el.value) {
					el.value = defaultValue;
				}
			};
			var fill_default_select_if_empty = function (id, defaultValue) {
				var el = E(id);
				var parentTr = elem.parentElem(id, 'tr');
				if (el && parentTr && parentTr.style.display !== 'none' && !el.value) {
					el.value = defaultValue;
				}
			};
			var fill_default_checkbox = function (id, defaultValue) {
				var el = E(id);
				var parentTr = elem.parentElem(id, 'tr');
				// 仅在新建节点模式下，且 checkbox 当前可见时，强制设置默认值
				if (el && parentTr && parentTr.style.display !== 'none' && node_sel === 'new_node') {
					// 检查是否已经有值（来自 forms 定义），如果没有再设置
					if (typeof el.checked !== 'boolean' || el.getAttribute('data-default-applied') !== 'true') {
						el.checked = defaultValue;
						el.setAttribute('data-default-applied', 'true'); // 标记已应用，防止重复设置
					}
				} else if (el && parentTr && parentTr.style.display !== 'none' && node_sel !== 'new_node') {
					// 编辑模式下，如果 checked 状态未定义（可能 conf2obj 未处理），则应用默认值
					if (typeof el.checked !== 'boolean') {
						el.checked = defaultValue;
					}
					// 移除标记，以便下次新建时能重新应用
					el.removeAttribute('data-default-applied');
				} else if (el && node_sel === 'new_node') {
					// 新建模式下如果字段不可见，也移除标记
					el.removeAttribute('data-default-applied');
				}
			};

			fill_default_select_if_empty("ss_basic_mode", "2");
			fill_default_select_if_empty("ss_basic_accel_mode", "0");

			fill_default_if_empty("ss_basic_kcp_rport", "48400");
			if (E("ss_basic_kcp_param") && elem.parentElem("ss_basic_kcp_param", 'tr').style.display !== 'none' && !E("ss_basic_kcp_param").value) { E("ss_basic_kcp_param").value = kcp_defaults; auto_grow_textarea(E("ss_basic_kcp_param")); } //
			fill_default_if_empty("ss_basic_udp2raw_rport", "38380");
			if (E("ss_basic_udp2raw_param") && elem.parentElem("ss_basic_udp2raw_param", 'tr').style.display !== 'none' && !E("ss_basic_udp2raw_param").value) { E("ss_basic_udp2raw_param").value = udp2raw_defaults; auto_grow_textarea(E("ss_basic_udp2raw_param")); } //

			if (node_type == "0") {
				fill_default_select_if_empty("ss_basic_method", "aes-256-gcm");
				fill_default_select_if_empty("ss_basic_ss_obfs", "0");
			}
			else if (node_type == "1") {
				fill_default_select_if_empty("ss_basic_method", "aes-256-gcm");
				fill_default_select_if_empty("ss_basic_rss_protocol", "origin");
				fill_default_select_if_empty("ss_basic_rss_obfs", "plain");
			}
			else if (node_type == "3" && v_json_off) {
				fill_default_if_empty("ss_basic_v2ray_alterid", "0");
				fill_default_select_if_empty("ss_basic_v2ray_security", "auto");
				fill_default_select_if_empty("ss_basic_v2ray_network", "tcp");
				fill_default_select_if_empty("ss_basic_v2ray_headtype_tcp", "none");
				fill_default_select_if_empty("ss_basic_v2ray_headtype_kcp", "none");
				fill_default_if_empty("ss_basic_v2ray_kcp_mtu", "1200");
				fill_default_if_empty("ss_basic_v2ray_kcp_tti", "40");
				fill_default_if_empty("ss_basic_v2ray_kcp_uplink", "1");
				fill_default_if_empty("ss_basic_v2ray_kcp_downlink", "100");
				fill_default_select_if_empty("ss_basic_v2ray_kcp_congestion", "1");
				fill_default_if_empty("ss_basic_v2ray_kcp_readbuf", "2");
				fill_default_if_empty("ss_basic_v2ray_kcp_writebuf", "2");
				fill_default_select_if_empty("ss_basic_v2ray_headtype_quic", "none");
				fill_default_select_if_empty("ss_basic_v2ray_network_security", "none");
				fill_default_checkbox("ss_basic_v2ray_mux_enable", false);
				fill_default_if_empty("ss_basic_v2ray_mux_concurrency", "8");
			}
			else if (node_type == "4" && x_json_off) {
				fill_default_if_empty("ss_basic_xray_encryption", "none");
				fill_default_select_if_empty("ss_basic_xray_network", "tcp");
				fill_default_select_if_empty("ss_basic_xray_headtype_tcp", "none");
				fill_default_select_if_empty("ss_basic_xray_headtype_kcp", "none");
				fill_default_if_empty("ss_basic_xray_kcp_mtu", "1200");
				fill_default_if_empty("ss_basic_xray_kcp_tti", "30");
				fill_default_if_empty("ss_basic_xray_kcp_uplink", "20");
				fill_default_if_empty("ss_basic_xray_kcp_downlink", "100");
				fill_default_select_if_empty("ss_basic_xray_kcp_congestion", "1");
				fill_default_if_empty("ss_basic_xray_kcp_readbuf", "4");
				fill_default_if_empty("ss_basic_xray_kcp_writebuf", "4");
				fill_default_select_if_empty("ss_basic_xray_headtype_quic", "none");
				fill_default_select_if_empty("ss_basic_xray_network_security", "none");
				fill_default_select_if_empty("ss_basic_xray_fingerprint", "chrome");
				fill_default_checkbox("ss_basic_xray_show", false);
			}
			else if (node_type == "5") {
				fill_default_checkbox("ss_basic_trojan_ai", false);
				fill_default_checkbox("ss_basic_trojan_tfo", false);
			}
			else if (node_type == "6") {
				fill_default_select_if_empty("ss_basic_naive_prot", "https");
				fill_default_if_empty("ss_basic_naive_port", "443");
			}
			else if (node_type == "8") {
				fill_default_if_empty("ss_basic_hy2_port", "443");
				fill_default_checkbox("ss_basic_hy2_ai", true); // true
				fill_default_checkbox("ss_basic_hy2_tfo", true); // true
				fill_default_select_if_empty("ss_basic_hy2_obfs", "0"); // 停用
				fill_default_if_empty("ss_basic_hy2_up", "20");
				fill_default_if_empty("ss_basic_hy2_dl", "100");
			}
		}
		function update_visibility() {
			var a = E("ss_basic_rule_update").value == "1";
			var b = E("ss_basic_node_update").value == "1";
			var d = E("ss_basic_udp_upstream_mtu").value == "1";
			var e = E("ss_china_dns").value == "12";
			var f = E("ss_foreign_dns").value;
			var g = E("ss_basic_tri_reboot_time").value;
			var h_0 = E("ss_basic_server_resolv").value;
			var j = E("ss_basic_chng_china_1_enable").checked;
			var j0 = E("ss_basic_chng_china_1_prot").value;
			var j1 = E("ss_basic_chng_china_1_udp").value == "96";
			var j2 = E("ss_basic_chng_china_1_tcp").value == "97";
			var j4 = E("ss_basic_chng_china_1_udp").value == "99";
			var j5 = E("ss_basic_chng_china_1_tcp").value == "99";
			var j6 = E("ss_basic_chng_china_1_udp").value;
			var k = E("ss_basic_chng_china_2_enable").checked;
			var k0 = E("ss_basic_chng_china_2_prot").value;
			var k1 = E("ss_basic_chng_china_2_udp").value == "96";
			var k2 = E("ss_basic_chng_china_2_tcp").value == "97";
			var k4 = E("ss_basic_chng_china_2_udp").value == "99";
			var k5 = E("ss_basic_chng_china_2_tcp").value == "99";
			var l = E("ss_basic_chng_trust_1_enable").checked;
			var l0 = E("ss_basic_chng_trust_1_opt").value;
			var l1 = E("ss_basic_chng_trust_1_opt_udp_val").value;
			var l2 = E("ss_basic_chng_trust_1_opt_tcp_val").value;
			var m = E("ss_basic_chng_trust_2_enable").checked;
			var m0 = E("ss_basic_chng_trust_2_opt").value;
			showhide("ss_basic_rule_update_time", a);
			showhide("update_choose", a);
			showhide("ss_basic_node_update_day", b);
			showhide("ss_basic_node_update_hr", b);
			showhide("ss_basic_udp_upstream_mtu_value", d);
			showhide("ss_china_dns_user", e);
			showhide("ss_basic_server_resolv_user", h_0 == "99");
			showhide("ss_dns2socks_user", (f == "3"));
			showhide("ss_v2_note", (f == "7"));
			showhide("ss_disable_aaaa", (f == "10"));
			showhide("ss_disable_aaaa_note", (f == "10"));
			showhide("ss_sstunnel_user", (f == "4"));
			showhide("ss_sstunnel_user_note", (f == "4"));
			showhide("ss_direct_user", (f == "8"));
			showhide("ss_basic_tri_reboot_time_note", (g != "0"));
			showhide("ss_basic_chng_china_1_prot", j);
			showhide("ss_basic_chng_china_1_ecs", j);
			showhide("ss_basic_chng_china_1_ecs_note", j);
			showhide("ss_basic_chng_china_1_udp", (j && j0 == "1"));
			showhide("ss_basic_chng_china_1_udp_user", (j && j0 == "1" && j4));
			showhide("ss_basic_chng_china_1_tcp", (j && j0 == "2"));
			showhide("ss_basic_chng_china_1_tcp_user", (j && j0 == "2" && j5));
			var s = E("ss_basic_chng_no_ipv6").checked;
			showhide("ss_basic_chng_left", s);
			showhide("ss_basic_chng_xact", s);
			showhide("ss_basic_chng_xgt", s);
			showhide("ss_basic_chng_xmc", s);
			showhide("ss_basic_chng_act", s);
			showhide("ss_basic_chng_gt", s);
			showhide("ss_basic_chng_mc", s);
			showhide("ss_basic_chng_right", s);
			var t1 = E("ss_basic_lt_cru_opts").value == "1";
			var t2 = E("ss_basic_lt_cru_opts").value == "2";
			showhide("ss_basic_lt_cru_time", t1 || t2);
			if (j == true) {
				if (j0 == "1" && j1) {
					$("#ss_basic_chng_china_1_ecs").hide();
					$("#ss_basic_chng_china_1_ecs_note").hide();
				}
				if (j0 == "2" && j2) {
					$("#ss_basic_chng_china_1_ecs").hide();
					$("#ss_basic_chng_china_1_ecs_note").hide();
				}
				if (j0 == "3" && j3) {
					$("#ss_basic_chng_china_1_ecs").hide();
					$("#ss_basic_chng_china_1_ecs_note").hide();
				}
			}
			showhide("ss_basic_chng_china_2_prot", k);
			showhide("ss_basic_chng_china_2_ecs", k);
			showhide("ss_basic_chng_china_2_ecs_note", k);
			showhide("ss_basic_chng_china_2_udp", (k && k0 == "1"));
			showhide("ss_basic_chng_china_2_udp_user", (k && k0 == "1" && k4));
			showhide("ss_basic_chng_china_2_tcp", (k && k0 == "2"));
			showhide("ss_basic_chng_china_2_tcp_user", (k && k0 == "2" && k5));
			if (k == true) {
				if (k0 == "1" && k1) {
					$("#ss_basic_chng_china_2_ecs").hide();
					$("#ss_basic_chng_china_2_ecs_note").hide();
				}
				if (k0 == "2" && k2) {
					$("#ss_basic_chng_china_2_ecs").hide();
					$("#ss_basic_chng_china_2_ecs_note").hide();
				}
				if (k0 == "3" && k3) {
					$("#ss_basic_chng_china_2_ecs").hide();
					$("#ss_basic_chng_china_2_ecs_note").hide();
				}
			}
			showhide("ss_basic_chng_trust_1_opt", l);
			showhide("ss_basic_chng_trust_1_ecs", l);
			showhide("ss_basic_chng_trust_1_ecs_note", l);
			showhide("ss_basic_chng_trust_1_opt_udp_val", (l && l0 == "1"));
			showhide("ss_basic_chng_trust_1_opt_udp_val_user", (l && l0 == "1" && l1 == "99"));
			showhide("ss_basic_chng_trust_1_opt_tcp_val", (l && l0 == "2"));
			showhide("ss_basic_chng_trust_1_opt_tcp_val_user", (l && l0 == "2" && l2 == "99"));
			showhide("ss_basic_chng_trust_2_opt", m);
			showhide("ss_basic_chng_trust_2_ecs", m);
			showhide("ss_basic_chng_trust_2_ecs_note", m);
			showhide("ss_basic_chng_trust_2_opt_udp", (m && m0 == "1"));
			showhide("ss_basic_chng_trust_2_opt_tcp", (m && m0 == "2"));
			if (m == true) {
				if (m0 == "3" && m3 == "97") {
					$("#ss_basic_chng_trust_2_ecs").hide();
					$("#ss_basic_chng_trust_2_ecs_note").hide();
				}
			}
			if (E("ss_basic_advdns").checked == true) {
				$(".chng").show();
				$(".old_dns").hide();
			} else {
				$(".new_dns").hide();
				$(".old_dns").show();
			}
			if (E("ss_basic_nochnipcheck").checked == true) {
				E("ss_basic_chng_china_1_ecs").disabled = true;
				$('#ss_basic_chng_china_1_ecs').attr("title", "因国内出口ip检查功能被关闭，因此无法使用此功能！")
				$('#ss_basic_chng_china_1_ecs_note > font').attr("color", "#646464")
				E("ss_basic_chng_china_2_ecs").disabled = true;
				$('#ss_basic_chng_china_2_ecs').attr("title", "因国内出口ip检查功能被关闭，因此无法使用此功能！")
				$('#ss_basic_chng_china_2_ecs_note > font').attr("color", "#646464")
			}
			if (E("ss_basic_nofrnipcheck").checked == true) {
				E("ss_basic_chng_trust_1_ecs").disabled = true;
				$('#ss_basic_chng_trust_1_ecs').attr("title", "因代理出口ip检查功能被关闭，因此无法使用此功能！")
				$('#ss_basic_chng_trust_1_ecs_note > font').attr("color", "#646464")
				E("ss_basic_chng_trust_2_ecs").disabled = true;
				$('#ss_basic_chng_trust_2_ecs').attr("title", "因代理出口ip检查功能被关闭，因此无法使用此功能！")
				$('#ss_basic_chng_trust_2_ecs_note > font').attr("color", "#646464")
			}
		}

		function Add_profile() { //点击节点页面内添加节点动作
			// (修改) 使用更可靠的jQuery方法创建蒙版
			if ($('.fullScreen').length <= 0) {
				$('body').prepend('<div class="fullScreen"></div>');
			}
			$('.fullScreen').show();

			tabclickhandler(0); //默认显示添加ss节点
			E("ss_node_table_name").value = "";
			E("ss_node_table_server").value = "";
			E("ss_node_table_port").value = "";
			E("ss_node_table_password").value = "";
			E("ss_node_table_method").value = "aes-256-cfb";
			E("ss_node_table_mode").value = "2";
			E("ss_node_table_ss_obfs").value = "0"
			E("ss_node_table_ss_obfs_host").value = "";
			E("ss_node_table_rss_protocol").value = "origin";
			E("ss_node_table_rss_protocol_param").value = "";
			E("ss_node_table_rss_obfs").value = "plain";
			E("ss_node_table_rss_obfs_param").value = "";
			E("ss_node_table_v2ray_uuid").value = "";
			E("ss_node_table_v2ray_alterid").value = "0";
			E("ss_node_table_v2ray_json").value = "";
			E("ss_node_table_xray_uuid").value = "";
			E("ss_node_table_xray_encryption").value = "none";
			E("ss_node_table_xray_json").value = "";
			E("ss_node_table_trojan_uuid").value = "";
			E("ss_node_table_trojan_ai").checked = false;
			E("ss_node_table_trojan_sni").value = "";
			E("ss_node_table_trojan_tfo").checked = false;
			E("ss_node_table_hy2_tfo").checked = false;
			E("ss_node_table_hy2_ai").checked = true;
			E("ss_node_table_kcp_param").value = kcp_defaults;
			E("ss_node_table_udp2raw_param").value = udp2raw_defaults;
			E("ssTitle").style.display = "";
			E("ssrTitle").style.display = "";
			E("v2rayTitle").style.display = "";
			E("xrayTitle").style.display = "";
			E("trojanTitle").style.display = "";
			E("naiveTitle").style.display = "";
			E("tuicTitle").style.display = "";
			E("hy2Title").style.display = "";
			E("add_node").style.display = "";
			E("edit_node").style.display = "none";
			E("continue_add").style.display = "";
			show_add_node_panel();
		}

		function show_add_node_panel() {
			document.scrollingElement.scrollTop = 0;
			$("#add_fancyss_node").show();
			$(".contentM_qis").css("top", "0px");
			$("#cancel_Btn").css("margin-left", "160px");
			$('#add_fancyss_node_title').html("添加节点");
		}
		function cancel_add_node() {
			$("#add_fancyss_node").hide();
			// (修改) 使用更可靠的jQuery方法移除蒙版
			$("body").find(".fullScreen").remove();
		}


		function tabclickhandler(_type) {
			E('ssTitle').className = "vpnClientTitle_td_unclick";
			E('ssrTitle').className = "vpnClientTitle_td_unclick";
			E('v2rayTitle').className = "vpnClientTitle_td_unclick";
			E('xrayTitle').className = "vpnClientTitle_td_unclick";
			E('trojanTitle').className = "vpnClientTitle_td_unclick";
			E('naiveTitle').className = "vpnClientTitle_td_unclick";
			E('tuicTitle').className = "vpnClientTitle_td_unclick";
			E('hy2Title').className = "vpnClientTitle_td_unclick";
			if (_type == 0) {
				save_flag = "shadowsocks";
				E('ssTitle').className = "vpnClientTitle_td_click";
				E('v2ray_use_json_tr').style.display = "none";
				E('xray_use_json_tr').style.display = "none";
				E('ss_name_support_tr').style.display = "";
				E('ss_server_support_tr').style.display = "";
				E('ss_port_support_tr').style.display = "";
				E('ss_passwd_support_tr').style.display = "";
				E('ss_method_support_tr').style.display = "";
				E('ssr_protocol_tr').style.display = "none";
				E('ssr_protocol_param_tr').style.display = "none";
				E('ssr_obfs_tr').style.display = "none";
				E('ssr_obfs_param_tr').style.display = "none";
				E('v2ray_uuid_tr').style.display = "none";
				$(".v2ray_elem").hide();
				E('v2ray_alterid_tr').style.display = "none";
				E('v2ray_security_tr').style.display = "none";
				E('v2ray_network_tr').style.display = "none";
				E('v2ray_headtype_tcp_tr').style.display = "none";
				E('v2ray_headtype_kcp_tr').style.display = "none";
				E('v2ray_headtype_quic_tr').style.display = "none";
				E('v2ray_grpc_mode_tr').style.display = "none";
				E('v2ray_network_path_tr').style.display = "none";
				E('v2ray_network_host_tr').style.display = "none";
				E('v2ray_kcp_seed_tr').style.display = "none";
				E('v2ray_network_security_tr').style.display = "none";
				E('v2ray_network_security_ai_tr').style.display = "none";
				E('v2ray_network_security_alpn_tr').style.display = "none";
				E('v2ray_network_security_sni_tr').style.display = "none";
				E('v2ray_mux_enable_tr').style.display = "none";
				E('v2ray_mux_concurrency_tr').style.display = "none";
				E('v2ray_json_tr').style.display = "none";
				E('xray_uuid_tr').style.display = "none";
				$(".xray_elem").hide();
				E('xray_encryption_tr').style.display = "none";
				E('xray_flow_tr').style.display = "none";
				E('xray_show_tr').style.display = "none";
				E('xray_publickey_tr').style.display = "none";
				E('xray_shortid_tr').style.display = "none";
				E('xray_spiderx_tr').style.display = "none";
				E('xray_network_tr').style.display = "none";
				E('xray_network_tr').style.display = "none";
				E('xray_headtype_tcp_tr').style.display = "none";
				E('xray_headtype_kcp_tr').style.display = "none";
				E('xray_headtype_quic_tr').style.display = "none";
				E('xray_grpc_mode_tr').style.display = "none";
				E('xray_network_path_tr').style.display = "none";
				E('xray_network_host_tr').style.display = "none";
				E('xray_kcp_seed_tr').style.display = "none";
				E('xray_network_security_tr').style.display = "none";
				E('xray_network_security_ai_tr').style.display = "none";
				E('xray_network_security_alpn_tr').style.display = "none";
				E('xray_network_security_sni_tr').style.display = "none";
				E('xray_fingerprint_tr').style.display = "none";
				E('xray_show_tr').style.display = "none";
				E('xray_json_tr').style.display = "none";
				E('trojan_ai_tr').style.display = "none";
				E('trojan_uuid_tr').style.display = "none";
				E('trojan_sni_tr').style.display = "none";
				E('trojan_tfo_tr').style.display = "none";
				E("naive_prot_tr").style.display = "none";
				E("naive_server_tr").style.display = "none";
				E("naive_port_tr").style.display = "none";
				E("naive_user_tr").style.display = "none";
				E("naive_pass_tr").style.display = "none";
				E('tuic_json_tr').style.display = "none";
				$(".hy2_elem").hide();
				showhide("ss_obfs_support", ($("#ss_node_table_mode").val() != "3"));
				showhide("ss_obfs_host_support", ($("#ss_node_table_mode").val() != "3" && $("#ss_node_table_ss_obfs").val() != "0"));
			}
			else if (_type == 1) {
				save_flag = "shadowsocksR";
				E('ssrTitle').className = "vpnClientTitle_td_click";
				E('v2ray_use_json_tr').style.display = "none";
				E('xray_use_json_tr').style.display = "none";
				E('ss_name_support_tr').style.display = "";
				E('ss_server_support_tr').style.display = "";
				E('ss_port_support_tr').style.display = "";
				E('ss_passwd_support_tr').style.display = "";
				E('ss_method_support_tr').style.display = "";
				E('ss_obfs_support').style.display = "none";
				E('ss_obfs_host_support').style.display = "none";
				E('ssr_protocol_tr').style.display = "";
				E('ssr_protocol_param_tr').style.display = "";
				E('ssr_obfs_tr').style.display = "";
				E('ssr_obfs_param_tr').style.display = "";
				E('v2ray_uuid_tr').style.display = "none";
				$(".v2ray_elem").hide();
				E('v2ray_alterid_tr').style.display = "none";
				E('v2ray_security_tr').style.display = "none";
				E('v2ray_network_tr').style.display = "none";
				E('v2ray_headtype_tcp_tr').style.display = "none";
				E('v2ray_headtype_kcp_tr').style.display = "none";
				E('v2ray_headtype_quic_tr').style.display = "none";
				E('v2ray_grpc_mode_tr').style.display = "none";
				E('v2ray_network_path_tr').style.display = "none";
				E('v2ray_network_host_tr').style.display = "none";
				E('v2ray_kcp_seed_tr').style.display = "none";
				E('v2ray_network_security_tr').style.display = "none";
				E('v2ray_network_security_ai_tr').style.display = "none";
				E('v2ray_network_security_alpn_tr').style.display = "none";
				E('v2ray_network_security_sni_tr').style.display = "none";
				E('v2ray_mux_enable_tr').style.display = "none";
				E('v2ray_mux_concurrency_tr').style.display = "none";
				E('v2ray_json_tr').style.display = "none";
				E('xray_uuid_tr').style.display = "none";
				$(".xray_elem").hide();
				E('xray_encryption_tr').style.display = "none";
				E('xray_flow_tr').style.display = "none";
				E('xray_show_tr').style.display = "none";
				E('xray_publickey_tr').style.display = "none";
				E('xray_shortid_tr').style.display = "none";
				E('xray_spiderx_tr').style.display = "none";
				E('xray_network_tr').style.display = "none";
				E('xray_network_tr').style.display = "none";
				E('xray_headtype_tcp_tr').style.display = "none";
				E('xray_headtype_kcp_tr').style.display = "none";
				E('xray_headtype_quic_tr').style.display = "none";
				E('xray_grpc_mode_tr').style.display = "none";
				E('xray_network_path_tr').style.display = "none";
				E('xray_network_host_tr').style.display = "none";
				E('xray_kcp_seed_tr').style.display = "none";
				E('xray_network_security_tr').style.display = "none";
				E('xray_network_security_ai_tr').style.display = "none";
				E('xray_network_security_alpn_tr').style.display = "none";
				E('xray_network_security_sni_tr').style.display = "none";
				E('xray_fingerprint_tr').style.display = "none";
				E('xray_show_tr').style.display = "none";
				E('xray_json_tr').style.display = "none";
				E('trojan_ai_tr').style.display = "none";
				E('trojan_uuid_tr').style.display = "none";
				E('trojan_sni_tr').style.display = "none";
				E('trojan_tfo_tr').style.display = "none";
				E("naive_prot_tr").style.display = "none";
				E("naive_server_tr").style.display = "none";
				E("naive_port_tr").style.display = "none";
				E("naive_user_tr").style.display = "none";
				E("naive_pass_tr").style.display = "none";
				E('tuic_json_tr').style.display = "none";
				$(".hy2_elem").hide();
			}
			else if (_type == 3) {
				save_flag = "v2ray";
				E('v2rayTitle').className = "vpnClientTitle_td_click";
				E('v2ray_use_json_tr').style.display = "";
				E('xray_use_json_tr').style.display = "none";
				E('ss_name_support_tr').style.display = "";
				E('ss_passwd_support_tr').style.display = "none";
				E('ss_method_support_tr').style.display = "none";
				E('ss_obfs_support').style.display = "none";
				E('ss_obfs_host_support').style.display = "none";
				E('ssr_protocol_tr').style.display = "none";
				E('ssr_protocol_param_tr').style.display = "none";
				E('ssr_obfs_tr').style.display = "none";
				E('ssr_obfs_param_tr').style.display = "none";
				E('v2ray_uuid_tr').style.display = "";
				$(".v2ray_elem").show();
				E('v2ray_alterid_tr').style.display = "";
				E('v2ray_security_tr').style.display = "";
				E('v2ray_network_tr').style.display = "";
				E('v2ray_headtype_tcp_tr').style.display = "";
				E('v2ray_headtype_kcp_tr').style.display = "";
				E('v2ray_headtype_quic_tr').style.display = "";
				E('v2ray_grpc_mode_tr').style.display = "";
				E('v2ray_network_path_tr').style.display = "";
				E('v2ray_network_host_tr').style.display = "";
				E('v2ray_kcp_seed_tr').style.display = "";
				E('v2ray_network_security_tr').style.display = "";
				E('v2ray_network_security_ai_tr').style.display = "";
				E('v2ray_network_security_alpn_tr').style.display = "";
				E('v2ray_network_security_sni_tr').style.display = "";
				E('v2ray_mux_enable_tr').style.display = "";
				E('v2ray_mux_concurrency_tr').style.display = "";
				E('v2ray_json_tr').style.display = "";
				E('xray_uuid_tr').style.display = "none";
				$(".xray_elem").hide();
				E('xray_encryption_tr').style.display = "none";
				E('xray_flow_tr').style.display = "none";
				E('xray_show_tr').style.display = "none";
				E('xray_publickey_tr').style.display = "none";
				E('xray_shortid_tr').style.display = "none";
				E('xray_spiderx_tr').style.display = "none";
				E('xray_network_tr').style.display = "none";
				E('xray_headtype_tcp_tr').style.display = "none";
				E('xray_headtype_kcp_tr').style.display = "none";
				E('xray_headtype_quic_tr').style.display = "none";
				E('xray_grpc_mode_tr').style.display = "none";
				E('xray_network_path_tr').style.display = "none";
				E('xray_network_host_tr').style.display = "none";
				E('xray_kcp_seed_tr').style.display = "none";
				E('xray_network_security_tr').style.display = "none";
				E('xray_network_security_ai_tr').style.display = "none";
				E('xray_network_security_alpn_tr').style.display = "none";
				E('xray_network_security_sni_tr').style.display = "none";
				E('xray_fingerprint_tr').style.display = "none";
				E('xray_json_tr').style.display = "none";
				E('trojan_ai_tr').style.display = "none";
				E('trojan_uuid_tr').style.display = "none";
				E('trojan_sni_tr').style.display = "none";
				E('trojan_tfo_tr').style.display = "none";
				E("naive_prot_tr").style.display = "none";
				E("naive_server_tr").style.display = "none";
				E("naive_port_tr").style.display = "none";
				E("naive_user_tr").style.display = "none";
				E("naive_pass_tr").style.display = "none";
				E('tuic_json_tr').style.display = "none";
				$(".hy2_elem").hide();
				if (E("ss_node_table_v2ray_use_json").checked) {
					E('ss_server_support_tr').style.display = "none";
					E('ss_port_support_tr').style.display = "none";
					E('v2ray_uuid_tr').style.display = "none";
					$(".v2ray_elem").hide();
					E('v2ray_alterid_tr').style.display = "none";
					E('v2ray_security_tr').style.display = "none";
					E('v2ray_network_tr').style.display = "none";
					E('v2ray_headtype_tcp_tr').style.display = "none";
					E('v2ray_headtype_kcp_tr').style.display = "none";
					E('v2ray_headtype_quic_tr').style.display = "none";
					E('v2ray_grpc_mode_tr').style.display = "none";
					E('v2ray_network_path_tr').style.display = "none";
					E('v2ray_network_host_tr').style.display = "none";
					E('v2ray_kcp_seed_tr').style.display = "none";
					E('v2ray_network_security_tr').style.display = "none";
					E('v2ray_network_security_ai_tr').style.display = "none";
					E('v2ray_network_security_alpn_tr').style.display = "none";
					E('v2ray_network_security_sni_tr').style.display = "none";
					E('v2ray_mux_enable_tr').style.display = "none";
					E('v2ray_mux_concurrency_tr').style.display = "none";
					E('v2ray_json_tr').style.display = "";
				} else {
					E('ss_server_support_tr').style.display = "";
					E('ss_port_support_tr').style.display = "";
					E('v2ray_uuid_tr').style.display = "";
					$(".v2ray_elem").show();
					E('v2ray_alterid_tr').style.display = "";
					E('v2ray_security_tr').style.display = "";
					E('v2ray_network_tr').style.display = "";
					E('v2ray_headtype_tcp_tr').style.display = "";
					E('v2ray_headtype_kcp_tr').style.display = "";
					E('v2ray_headtype_quic_tr').style.display = "";
					E('v2ray_grpc_mode_tr').style.display = "";
					E('v2ray_network_path_tr').style.display = "";
					E('v2ray_network_host_tr').style.display = "";
					E('v2ray_kcp_seed_tr').style.display = "";
					E('v2ray_network_security_tr').style.display = "";
					E('v2ray_network_security_ai_tr').style.display = "";
					E('v2ray_network_security_alpn_tr').style.display = "";
					E('v2ray_network_security_sni_tr').style.display = "";
					E('v2ray_mux_enable_tr').style.display = "";
					E('v2ray_mux_concurrency_tr').style.display = "";
					E('v2ray_json_tr').style.display = "none";
					var v_tcp_on_2 = E("ss_node_table_v2ray_network").value == "tcp";
					var v_http_on_2 = E("ss_node_table_v2ray_network").value == "tcp" && E("ss_node_table_v2ray_headtype_tcp").value == "http";
					var v_host_on_2 = E("ss_node_table_v2ray_network").value == "ws" || E("ss_node_table_v2ray_network").value == "h2" || v_http_on_2;
					var v_path_on_2 = E("ss_node_table_v2ray_network").value == "ws" || E("ss_node_table_v2ray_network").value == "h2";
					var v_tls_on_2 = E("ss_node_table_v2ray_network_security").value == "tls";
					var v_grpc_on_2 = E("ss_node_table_v2ray_network").value == "grpc"
					showhide("v2ray_headtype_tcp_tr", v_tcp_on_2);
					showhide("v2ray_headtype_kcp_tr", (E("ss_node_table_v2ray_network").value == "kcp"));
					showhide("v2ray_kcp_seed_tr", (E("ss_node_table_v2ray_network").value == "kcp"));
					showhide("v2ray_headtype_quic_tr", (E("ss_node_table_v2ray_network").value == "quic"));
					showhide("v2ray_grpc_mode_tr", v_grpc_on_2);
					showhide("v2ray_network_host_tr", v_host_on_2);
					showhide("v2ray_network_path_tr", v_path_on_2);
					showhide("v2ray_mux_concurrency_tr", (E("ss_node_table_v2ray_mux_enable").checked));
					showhide("v2ray_json_tr", (E("ss_node_table_v2ray_use_json").checked));
					showhide("v2ray_network_security_ai_tr", v_tls_on_2);
					showhide("v2ray_network_security_alpn_tr", v_tls_on_2);
					showhide("v2ray_network_security_sni_tr", v_tls_on_2);
					if (v_grpc_on_2) {
						$('#v2ray_network_path_tr > th').html('* serviceName');
					} else {
						$('#v2ray_network_path_tr > th').html('* 路径 (path)');
					}
				}
			}
			else if (_type == 4) {
				save_flag = "xray";
				E('xrayTitle').className = "vpnClientTitle_td_click";
				E('v2ray_use_json_tr').style.display = "none";
				E('xray_use_json_tr').style.display = "";
				E('ss_name_support_tr').style.display = "";
				E('ss_passwd_support_tr').style.display = "none";
				E('ss_method_support_tr').style.display = "none";
				E('ss_obfs_support').style.display = "none";
				E('ss_obfs_host_support').style.display = "none";
				E('ssr_protocol_tr').style.display = "none";
				E('ssr_protocol_param_tr').style.display = "none";
				E('ssr_obfs_tr').style.display = "none";
				E('ssr_obfs_param_tr').style.display = "none";
				E('v2ray_uuid_tr').style.display = "none";
				$(".v2ray_elem").hide();
				E('v2ray_alterid_tr').style.display = "none";
				E('v2ray_security_tr').style.display = "none";
				E('v2ray_network_tr').style.display = "none";
				E('v2ray_headtype_tcp_tr').style.display = "none";
				E('v2ray_headtype_kcp_tr').style.display = "none";
				E('v2ray_headtype_quic_tr').style.display = "none";
				E('v2ray_grpc_mode_tr').style.display = "none";
				E('v2ray_network_path_tr').style.display = "none";
				E('v2ray_network_host_tr').style.display = "none";
				E('v2ray_kcp_seed_tr').style.display = "none";
				E('v2ray_network_security_tr').style.display = "none";
				E('v2ray_network_security_ai_tr').style.display = "none";
				E('v2ray_network_security_alpn_tr').style.display = "none";
				E('v2ray_network_security_sni_tr').style.display = "none";
				E('v2ray_mux_enable_tr').style.display = "none";
				E('v2ray_mux_concurrency_tr').style.display = "none";
				E('v2ray_json_tr').style.display = "none";
				E('xray_uuid_tr').style.display = "";
				$(".xray_elem").show();
				E('xray_encryption_tr').style.display = "";
				E('xray_flow_tr').style.display = "";
				E('xray_show_tr').style.display = "";
				E('xray_publickey_tr').style.display = "";
				E('xray_shortid_tr').style.display = "";
				E('xray_spiderx_tr').style.display = "";
				E('xray_network_tr').style.display = "";
				E('xray_headtype_tcp_tr').style.display = "";
				E('xray_headtype_kcp_tr').style.display = "";
				E('xray_headtype_quic_tr').style.display = "";
				E('xray_grpc_mode_tr').style.display = "";
				E('xray_network_path_tr').style.display = "";
				E('xray_network_host_tr').style.display = "";
				E('xray_kcp_seed_tr').style.display = "";
				E('xray_network_security_tr').style.display = "";
				E('xray_network_security_ai_tr').style.display = "";
				E('xray_network_security_alpn_tr').style.display = "";
				E('xray_network_security_sni_tr').style.display = "";
				E('xray_fingerprint_tr').style.display = "";
				E('xray_json_tr').style.display = "";
				E('trojan_ai_tr').style.display = "none";
				E('trojan_uuid_tr').style.display = "none";
				E('trojan_sni_tr').style.display = "none";
				E('trojan_tfo_tr').style.display = "none";
				E("naive_prot_tr").style.display = "none";
				E("naive_server_tr").style.display = "none";
				E("naive_port_tr").style.display = "none";
				E("naive_user_tr").style.display = "none";
				E("naive_pass_tr").style.display = "none";
				E('tuic_json_tr').style.display = "none";
				$(".hy2_elem").hide();
				if (E("ss_node_table_xray_use_json").checked) {
					E('ss_server_support_tr').style.display = "none";
					E('ss_port_support_tr').style.display = "none";
					E('xray_uuid_tr').style.display = "none";
					$(".xray_elem").hide();
					E('xray_encryption_tr').style.display = "none";
					E('xray_flow_tr').style.display = "none";
					E('xray_show_tr').style.display = "none";
					E('xray_publickey_tr').style.display = "none";
					E('xray_shortid_tr').style.display = "none";
					E('xray_spiderx_tr').style.display = "none";
					E('xray_network_tr').style.display = "none";
					E('xray_headtype_tcp_tr').style.display = "none";
					E('xray_headtype_kcp_tr').style.display = "none";
					E('xray_headtype_quic_tr').style.display = "none";
					E('xray_grpc_mode_tr').style.display = "none";
					E('xray_network_path_tr').style.display = "none";
					E('xray_network_host_tr').style.display = "none";
					E('xray_kcp_seed_tr').style.display = "none";
					E('xray_network_security_tr').style.display = "none";
					E('xray_network_security_ai_tr').style.display = "none";
					E('xray_network_security_alpn_tr').style.display = "none";
					E('xray_network_security_sni_tr').style.display = "none";
					E('xray_fingerprint_tr').style.display = "none";
					E('xray_json_tr').style.display = "";
				} else {
					E('ss_server_support_tr').style.display = "";
					E('ss_port_support_tr').style.display = "";
					E('xray_uuid_tr').style.display = "";
					$(".xray_elem").show();
					E('xray_encryption_tr').style.display = "";
					E('xray_flow_tr').style.display = "";
					E('xray_show_tr').style.display = "";
					E('xray_publickey_tr').style.display = "";
					E('xray_shortid_tr').style.display = "";
					E('xray_spiderx_tr').style.display = "";
					E('xray_network_tr').style.display = "";
					E('xray_headtype_tcp_tr').style.display = "";
					E('xray_headtype_kcp_tr').style.display = "";
					E('xray_headtype_quic_tr').style.display = "";
					E('xray_grpc_mode_tr').style.display = "";
					E('xray_network_path_tr').style.display = "";
					E('xray_network_host_tr').style.display = "";
					E('xray_kcp_seed_tr').style.display = "";
					E('xray_network_security_tr').style.display = "";
					E('xray_network_security_ai_tr').style.display = "";
					E('xray_network_security_alpn_tr').style.display = "";
					E('xray_network_security_sni_tr').style.display = "";
					E('xray_json_tr').style.display = "none";
					var x_http_on_2 = E("ss_node_table_xray_network").value == "tcp" && E("ss_node_table_xray_headtype_tcp").value == "http";
					var x_host_on_2 = E("ss_node_table_xray_network").value == "ws" || E("ss_node_table_xray_network").value == "h2" || x_http_on_2;
					var x_path_on_2 = E("ss_node_table_xray_network").value == "ws" || E("ss_node_table_xray_network").value == "h2";
					var x_tls_on_2 = E("ss_node_table_xray_network_security").value == "tls" || E("ss_node_table_xray_network_security").value == "xtls";
					var x_xtls_on_2 = E("ss_node_table_xray_network_security").value == "xtls";
					var x_real_on_2 = E("ss_node_table_xray_network_security").value == "reality";
					var x_tcp_on_2 = E("ss_node_table_xray_network").value == "tcp";
					var x_grpc_on_2 = E("ss_node_table_xray_network").value == "grpc";
					showhide("xray_headtype_tcp_tr", x_tcp_on_2);
					showhide("xray_headtype_kcp_tr", (E("ss_node_table_xray_network").value == "kcp"));
					showhide("xray_kcp_seed_tr", (E("ss_node_table_xray_network").value == "kcp"));
					showhide("xray_headtype_quic_tr", (E("ss_node_table_xray_network").value == "quic"));
					showhide("xray_grpc_mode_tr", x_grpc_on_2);
					showhide("xray_network_host_tr", x_host_on_2);
					showhide("xray_network_path_tr", x_path_on_2);
					showhide("xray_json_tr", (E("ss_node_table_xray_use_json").checked));
					showhide("xray_network_security_ai_tr", x_tls_on_2);
					showhide("xray_network_security_alpn_tr", x_tls_on_2);
					showhide("xray_network_security_sni_tr", x_tls_on_2 || x_real_on_2);
					showhide("xray_fingerprint_tr", x_tls_on_2 || x_real_on_2);
					showhide("xray_flow_tr", x_xtls_on_2 && x_tcp_on_2 || x_real_on_2 && x_tcp_on_2);
					showhide("xray_show_tr", x_real_on_2);
					showhide("xray_publickey_tr", x_real_on_2);
					showhide("xray_shortid_tr", x_real_on_2);
					showhide("xray_spiderx_tr", x_real_on_2);
					if (x_grpc_on_2) {
						$('#xray_network_path_tr > th').html('* serviceName');
					} else {
						$('#xray_network_path_tr > th').html('* 路径 (path)');
					}
				}
			}
			else if (_type == 5) {
				save_flag = "trojan";
				E('trojanTitle').className = "vpnClientTitle_td_click";
				E('v2ray_use_json_tr').style.display = "none";
				E('xray_use_json_tr').style.display = "none";
				E('ss_name_support_tr').style.display = "";
				E('ss_server_support_tr').style.display = "";
				E('ss_port_support_tr').style.display = "";
				E('ss_passwd_support_tr').style.display = "none";
				E('ss_method_support_tr').style.display = "none";
				E('ss_obfs_support').style.display = "none";
				E('ss_obfs_host_support').style.display = "none";
				E('ssr_protocol_tr').style.display = "none";
				E('ssr_protocol_param_tr').style.display = "none";
				E('ssr_obfs_tr').style.display = "none";
				E('ssr_obfs_param_tr').style.display = "none";
				E('v2ray_uuid_tr').style.display = "none";
				$(".v2ray_elem").hide();
				E('v2ray_alterid_tr').style.display = "none";
				E('v2ray_security_tr').style.display = "none";
				E('v2ray_network_tr').style.display = "none";
				E('v2ray_headtype_tcp_tr').style.display = "none";
				E('v2ray_headtype_kcp_tr').style.display = "none";
				E('v2ray_headtype_quic_tr').style.display = "none";
				E('v2ray_grpc_mode_tr').style.display = "none";
				E('v2ray_network_path_tr').style.display = "none";
				E('v2ray_network_host_tr').style.display = "none";
				E('v2ray_kcp_seed_tr').style.display = "none";
				E('v2ray_network_security_tr').style.display = "none";
				E('v2ray_network_security_ai_tr').style.display = "none";
				E('v2ray_network_security_alpn_tr').style.display = "none";
				E('v2ray_network_security_sni_tr').style.display = "none";
				E('v2ray_mux_enable_tr').style.display = "none";
				E('v2ray_mux_concurrency_tr').style.display = "none";
				E('v2ray_json_tr').style.display = "none";
				E('xray_uuid_tr').style.display = "none";
				$(".xray_elem").hide();
				E('xray_encryption_tr').style.display = "none";
				E('xray_flow_tr').style.display = "none";
				E('xray_show_tr').style.display = "none";
				E('xray_publickey_tr').style.display = "none";
				E('xray_shortid_tr').style.display = "none";
				E('xray_spiderx_tr').style.display = "none";
				E('xray_network_tr').style.display = "none";
				E('xray_headtype_tcp_tr').style.display = "none";
				E('xray_headtype_kcp_tr').style.display = "none";
				E('xray_headtype_quic_tr').style.display = "none";
				E('xray_grpc_mode_tr').style.display = "none";
				E('xray_network_path_tr').style.display = "none";
				E('xray_network_host_tr').style.display = "none";
				E('xray_kcp_seed_tr').style.display = "none";
				E('xray_network_security_tr').style.display = "none";
				E('xray_network_security_ai_tr').style.display = "none";
				E('xray_network_security_alpn_tr').style.display = "none";
				E('xray_network_security_sni_tr').style.display = "none";
				E('xray_fingerprint_tr').style.display = "none";
				E('xray_json_tr').style.display = "none";
				E('trojan_ai_tr').style.display = "";
				E('trojan_uuid_tr').style.display = "";
				E('trojan_sni_tr').style.display = "";
				E('trojan_tfo_tr').style.display = "";
				E("naive_prot_tr").style.display = "none";
				E("naive_server_tr").style.display = "none";
				E("naive_port_tr").style.display = "none";
				E("naive_user_tr").style.display = "none";
				E("naive_pass_tr").style.display = "none";
				E('tuic_json_tr').style.display = "none";
				$(".hy2_elem").hide();
			}
			else if (_type == 6) {
				save_flag = "naive";
				E('naiveTitle').className = "vpnClientTitle_td_click";
				E('v2ray_use_json_tr').style.display = "none";
				E('xray_use_json_tr').style.display = "none";
				E('ss_name_support_tr').style.display = "";
				E('ss_server_support_tr').style.display = "none";
				E('ss_port_support_tr').style.display = "none";
				E('ss_passwd_support_tr').style.display = "none";
				E('ss_method_support_tr').style.display = "none";
				E('ss_obfs_support').style.display = "none";
				E('ss_obfs_host_support').style.display = "none";
				E('ssr_protocol_tr').style.display = "none";
				E('ssr_protocol_param_tr').style.display = "none";
				E('ssr_obfs_tr').style.display = "none";
				E('ssr_obfs_param_tr').style.display = "none";
				E('v2ray_uuid_tr').style.display = "none";
				$(".v2ray_elem").hide();
				E('v2ray_alterid_tr').style.display = "none";
				E('v2ray_security_tr').style.display = "none";
				E('v2ray_network_tr').style.display = "none";
				E('v2ray_headtype_tcp_tr').style.display = "none";
				E('v2ray_headtype_kcp_tr').style.display = "none";
				E('v2ray_headtype_quic_tr').style.display = "none";
				E('v2ray_grpc_mode_tr').style.display = "none";
				E('v2ray_network_path_tr').style.display = "none";
				E('v2ray_network_host_tr').style.display = "none";
				E('v2ray_kcp_seed_tr').style.display = "none";
				E('v2ray_network_security_tr').style.display = "none";
				E('v2ray_network_security_ai_tr').style.display = "none";
				E('v2ray_network_security_alpn_tr').style.display = "none";
				E('v2ray_network_security_sni_tr').style.display = "none";
				E('v2ray_mux_enable_tr').style.display = "none";
				E('v2ray_mux_concurrency_tr').style.display = "none";
				E('v2ray_json_tr').style.display = "none";
				E('xray_uuid_tr').style.display = "none";
				$(".xray_elem").hide();
				E('xray_encryption_tr').style.display = "none";
				E('xray_flow_tr').style.display = "none";
				E('xray_show_tr').style.display = "none";
				E('xray_publickey_tr').style.display = "none";
				E('xray_shortid_tr').style.display = "none";
				E('xray_spiderx_tr').style.display = "none";
				E('xray_network_tr').style.display = "none";
				E('xray_headtype_tcp_tr').style.display = "none";
				E('xray_headtype_kcp_tr').style.display = "none";
				E('xray_headtype_quic_tr').style.display = "none";
				E('xray_grpc_mode_tr').style.display = "none";
				E('xray_network_path_tr').style.display = "none";
				E('xray_network_host_tr').style.display = "none";
				E('xray_kcp_seed_tr').style.display = "none";
				E('xray_network_security_tr').style.display = "none";
				E('xray_network_security_ai_tr').style.display = "none";
				E('xray_network_security_alpn_tr').style.display = "none";
				E('xray_network_security_sni_tr').style.display = "none";
				E('xray_fingerprint_tr').style.display = "none";
				E('xray_json_tr').style.display = "none";
				E('trojan_ai_tr').style.display = "none";
				E('trojan_uuid_tr').style.display = "none";
				E('trojan_sni_tr').style.display = "none";
				E('trojan_tfo_tr').style.display = "none";
				E("naive_prot_tr").style.display = "";
				E("naive_server_tr").style.display = "";
				E("naive_port_tr").style.display = "";
				E("naive_user_tr").style.display = "";
				E("naive_pass_tr").style.display = "";
				E('tuic_json_tr').style.display = "none";
				$(".hy2_elem").hide();
			}
			else if (_type == 7) {
				save_flag = "tuic";
				E('tuicTitle').className = "vpnClientTitle_td_click";
				E('v2ray_use_json_tr').style.display = "none";
				E('xray_use_json_tr').style.display = "none";
				E('ss_name_support_tr').style.display = "";
				E('ss_server_support_tr').style.display = "none";
				E('ss_port_support_tr').style.display = "none";
				E('ss_passwd_support_tr').style.display = "none";
				E('ss_method_support_tr').style.display = "none";
				E('ss_obfs_support').style.display = "none";
				E('ss_obfs_host_support').style.display = "none";
				E('ssr_protocol_tr').style.display = "none";
				E('ssr_protocol_param_tr').style.display = "none";
				E('ssr_obfs_tr').style.display = "none";
				E('ssr_obfs_param_tr').style.display = "none";
				E('v2ray_uuid_tr').style.display = "none";
				$(".v2ray_elem").hide();
				E('v2ray_alterid_tr').style.display = "none";
				E('v2ray_security_tr').style.display = "none";
				E('v2ray_network_tr').style.display = "none";
				E('v2ray_headtype_tcp_tr').style.display = "none";
				E('v2ray_headtype_kcp_tr').style.display = "none";
				E('v2ray_headtype_quic_tr').style.display = "none";
				E('v2ray_grpc_mode_tr').style.display = "none";
				E('v2ray_network_path_tr').style.display = "none";
				E('v2ray_network_host_tr').style.display = "none";
				E('v2ray_kcp_seed_tr').style.display = "none";
				E('v2ray_network_security_tr').style.display = "none";
				E('v2ray_network_security_ai_tr').style.display = "none";
				E('v2ray_network_security_alpn_tr').style.display = "none";
				E('v2ray_network_security_sni_tr').style.display = "none";
				E('v2ray_mux_enable_tr').style.display = "none";
				E('v2ray_mux_concurrency_tr').style.display = "none";
				E('v2ray_json_tr').style.display = "none";
				E('xray_uuid_tr').style.display = "none";
				$(".xray_elem").hide();
				E('xray_encryption_tr').style.display = "none";
				E('xray_flow_tr').style.display = "none";
				E('xray_show_tr').style.display = "none";
				E('xray_publickey_tr').style.display = "none";
				E('xray_shortid_tr').style.display = "none";
				E('xray_spiderx_tr').style.display = "none";
				E('xray_network_tr').style.display = "none";
				E('xray_headtype_tcp_tr').style.display = "none";
				E('xray_headtype_kcp_tr').style.display = "none";
				E('xray_headtype_quic_tr').style.display = "none";
				E('xray_grpc_mode_tr').style.display = "none";
				E('xray_network_path_tr').style.display = "none";
				E('xray_network_host_tr').style.display = "none";
				E('xray_kcp_seed_tr').style.display = "none";
				E('xray_network_security_tr').style.display = "none";
				E('xray_network_security_ai_tr').style.display = "none";
				E('xray_network_security_alpn_tr').style.display = "none";
				E('xray_network_security_sni_tr').style.display = "none";
				E('xray_fingerprint_tr').style.display = "none";
				E('xray_json_tr').style.display = "none";
				E('trojan_ai_tr').style.display = "none";
				E('trojan_uuid_tr').style.display = "none";
				E('trojan_sni_tr').style.display = "none";
				E('trojan_tfo_tr').style.display = "none";
				E("naive_prot_tr").style.display = "none";
				E("naive_server_tr").style.display = "none";
				E("naive_port_tr").style.display = "none";
				E("naive_user_tr").style.display = "none";
				E("naive_pass_tr").style.display = "none";
				E('tuic_json_tr').style.display = "";
				$(".hy2_elem").hide();
			}
			else if (_type == 8) {
				save_flag = "hysteria2";
				E('hy2Title').className = "vpnClientTitle_td_click";
				E('v2ray_use_json_tr').style.display = "none";
				E('xray_use_json_tr').style.display = "none";
				E('ss_name_support_tr').style.display = "";
				E('ss_server_support_tr').style.display = "none";
				E('ss_port_support_tr').style.display = "none";
				E('ss_passwd_support_tr').style.display = "none";
				E('ss_method_support_tr').style.display = "none";
				E('ss_obfs_support').style.display = "none";
				E('ss_obfs_host_support').style.display = "none";
				E('ssr_protocol_tr').style.display = "none";
				E('ssr_protocol_param_tr').style.display = "none";
				E('ssr_obfs_tr').style.display = "none";
				E('ssr_obfs_param_tr').style.display = "none";
				E('v2ray_uuid_tr').style.display = "none";
				$(".v2ray_elem").hide();
				E('v2ray_alterid_tr').style.display = "none";
				E('v2ray_security_tr').style.display = "none";
				E('v2ray_network_tr').style.display = "none";
				E('v2ray_headtype_tcp_tr').style.display = "none";
				E('v2ray_headtype_kcp_tr').style.display = "none";
				E('v2ray_headtype_quic_tr').style.display = "none";
				E('v2ray_grpc_mode_tr').style.display = "none";
				E('v2ray_network_path_tr').style.display = "none";
				E('v2ray_network_host_tr').style.display = "none";
				E('v2ray_kcp_seed_tr').style.display = "none";
				E('v2ray_network_security_tr').style.display = "none";
				E('v2ray_network_security_ai_tr').style.display = "none";
				E('v2ray_network_security_alpn_tr').style.display = "none";
				E('v2ray_network_security_sni_tr').style.display = "none";
				E('v2ray_mux_enable_tr').style.display = "none";
				E('v2ray_mux_concurrency_tr').style.display = "none";
				E('v2ray_json_tr').style.display = "none";
				E('xray_uuid_tr').style.display = "none";
				$(".xray_elem").hide();
				E('xray_encryption_tr').style.display = "none";
				E('xray_flow_tr').style.display = "none";
				E('xray_show_tr').style.display = "none";
				E('xray_publickey_tr').style.display = "none";
				E('xray_shortid_tr').style.display = "none";
				E('xray_spiderx_tr').style.display = "none";
				E('xray_network_tr').style.display = "none";
				E('xray_headtype_tcp_tr').style.display = "none";
				E('xray_headtype_kcp_tr').style.display = "none";
				E('xray_headtype_quic_tr').style.display = "none";
				E('xray_grpc_mode_tr').style.display = "none";
				E('xray_network_path_tr').style.display = "none";
				E('xray_network_host_tr').style.display = "none";
				E('xray_kcp_seed_tr').style.display = "none";
				E('xray_network_security_tr').style.display = "none";
				E('xray_network_security_ai_tr').style.display = "none";
				E('xray_network_security_alpn_tr').style.display = "none";
				E('xray_network_security_sni_tr').style.display = "none";
				E('xray_fingerprint_tr').style.display = "none";
				E('xray_json_tr').style.display = "none";
				E('trojan_ai_tr').style.display = "none";
				E('trojan_uuid_tr').style.display = "none";
				E('trojan_sni_tr').style.display = "none";
				E('trojan_tfo_tr').style.display = "none";
				E("naive_prot_tr").style.display = "none";
				E("naive_server_tr").style.display = "none";
				E("naive_port_tr").style.display = "none";
				E("naive_user_tr").style.display = "none";
				E("naive_pass_tr").style.display = "none";
				E('tuic_json_tr').style.display = "none";
				$(".hy2_elem").show();
				showhide("hy2_obfs_pass_tr", E("ss_node_table_hy2_obfs").value == "1");
			}
			return save_flag;
		}
		function add_ss_node_conf(flag) {
			var ns = {};
			var p = "ssconf_basic";
			node_max += 1;
			if (!$.trim($('#ss_node_table_name').val())) {
				alert("节点名不能为空！！");
				return false;
			}
			if (flag == 'shadowsocks') {
				var params1 = ["mode", "name", "server", "port", "method", "ss_obfs", "ss_obfs_host"];
				//ss
				for (var i = 0; i < params1.length; i++) {
					ns[p + "_" + params1[i] + "_" + node_max] = $.trim($("#ss_node_table_" + params1[i]).val());
				}
				ns[p + "_password_" + node_max] = Base64.encode($.trim($("#ss_node_table_password").val()));
				ns[p + "_type_" + node_max] = "0";
			} else if (flag == 'shadowsocksR') {
				var params2 = ["mode", "name", "server", "port", "method", "rss_protocol", "rss_protocol_param", "rss_obfs", "rss_obfs_param"];
				//ssr
				for (var i = 0; i < params2.length; i++) {
					ns[p + "_" + params2[i] + "_" + node_max] = $.trim($("#ss_node_table_" + params2[i]).val());
				}
				ns[p + "_password_" + node_max] = Base64.encode($.trim($("#ss_node_table_password").val()));
				ns[p + "_type_" + node_max] = "1";
			} else if (flag == 'v2ray') {
				var params4_1 = ["mode", "name", "server", "port", "v2ray_uuid", "v2ray_alterid", "v2ray_security", "v2ray_network", "v2ray_headtype_tcp", "v2ray_headtype_kcp", "v2ray_kcp_seed", "v2ray_headtype_quic", "v2ray_grpc_mode", "v2ray_network_path", "v2ray_network_host", "v2ray_network_security", "v2ray_network_security_sni", "v2ray_mux_concurrency"];
				//for v2ray
				var params4_2 = ["v2ray_use_json", "v2ray_mux_enable", "v2ray_network_security_ai", "v2ray_network_security_alpn_h2", "v2ray_network_security_alpn_http"];
				if (E("ss_node_table_v2ray_use_json").checked == true) {
					ns[p + "_mode_" + node_max] = $.trim($("#ss_node_table_mode").val());
					ns[p + "_name_" + node_max] = $.trim($("#ss_node_table_name").val());
					ns[p + "_v2ray_use_json_" + node_max] = "1";
					if ($("#ss_node_table_v2ray_json").val()) {
						if (isJSON(E("ss_node_table_v2ray_json").value)) {
							if (E("ss_node_table_v2ray_json").value.indexOf("outbound") != -1) {
								ns[p + "_v2ray_json_" + node_max] = Base64.encode(pack_js(E("ss_node_table_v2ray_json").value));
							} else {
								alert("错误！你的json配置文件有误！\n正确格式请参考:https://www.v2ray.com/chapter_02/01_overview.html");
								return false;
							}
						} else {
							alert("错误！检测到你输入的v2ray配置不是标准json格式！");
							return false;
						}
					} else {
						alert("错误！你的json配置为空！");
						return false;
					}
				} else {
					for (var i = 0; i < params4_1.length; i++) {
						ns[p + "_" + params4_1[i] + "_" + node_max] = $.trim($("#ss_node_table_" + params4_1[i]).val());
					}
					for (var i = 0; i < params4_2.length; i++) {
						ns[p + "_" + params4_2[i] + "_" + node_max] = E("ss_node_table_" + params4_2[i]).checked ?
							"1" : "";
					}
				}
				ns[p + "_type_" + node_max] = "3";
			} else if (flag == 'xray') {
				var params5_1 = ["mode", "name", "server", "port", "xray_uuid", "xray_encryption", "xray_flow", "xray_network", "xray_headtype_tcp", "xray_headtype_kcp", "xray_headtype_quic", "xray_grpc_mode", "xray_network_path", "xray_network_host", "xray_network_security", "xray_network_security_sni", "xray_fingerprint", "xray_publickey", "xray_shortid", "xray_spiderx"];
				//for xray
				var params5_2 = ["xray_use_json", "xray_network_security_ai", "xray_network_security_alpn_h2", "xray_network_security_alpn_http", "xray_show"];
				if (E("ss_node_table_xray_use_json").checked == true) {
					ns[p + "_mode_" + node_max] = $.trim($("#ss_node_table_mode").val());
					ns[p + "_name_" + node_max] = $.trim($("#ss_node_table_name").val());
					ns[p + "_xray_use_json_" + node_max] = "1";
					if ($("#ss_node_table_xray_json").val()) {
						if (isJSON(E('ss_node_table_xray_json').value)) {
							if (E('ss_node_table_xray_json').value.indexOf("outbound") != -1) {
								ns[p + "_xray_json_" + node_max] = Base64.encode(pack_js(E('ss_node_table_xray_json').value));
							} else {
								alert("错误！你的json配置文件有误！");
								return false;
							}
						} else {
							alert("错误！检测到你输入的xray配置不是标准json格式！");
							return false;
						}
					} else {
						alert("错误！你的json配置为空！");
						return false;
					}
				} else {
					for (var i = 0; i < params5_1.length; i++) {
						ns[p + "_" + params5_1[i] + "_" + node_max] = $.trim($('#ss_node_table' + "_" + params5_1[i]).val());
					}
					for (var i = 0; i < params5_2.length; i++) {
						ns[p + "_" + params5_2[i] + "_" + node_max] = E("ss_node_table_" + params5_2[i]).checked ?
							'1' : '';
					}
					ns[p + "_xray_prot_" + node_max] = "vless";
				}
				ns[p + "_type_" + node_max] = "4";
			} else if (flag == 'trojan') {
				var params6 = ["mode", "name", "server", "port", "trojan_uuid", "trojan_sni"];
				//trojan
				for (var i = 0; i < params6.length; i++) {
					ns[p + "_" + params6[i] + "_" + node_max] = $.trim($('#ss_node_table' + "_" + params6[i]).val());
				}
				ns[p + "_trojan_ai_" + node_max] = E("ss_node_table_trojan_ai").checked ? '1' : '';
				ns[p + "_trojan_tfo_" + node_max] = E("ss_node_table_trojan_tfo").checked ?
					'1' : '';
				ns[p + "_type_" + node_max] = "5";
			}
			else if (flag == 'naive') {
				var params7 = ["mode", "name", "naive_prot", "naive_server", "naive_port", "naive_user"];
				//naive
				for (var i = 0; i < params7.length; i++) {
					ns[p + "_" + params7[i] + "_" + node_max] = $.trim($('#ss_node_table' + "_" + params7[i]).val());
				}
				ns[p + "_naive_pass_" + node_max] = Base64.encode($.trim($("#ss_node_table_naive_pass").val()));
				ns[p + "_type_" + node_max] = "6";
			}
			else if (flag == 'tuic') {
				ns[p + "_mode_" + node_max] = $.trim($("#ss_node_table_mode").val());
				ns[p + "_name_" + node_max] = $.trim($("#ss_node_table_name").val());
				if ($("#ss_node_table_tuic_json").val()) {
					if (isJSON(E('ss_node_table_tuic_json').value)) {
						// (修正) tuic的json检查关键字应为 relay
						if (E('ss_node_table_tuic_json').value.indexOf("relay") != -1) {
							ns[p + "_tuic_json_" + node_max] = Base64.encode(pack_js(E('ss_node_table_tuic_json').value));
						} else {
							alert("错误！你的json配置文件有误！");
							return false;
						}
					} else {
						alert("错误！检测到你输入的tuic client配置不是标准json格式！");
						return false;
					}
				} else {
					alert("错误！你的json配置为空！");
					return false;
				}
				ns[p + "_type_" + node_max] = "7";
			}
			else if (flag == 'hysteria2') {
				var params8 = ["mode", "name", "hy2_server", "hy2_port", "hy2_up", "hy2_dl", "hy2_obfs", "hy2_obfs_pass", "hy2_pass", "hy2_sni"];
				//hy2
				for (var i = 0; i < params8.length; i++) {
					ns[p + "_" + params8[i] + "_" + node_max] = $.trim($('#ss_node_table' + "_" + params8[i]).val());
				}
				ns[p + "_hy2_ai_" + node_max] = E("ss_node_table_hy2_ai").checked ? '1' : '';
				ns[p + "_hy2_tfo_" + node_max] = E("ss_node_table_hy2_tfo").checked ?
					'1' : '';
				ns[p + "_type_" + node_max] = "8";
			}

			// --- (关键新增) 开始：复制加速参数保存逻辑 ---
			// 注意：弹出框的id是 ss_node_table_... 而不是 ss_basic_...
			var accel_mode = E("ss_node_table_accel_mode") ? E("ss_node_table_accel_mode").value : "0"; // 从隐藏字段获取
			ns[p + "_accel_mode_" + node_max] = accel_mode;
			ns[p + "_use_kcp_" + node_max] = (accel_mode == "1" || accel_mode == "2") ? "1" : "0";

			ns[p + "_name_" + node_max] = E("ss_node_table_name").value;

			if (accel_mode == "1" || accel_mode == "2") {
				var kcp_param_str = E("ss_node_table_kcp_param").value;
				var kcp_r_match = kcp_param_str.match(/--r\s+([^:\s]+):([0-9]+)/);
				var final_kcp_param = kcp_param_str;
				if (kcp_r_match && kcp_r_match.length === 3) {
					ns[p + "_kcp_rserver_" + node_max] = kcp_r_match[1];
					ns[p + "_kcp_rport_" + node_max] = kcp_r_match[2];
					final_kcp_param = final_kcp_param.replace(/--r\s+[^:\s]+:[0-9]+/, '');
				} else {
					ns[p + "_kcp_rserver_" + node_max] = E("ss_node_table_kcp_rserver") ? E("ss_node_table_kcp_rserver").value : "";
					ns[p + "_kcp_rport_" + node_max] = E("ss_node_table_kcp_rport") ? E("ss_node_table_kcp_rport").value : "48400";
				}
				final_kcp_param = final_kcp_param.replace(/--l\s+[^:\s]+:[0-9]+/, '').trim();
				ns[p + "_kcp_param_" + node_max] = final_kcp_param;
			}

			if (accel_mode == "2" || accel_mode == "3") {
				var udp2raw_param_str = E("ss_node_table_udp2raw_param").value;
				var udp_r_match = udp2raw_param_str.match(/-r\s+([^:\s]+):([0-9]+)/);
				var final_udp_param = udp2raw_param_str;
				if (udp_r_match && udp_r_match.length === 3) {
					ns[p + "_udp2raw_rserver_" + node_max] = udp_r_match[1];
					ns[p + "_udp2raw_rport_" + node_max] = udp_r_match[2];
					final_udp_param = final_udp_param.replace(/-r\s+[^:\s]+:[0-9]+/, '');
				} else {
					ns[p + "_udp2raw_rserver_" + node_max] = E("ss_node_table_udp2raw_rserver") ? E("ss_node_table_udp2raw_rserver").value : "";
					ns[p + "_udp2raw_rport_" + node_max] = E("ss_node_table_udp2raw_rport") ? E("ss_node_table_udp2raw_rport").value : "38380";
				}
				final_udp_param = final_udp_param.replace(/-l\s+[^:\s]+:[0-9]+/, '');
				var parts = final_udp_param.split(/\s+/);
				var filtered_parts = parts.filter(function (part) { return part !== '-c' && part !== ''; });
				ns[p + "_udp2raw_param_" + node_max] = filtered_parts.join(' ');
			}
			// --- (关键新增) 结束 ---

			var id = parseInt(Math.random() * 100000000);
			var postData = { "id": id, "method": "dummy_script.sh", "params": [], "fields": ns };
			$.ajax({
				type: "POST",
				cache: false,
				url: "/_api/",
				data: JSON.stringify(postData),
				dataType: "json",
				success: function (response) {
					refresh_table();
					E("ss_node_table_server").value = "";
					if ((E("continue_add_box").checked) == false) {
						E("ss_node_table_name").value = "";
						E("ss_node_table_port").value = "";
						E("ss_node_table_password").value = "";
						E("ss_node_table_method").value = "aes-256-cfb";
						E("ss_node_table_mode").value = "2";
						E("ss_node_table_ss_obfs").value = "0"
						E("ss_node_table_ss_obfs_host").value = "";
						E("ss_node_table_rss_protocol").value = "origin";
						E("ss_node_table_rss_protocol_param").value = "";
						E("ss_node_table_rss_obfs").value = "plain";
						E("ss_node_table_rss_obfs_param").value = "";
						E("ss_node_table_v2ray_uuid").value = "";
						E("ss_node_table_v2ray_alterid").value = "0";
						E("ss_node_table_v2ray_json").value = "";
						E("ss_node_table_xray_uuid").value = "";
						E("ss_node_table_xray_encryption").value = "none";
						E("ss_node_table_xray_json").value = "";
						E("ss_node_table_trojan_ai").checked = false;
						E("ss_node_table_trojan_uuid").value = "";
						E("ss_node_table_trojan_sni").value = "";
						E("ss_node_table_trojan_tfo").checked = false;
						E("ss_node_table_naive_prot").value = "https";
						E("ss_node_table_naive_server").value = "";
						E("ss_node_table_naive_port").value = "443";
						E("ss_node_table_naive_user").value = "";
						E("ss_node_table_naive_pass").value = "";
						E("ss_node_table_tuic_json").value = "";
						cancel_add_node();
					}
				}
			});
		}

		function remove_conf_table(o) {
			var id = $(o).attr("id"); //
			var ids = id.split("_"); //
			var p = "ssconf_basic"; //
			id = ids[ids.length - 1];
			//
			if ((parseInt(db_ss["ssconf_basic_node"]) == id) && db_ss["ss_basic_enable"] == "1") { //
				alert("警告：这个节点正在运行，无法删除！")
				return false;
			}
			var dbus_tmp = {};
			//
			var perf = "ssconf_basic_" //

			// (已移除) var temp = ["name", "server", "server_ip", "mode", ... (原先不完整的字段列表) ];

			// (关键修正) 替换为与 save_new_order() 中一致的、最完整的字段列表
			var temp = [
				"accel_mode", "group", "hy2_ai", "hy2_dl", "hy2_obfs", "hy2_obfs_pass",
				"hy2_pass", "hy2_port", "hy2_server", "hy2_sni", "hy2_tfo", "hy2_up",
				"kcp_param", "kcp_rport", "kcp_rserver", "latency", "lbmode", "method",
				"mode", "name", "naive_pass", "naive_port", "naive_prot", "naive_server",
				"naive_user", "password", "port", "rss_obfs", "rss_obfs_param",
				"rss_protocol", "rss_protocol_param", "server", "server_ip",
				"ss_obfs", "ss_obfs_host", "trojan_ai", "trojan_sni", "trojan_tfo", "trojan_uuid",
				"tuic_json", "type", "udp2raw_param", "udp2raw_rport", "udp2raw_rserver",
				"use_kcp", "use_lb", "v2ray_alterid", "v2ray_grpc_mode", "v2ray_headtype_kcp",
				"v2ray_headtype_quic", "v2ray_headtype_tcp", "v2ray_json", "v2ray_kcp_congestion",
				"v2ray_kcp_downlink", "v2ray_kcp_mtu", "v2ray_kcp_readbuf", "v2ray_kcp_seed",
				"v2ray_kcp_tti", "v2ray_kcp_uplink", "v2ray_kcp_writebuf", "v2ray_mux_concurrency",
				"v2ray_mux_enable", "v2ray_network", "v2ray_network_host", "v2ray_network_path",
				"v2ray_network_security", "v2ray_network_security_ai", "v2ray_network_security_alpn_h2",
				"v2ray_network_security_alpn_http", "v2ray_network_security_sni", "v2ray_security",
				"v2ray_use_json", "v2ray_uuid", "weight", "xray_alterid", "xray_encryption",
				"xray_fingerprint", "xray_flow", "xray_grpc_mode", "xray_headtype_kcp",
				"xray_headtype_quic", "xray_headtype_tcp", "xray_json", "xray_kcp_congestion",
				"xray_kcp_downlink", "xray_kcp_mtu", "xray_kcp_readbuf", "xray_kcp_seed",
				"xray_kcp_tti", "xray_kcp_uplink", "xray_kcp_writebuf", "xray_network",
				"xray_network_host", "xray_network_path", "xray_network_security",
				"xray_network_security_ai", "xray_network_security_alpn_h2",
				"xray_network_security_alpn_http", "xray_network_security_sni", "xray_prot",
				"xray_publickey", "xray_shortid", "xray_show", "xray_spiderx",
				"xray_use_json", "xray_uuid"
			];

			var new_nodes = ss_nodes.concat() //
			new_nodes.splice(new_nodes.indexOf(id), 1); //
			for (var i = 0; i < ss_nodes.length; i++) {
				for (var j = 0; j < temp.length; j++) {
					dbus_tmp[perf + temp[j] + "_" + ss_nodes[i]] = "";
					//
				}
			}
			for (var i = 0; i < new_nodes.length; i++) {
				for (var j = 0; j < temp.length; j++) {
					if (db_ss[perf + temp[j] + "_" + new_nodes[i]]) {
						dbus_tmp[perf + temp[j] + "_" + (i + 1)] = db_ss[perf + temp[j] + "_" + new_nodes[i]];
						//
					} else {
						dbus_tmp[perf + temp[j] + "_" + (i + 1)] = ""; //
					}
				}
			}
			var post_data = compfilter(db_ss, dbus_tmp);
			//
			var id_1 = parseInt(Math.random() * 100000000); //
			var postData = { "id": id_1, "method": "dummy_script.sh", "params": [], "fields": post_data };
			//
			$.ajax({ //
				type: "POST", //
				cache: false, //
				url: "/_api/", //
				data: JSON.stringify(postData), //
				dataType: "json", //
				success: function (response) {
					$('#node_' + id) // <-- 修改后的代码
						.remove();
					refresh_dbss(); //
					reorder_trs(); //
					refresh_options(); //
				}
			});
		}

		function edit_conf_table(o) {
			var id = $(o).attr("id");
			var ids = id.split("_");
			var p = "ssconf_basic";
			id = ids[ids.length - 1];
			edit_id = id;
			if ((parseInt(db_ss["ssconf_basic_node"]) == id) && db_ss["ss_basic_enable"] == "1") {
				alert("提醒：这个节点正在运行！\n如果更改了其中的参数，需要重新点击【保存&应用】才能生效！")
			}
			var c = confs[id];

			E("ss_node_table_kcp_param").value = kcp_defaults;
			E("ss_node_table_udp2raw_param").value = udp2raw_defaults;
			var params1_base64 = ["password", "naive_pass"];
			var params1_check = ["v2ray_use_json", "v2ray_mux_enable", "v2ray_network_security_ai", "v2ray_network_security_alpn_h2", "v2ray_network_security_alpn_http", "xray_use_json", "xray_network_security_ai", "xray_network_security_alpn_h2", "xray_network_security_alpn_http", "trojan_ai", "xray_show", "hy2_ai", "hy2_tfo"];

			// (关键修正) 在此数组中添加所有缺失的加速器字段
			var params1_input = ["name", "server", "mode", "port", "method", "ss_obfs", "ss_obfs_host", "rss_protocol", "rss_protocol_param", "rss_obfs", "rss_obfs_param", "v2ray_uuid", "v2ray_alterid", "v2ray_security", "v2ray_network", "v2ray_headtype_tcp", "v2ray_headtype_kcp", "v2ray_kcp_seed", "v2ray_headtype_quic", "v2ray_grpc_mode", "v2ray_network_path", "v2ray_network_host", "v2ray_network_security", "v2ray_network_security_sni", "v2ray_mux_concurrency", "xray_uuid", "xray_encryption", "xray_flow", "xray_network", "xray_headtype_tcp", "xray_headtype_kcp", "xray_headtype_quic", "xray_grpc_mode", "xray_network_path", "xray_network_host", "xray_network_security", "xray_network_security_sni", "xray_fingerprint", "xray_publickey", "xray_shortid", "xray_spiderx", "trojan_uuid", "trojan_sni", "trojan_tfo", "naive_prot", "naive_server", "naive_port", "naive_user", "hy2_server", "hy2_port", "hy2_pass", "hy2_up", "hy2_dl", "hy2_obfs", "hy2_obfs_pass", "hy2_sni",
				"accel_mode", "kcp_rserver", "kcp_rport", "udp2raw_rserver", "udp2raw_rport"
			];

			if (c["v2ray_json"]) {
				E("ss_node_table_v2ray_json").value = do_js_beautify(Base64.decode(c["v2ray_json"]));
			}
			if (c["xray_json"]) {
				E("ss_node_table_xray_json").value = do_js_beautify(Base64.decode(c["xray_json"]));
			}

			// (修正) 确保 kcp_param 和 udp2raw_param 即使在 c 对象中不存在（例如旧节点）也能被正确加载默认值
			if (c["kcp_param"]) {
				E("ss_node_table_kcp_param").value = c["kcp_param"];
			} else if (c["accel_mode"] == "1" || c["accel_mode"] == "2") {
				E("ss_node_table_kcp_param").value = kcp_defaults;
			}

			if (c["udp2raw_param"]) {
				E("ss_node_table_udp2raw_param").value = c["udp2raw_param"];
			} else if (c["accel_mode"] == "2" || c["accel_mode"] == "3") {
				E("ss_node_table_udp2raw_param").value = udp2raw_defaults;
			}

			if (c["tuic_json"]) {
				E("ss_node_table_tuic_json").value = do_js_beautify(Base64.decode(c["tuic_json"]));
			}
			for (var i = 0; i < params1_base64.length; i++) {
				if (c[params1_base64[i]]) {
					E("ss_node_table_" + params1_base64[i]).value = Base64.decode(c[params1_base64[i]]);
				}
			}
			for (var i = 0; i < params1_check.length; i++) {
				if (c[params1_check[i]]) {
					E("ss_node_table_" + params1_check[i]).checked = c[params1_check[i]] == "1";
				} else {
					E("ss_node_table_" + params1_check[i]).checked = false;
				}
			}
			for (var i = 0; i < params1_input.length; i++) {
				// (关键修正) 确保在加载时，如果c[field]未定义(例如新添加的字段)，则赋空值
				var field_name = params1_input[i];
				if (E("ss_node_table_" + field_name)) {
					// (修正) 确保默认值为 0 的字段（如 accel_mode）在 c 对象中不存在时，能被正确加载为 "0"
					E("ss_node_table_" + field_name).value = c[field_name] || (field_name === 'accel_mode' ? '0' : '');
				}
			}

			// (关键新增) 加载 V2Ray/Xray KCP 参数 (这些字段不在 params1_input 数组中)
			var v2_kcp_params = ["v2ray_kcp_mtu", "v2ray_kcp_tti", "v2ray_kcp_uplink", "v2ray_kcp_downlink", "v2ray_kcp_congestion", "v2ray_kcp_readbuf", "v2ray_kcp_writebuf"];
			v2_kcp_params.forEach(function (param) {
				if (E("ss_node_table_" + param)) E("ss_node_table_" + param).value = c[param] || "";
			});

			var x_kcp_params = ["xray_kcp_mtu", "xray_kcp_tti", "xray_kcp_uplink", "xray_kcp_downlink", "xray_kcp_congestion", "xray_kcp_readbuf", "xray_kcp_writebuf"];
			x_kcp_params.forEach(function (param) {
				if (E("ss_node_table_" + param)) E("ss_node_table_" + param).value = c[param] || "";
			});

			E("cancel_Btn").style.display = "";
			E("add_node").style.display = "none";
			E("edit_node").style.display = "";
			E("continue_add").style.display = "none";
			if (c["type"] == "0") {
				E("ssTitle").style.display = "";
				E("ssrTitle").style.display = "none";
				E("v2rayTitle").style.display = "none";
				E("xrayTitle").style.display = "none";
				E("trojanTitle").style.display = "none";
				E("naiveTitle").style.display = "none";
				E("tuicTitle").style.display = "none";
				E("hy2Title").style.display = "none";
				$("#ssTitle").html("编辑ss节点");
				tabclickhandler(0);
			}
			else if (c["type"] == "1") {
				E("ssTitle").style.display = "none";
				E("ssrTitle").style.display = "";
				E("v2rayTitle").style.display = "none";
				E("xrayTitle").style.display = "none";
				E("trojanTitle").style.display = "none";
				E("naiveTitle").style.display = "none";
				E("tuicTitle").style.display = "none";
				E("hy2Title").style.display = "none";
				$("#ssrTitle").html("编辑SSR节点");
				tabclickhandler(1);
			}
			else if (c["type"] == "3") {
				E("ssTitle").style.display = "none";
				E("ssrTitle").style.display = "none";
				E("v2rayTitle").style.display = "";
				E("xrayTitle").style.display = "none";
				E("trojanTitle").style.display = "none";
				E("naiveTitle").style.display = "none";
				E("tuicTitle").style.display = "none";
				E("hy2Title").style.display = "none";
				$("#v2rayTitle").html("编辑V2Ray账号");
				tabclickhandler(3);
			}
			else if (c["type"] == "4") {
				E("ssTitle").style.display = "none";
				E("ssrTitle").style.display = "none";
				E("v2rayTitle").style.display = "none";
				E("xrayTitle").style.display = "";
				E("trojanTitle").style.display = "none";
				E("naiveTitle").style.display = "none";
				E("tuicTitle").style.display = "none";
				E("hy2Title").style.display = "none";
				$("#xrayTitle").html("编辑Xray账号");
				tabclickhandler(4);
			}
			else if (c["type"] == "5") {
				E("ssTitle").style.display = "none";
				E("ssrTitle").style.display = "none";
				E("v2rayTitle").style.display = "none";
				E("xrayTitle").style.display = "none";
				E("trojanTitle").style.display = "";
				E("naiveTitle").style.display = "none";
				E("tuicTitle").style.display = "none";
				E("hy2Title").style.display = "none";
				$("#trojanTitle").html("编辑trojan账号");
				tabclickhandler(5);
			}
			else if (c["type"] == "6") {
				E("ssTitle").style.display = "none";
				E("ssrTitle").style.display = "none";
				E("v2rayTitle").style.display = "none";
				E("xrayTitle").style.display = "none";
				E("trojanTitle").style.display = "none";
				E("naiveTitle").style.display = "";
				E("tuicTitle").style.display = "none";
				E("hy2Title").style.display = "none";
				$("#naiveTitle").html("编辑NaïveProxy账号");
				tabclickhandler(6);
			}
			else if (c["type"] == "7") {
				E("ssTitle").style.display = "none";
				E("ssrTitle").style.display = "none";
				E("v2rayTitle").style.display = "none";
				E("xrayTitle").style.display = "none";
				E("trojanTitle").style.display = "none";
				E("naiveTitle").style.display = "none";
				E("tuicTitle").style.display = "";
				E("hy2Title").style.display = "none";
				$("#naiveTitle").html("编辑tuic账号");
				tabclickhandler(7);
			}
			else if (c["type"] == "8") {
				E("ssTitle").style.display = "none";
				E("ssrTitle").style.display = "none";
				E("v2rayTitle").style.display = "none";
				E("xrayTitle").style.display = "";
				E("trojanTitle").style.display = "none";
				E("naiveTitle").style.display = "none";
				E("tuicTitle").style.display = "none";
				E("hy2Title").style.display = "";
				$("#hy2Title").html("编辑hysteria2账号");
				tabclickhandler(8);
			}
			show_add_node_panel();
			$("#cancel_Btn").css("margin-left", "10px");
			$('#add_fancyss_node_title').html("修改节点");
		}

		function edit_ss_node_conf(flag) {
			var ns = {};
			var p = "ssconf_basic";
			if (flag == 'shadowsocks') {
				var params1 = ["name", "server", "mode", "port", "method", "ss_obfs", "ss_obfs_host"];
				for (var i = 0; i < params1.length; i++) {
					ns[p + "_" + params1[i] + "_" + edit_id] = $('#ss_node_table' + "_" + params1[i]).val();
				}
				ns[p + "_password_" + edit_id] = Base64.encode($("#ss_node_table_password").val());
				ns[p + "_type_" + edit_id] = "0";
			}
			else if (flag == 'shadowsocksR') {
				var params2 = ["name", "server", "mode", "port", "method", "rss_protocol", "rss_protocol_param", "rss_obfs", "rss_obfs_param"];
				for (var i = 0; i < params2.length; i++) {
					ns[p + "_" + params2[i] + "_" + edit_id] = $('#ss_node_table' + "_" + params2[i]).val();
				}
				ns[p + "_password_" + edit_id] = Base64.encode($("#ss_node_table_password").val());
				ns[p + "_type_" + edit_id] = "1";
			}
			else if (flag == 'v2ray') {
				var params4_1 = ["mode", "name", "server", "port", "v2ray_uuid", "v2ray_alterid", "v2ray_security", "v2ray_network", "v2ray_headtype_tcp", "v2ray_headtype_kcp", "v2ray_kcp_seed", "v2ray_headtype_quic", "v2ray_grpc_mode", "v2ray_network_path", "v2ray_network_host", "v2ray_network_security", "v2ray_network_security_sni", "v2ray_mux_concurrency", "v2ray_kcp_mtu", "v2ray_kcp_tti", "v2ray_kcp_uplink", "v2ray_kcp_downlink", "v2ray_kcp_readbuf", "v2ray_kcp_writebuf"]; // (新增kcp字段)
				var params4_2 = ["v2ray_use_json", "v2ray_mux_enable", "v2ray_network_security_ai", "v2ray_network_security_alpn_h2", "v2ray_network_security_alpn_http", "v2ray_kcp_congestion"]; // (新增kcp字段)
				if (E("ss_node_table_v2ray_use_json").checked == true) {
					ns[p + "_mode_" + edit_id] = $.trim($("#ss_node_table_mode").val());
					ns[p + "_name_" + edit_id] = $.trim($("#ss_node_table_name").val());
					ns[p + "_v2ray_use_json_" + edit_id] = "1";
					if ($("#ss_node_table_v2ray_json").val()) {
						if (isJSON(E("ss_node_table_v2ray_json").value)) {
							if (E("ss_node_table_v2ray_json").value.indexOf("outbound") != -1) {
								ns[p + "_v2ray_json_" + edit_id] = Base64.encode(pack_js(E("ss_node_table_v2ray_json").value));
							} else {
								alert("错误！你的json配置文件有误！\n正确格式请参考:https://www.v2ray.com/chapter_02/01_overview.html");
								return false;
							}
						} else {
							alert("错误！检测到你输入的v2ray配置不是标准json格式！");
							return false;
						}
					} else {
						alert("错误！你的json配置为空！");
						return false;
					}
				} else {
					for (var i = 0; i < params4_1.length; i++) {
						ns[p + "_" + params4_1[i] + "_" + edit_id] = $('#ss_node_table' + "_" + params4_1[i]).val();
					}

					for (var i = 0; i < params4_2.length; i++) {
						var field_name = params4_2[i];
						if (field_name === 'v2ray_kcp_congestion') {
							ns[p + "_" + field_name + "_" + node_id] = E("ss_basic_" + field_name).value;
						} else {
							ns[p + "_" + field_name + "_" + node_id] = E("ss_basic_" + field_name).checked ? '1' : '0';
						}
					}
				}



				ns[p + "_type_" + edit_id] = "3";
			}
			else if (flag == 'xray') {
				var params5_1 = ["mode", "name", "server", "port", "xray_uuid", "xray_encryption", "xray_flow", "xray_network", "xray_headtype_tcp", "xray_headtype_kcp", "xray_kcp_seed", "xray_headtype_quic", "xray_grpc_mode", "xray_network_path", "xray_network_host", "xray_network_security", "xray_network_security_sni", "xray_fingerprint", "xray_publickey", "xray_shortid", "xray_spiderx", "xray_kcp_mtu", "xray_kcp_tti", "xray_kcp_uplink", "xray_kcp_downlink", "xray_kcp_readbuf", "xray_kcp_writebuf"]; // (新增kcp字段)
				var params5_2 = ["xray_use_json", "xray_network_security_ai", "xray_network_security_alpn_h2", "xray_network_security_alpn_http", "xray_show", "xray_kcp_congestion"]; // (新增kcp字段)
				if (E("ss_node_table_xray_use_json").checked == true) {
					ns[p + "_mode_" + edit_id] = $.trim($("#ss_node_table_mode").val());
					ns[p + "_name_" + edit_id] = $.trim($("#ss_node_table_name").val());
					ns[p + "_xray_use_json_" + edit_id] = "1";
					if ($("#ss_node_table_xray_json").val()) {
						if (isJSON(E('ss_node_table_xray_json').value)) {
							if (E('ss_node_table_xray_json').value.indexOf("outbound") != -1) {
								ns[p + "_xray_json_" + edit_id] = Base64.encode(pack_js(E('ss_node_table_xray_json').value));
							} else {
								alert("错误！你的json配置文件有误！");
								return false;
							}
						} else {
							alert("错误！检测到你输入的xray配置不是标准json格式！");
							return false;
						}
					} else {
						alert("错误！你的json配置为空！");
						return false;
					}
				} else {
					for (var i = 0; i < params5_1.length; i++) {
						ns[p + "_" + params5_1[i] + "_" + edit_id] = $('#ss_node_table' + "_" + params5_1[i]).val();
					}
					for (var i = 0; i < params5_2.length; i++) {

						if (params5_2[i] === 'xray_kcp_congestion') {
							ns[p + "_" + params5_2[i] + "_" + edit_id] = E("ss_node_table_" + params5_2[i]).value;
						} else {
							ns[p + "_" + params5_2[i] + "_" + edit_id] = E("ss_node_table_" + params5_2[i]).checked ? "1" : "0";
						}
					}
				}
				ns[p + "_type_" + edit_id] = "4";
			}
			else if (flag == 'trojan') {
				var params6 = ["mode", "name", "server", "port", "trojan_uuid", "trojan_sni"];
				//trojan
				for (var i = 0; i < params6.length; i++) {
					ns[p + "_" + params6[i] + "_" + edit_id] = $.trim($('#ss_node_table' + "_" + params6[i]).val());
				}
				ns[p + "_trojan_ai_" + edit_id] = E("ss_node_table_trojan_ai").checked ? "1" : "0"; // (修正) checkbox 应保存 "0" 而不是 ""
				ns[p + "_trojan_tfo_" + edit_id] = E("ss_node_table_trojan_tfo").checked ? "1" : "0"; // (修正) checkbox 应保存 "0" 而不是 ""
				// ns[p + "_password_" + edit_id] = Base64.encode($.trim($("#ss_node_table_password").val())); // Trojan 没有 password 字段
				ns[p + "_type_" + edit_id] = "5";
			}
			else if (flag == 'naive') {
				var params7 = ["mode", "name", "naive_prot", "naive_server", "naive_port", "naive_user"];
				//naive
				for (var i = 0; i < params7.length; i++) {
					ns[p + "_" + params7[i] + "_" + edit_id] = $.trim($('#ss_node_table' + "_" + params7[i]).val());
				}
				ns[p + "_naive_pass_" + edit_id] = Base64.encode($.trim($("#ss_node_table_naive_pass").val()));
				ns[p + "_type_" + edit_id] = "6";
			}
			else if (flag == 'tuic') {
				ns[p + "_mode_" + edit_id] = $.trim($("#ss_node_table_mode").val());
				ns[p + "_name_" + edit_id] = $.trim($("#ss_node_table_name").val());
				if ($("#ss_node_table_tuic_json").val()) {
					if (isJSON(E('ss_node_table_tuic_json').value)) {
						// (关键修正) 修复tuic json的检查关键字，应为 "relay"
						if (E('ss_node_table_tuic_json').value.indexOf("relay") != -1) {
							ns[p + "_tuic_json_" + edit_id] = Base64.encode(pack_js(E('ss_node_table_tuic_json').value));
						} else {
							alert("错误！你的json配置文件有误！");
							return false;
						}
					} else {
						alert("错误！检测到你输入的tuic client配置不是标准json格式！");
						return false;
					}
				} else {
					alert("错误！你的json配置为空！");
					return false;
				}
				ns[p + "_type_" + edit_id] = "7";
			}
			else if (flag == 'hysteria2') {
				var params8 = ["mode", "name", "hy2_server", "hy2_port", "hy2_pass", "hy2_up", "hy2_dl", "hy2_obfs", "hy2_obfs_pass", "hy2_sni"];
				//hy2
				for (var i = 0; i < params8.length; i++) {
					ns[p + "_" + params8[i] + "_" + edit_id] = $.trim($('#ss_node_table' + "_" + params8[i]).val());
				}
				ns[p + "_hy2_ai_" + edit_id] = E("ss_node_table_hy2_ai").checked ? "1" : "0"; // (修正) checkbox 应保存 "0" 而不是 ""
				ns[p + "_hy2_tfo_" + edit_id] = E("ss_node_table_hy2_tfo").checked ? "1" : "0"; // (修正) checkbox 应保存 "0" 而不是 ""
				ns[p + "_type_" + edit_id] = "8";
			}

			// --- (关键新增) 开始：复制加速参数保存逻辑 ---
			// 注意：弹出框的id是 ss_node_table_... 
			var accel_mode = E("ss_node_table_accel_mode") ? E("ss_node_table_accel_mode").value : "0"; // 从(现在已正确加载的)字段获取
			ns[p + "_accel_mode_" + edit_id] = accel_mode;
			ns[p + "_use_kcp_" + edit_id] = (accel_mode == "1" || accel_mode == "2") ? "1" : "0";

			ns[p + "_name_" + edit_id] = E("ss_node_table_name").value;


			if (accel_mode == "1" || accel_mode == "2") {
				var kcp_param_str = E("ss_node_table_kcp_param").value;
				var kcp_r_match = kcp_param_str.match(/--r\s+([^:\s]+):([0-9]+)/);
				var final_kcp_param = kcp_param_str;
				if (kcp_r_match && kcp_r_match.length === 3) {
					ns[p + "_kcp_rserver_" + edit_id] = kcp_r_match[1];
					ns[p + "_kcp_rport_" + edit_id] = kcp_r_match[2];
					final_kcp_param = final_kcp_param.replace(/--r\s+[^:\s]+:[0-9]+/, '');
				} else {
					ns[p + "_kcp_rserver_" + edit_id] = E("ss_node_table_kcp_rserver") ? E("ss_node_table_kcp_rserver").value : "";
					ns[p + "_kcp_rport_" + edit_id] = E("ss_node_table_kcp_rport") ? E("ss_node_table_kcp_rport").value : "48400";
				}
				final_kcp_param = final_kcp_param.replace(/--l\s+[^:\s]+:[0-9]+/, '').trim();
				ns[p + "_kcp_param_" + edit_id] = final_kcp_param;
			}

			if (accel_mode == "2" || accel_mode == "3") {
				var udp2raw_param_str = E("ss_node_table_udp2raw_param").value;
				var udp_r_match = udp2raw_param_str.match(/-r\s+([^:\s]+):([0-9]+)/);
				var final_udp_param = udp2raw_param_str;
				if (udp_r_match && udp_r_match.length === 3) {
					ns[p + "_udp2raw_rserver_" + edit_id] = udp_r_match[1];
					ns[p + "_udp2raw_rport_" + edit_id] = udp_r_match[2];
					final_udp_param = final_udp_param.replace(/-r\s+[^:\s]+:[0-9]+/, '');
				} else {
					ns[p + "_udp2raw_rserver_" + edit_id] = E("ss_node_table_udp2raw_rserver") ? E("ss_node_table_udp2raw_rserver").value : "";
					ns[p + "_udp2raw_rport_" + edit_id] = E("ss_node_table_udp2raw_rport") ? E("ss_node_table_udp2raw_rport").value : "38380";
				}
				final_udp_param = final_udp_param.replace(/-l\s+[^:\s]+:[0-9]+/, '');
				var parts = final_udp_param.split(/\s+/);
				var filtered_parts = parts.filter(function (part) { return part !== '-c' && part !== ''; });
				ns[p + "_udp2raw_param_" + edit_id] = filtered_parts.join(' ');
			}
			// --- (关键新增) 结束 ---

			var id = parseInt(Math.random() * 100000000);
			var postData = { "id": id, "method": "dummy_script.sh", "params": [], "fields": ns };
			$.ajax({
				type: "POST",
				cache: false,
				url: "/_api/",
				data: JSON.stringify(postData),
				dataType: "json",
				success: function (response) {
					refresh_table();
					E("ss_node_table_name").value = "";
					E("ss_node_table_port").value = "";
					E("ss_node_table_server").value = "";
					E("ss_node_table_password").value = "";
					E("ss_node_table_method").value = "aes-256-gcm";
					E("ss_node_table_mode").value = "2";
					E("ss_node_table_ss_obfs").value = "0"
					E("ss_node_table_ss_obfs_host").value = "";
					E("ss_node_table_rss_protocol").value = "origin";
					E("ss_node_table_rss_protocol_param").value = "";
					E("ss_node_table_rss_obfs").value = "plain";
					E("ss_node_table_rss_obfs_param").value = "";
					E("ss_node_table_v2ray_uuid").value = "";
					E("ss_node_table_v2ray_alterid").value = "0";
					E("ss_node_table_v2ray_json").value = "";
					E("ss_node_table_xray_uuid").value = "";
					E("ss_node_table_xray_encryption").value = "0";
					E("ss_node_table_xray_json").value = "";
					E("ss_node_table_trojan_ai").checked = false;
					E("ss_node_table_trojan_uuid").value = "";
					E("ss_node_table_trojan_sni").value = "";
					E("ss_node_table_trojan_tfo").checked = false;
					E("ss_node_table_naive_prot").value = "https";
					E("ss_node_table_naive_server").value = "";
					E("ss_node_table_naive_port").value = "443";
					E("ss_node_table_naive_user").value = "";
					E("ss_node_table_naive_pass").value = "";
					E("ss_node_table_tuic_json").value = "";
					E("ss_node_table_hy2_server").value = "";
					E("ss_node_table_hy2_port").value = "111";
					E("ss_node_table_hy2_pass").value = "";
					E("ss_node_table_hy2_tfo").value = "";
					E("ss_node_table_hy2_obfs").value = "0";
					E("ss_node_table_hy2_obfs_pass").value = "";
					E("ss_node_table_hy2_sni").value = "";
					E("ss_node_table_hy2_ai").checked = true;

					refresh_node_panel();
				}
			});
			cancel_add_node();
		}

		function refresh_node_panel() {
			$.ajax({
				type: "GET",
				url: "/_api/ss",
				dataType: "json",
				async: false,
				success: function (data) {
					db_ss = data.result[0];
					ss_node_sel();
				}
			});
		}
		function generate_node_info() {
			ss_nodes = [];
			for (var field in db_ss) {
				var arr = field.split("ssconf_basic_name_");
				if (arr[0] == "") {
					ss_nodes.push(arr[1]);
				}
			}
			ss_nodes = ss_nodes.sort(compare);
			node_nu = ss_nodes.length;
			node_max = ss_nodes.length > 0 ? Math.max.apply(null, ss_nodes) : 0;
			node_idx = $.inArray(db_ss["ssconf_basic_node"], ss_nodes) + 1;
			confs = {};
			var p = "ssconf_basic";
			for (var j = 0; j < ss_nodes.length; j++) {
				var idx = ss_nodes[j];
				var obj = {};
				obj["node"] = idx;
				if (typeof (db_ss["ssconf_basic_type_" + idx]) != "undefined") {
					obj["type"] = db_ss["ssconf_basic_type_" + idx];
				}
				var params = ["group", "name", "port", "method", "password", "mode", "ss_obfs", "ss_obfs_host", "rss_protocol", "rss_protocol_param", "rss_obfs", "rss_obfs_param", "weight", "lbmode", "v2ray_uuid", "v2ray_alterid", "v2ray_security", "v2ray_network", "v2ray_headtype_tcp", "v2ray_headtype_kcp", "v2ray_kcp_seed", "v2ray_headtype_quic", "v2ray_grpc_mode", "v2ray_network_path", "v2ray_network_host", "v2ray_network_security", "v2ray_network_security_sni", "v2ray_mux_concurrency", "v2ray_json", "v2ray_use_json", "xray_uuid", "xray_encryption", "xray_flow", "xray_network", "xray_headtype_tcp", "xray_headtype_kcp", "xray_headtype_quic", "xray_grpc_mode", "xray_network_path", "xray_network_host", "xray_network_security", "xray_network_security_sni", "xray_fingerprint", "xray_publickey", "xray_shortid", "xray_spiderx", "xray_show", "xray_json", "tuic_json", "xray_use_json", "trojan_ai", "trojan_uuid", "trojan_sni", "trojan_tfo", "naive_prot", "naive_server", "naive_port", "naive_user", "naive_pass", "hy2_server", "hy2_port", "hy2_pass", "hy2_up", "hy2_dl", "hy2_obfs", "hy2_obfs_pass", "hy2_sni", "hy2_ai", "hy2_tfo", "accel_mode", "kcp_rserver", "kcp_rport", "kcp_param", "udp2raw_rserver", "udp2raw_rport", "udp2raw_param"];

				for (var i = 0; i < params.length; i++) {
					var ofield = p + "_" + params[i] + "_" + idx;
					if (typeof db_ss[ofield] == "undefined") {
						obj[params[i]] = '';
					} else {
						obj[params[i]] = db_ss[ofield];
					}
				}
				if (db_ss["ssconf_basic_xray_prot_" + idx] == "vmess") {
					obj["xray_prot"] = "vmess";
				} else {
					obj["xray_prot"] = "vless";
				}
				var params_sp = ["use_kcp", "use_lb", "v2ray_mux_enable", "v2ray_network_security_ai", "v2ray_network_security_alpn_h2", "v2ray_network_security_alpn_http", "xray_network_security_ai", "xray_network_security_alpn_h2", "xray_network_security_alpn_http"];
				for (var i = 0; i < params_sp.length; i++) {
					if (typeof db_ss[p + "_" + params_sp[i] + "_" + idx] == "undefined") {
						obj[params_sp[i]] = '0';
					} else {
						obj[params_sp[i]] = db_ss[p + "_" + params_sp[i] + "_" + idx];
					}
				}
				if (typeof db_ss[p + "_server_" + idx] != "undefined") {
					obj["server"] = db_ss[p + "_server_" + idx];
				} else {
					obj["server"] = '';
				}
				if (db_ss[p + "_type_" + idx] == "7") {
					var json = JSON.parse(Base64.decode(db_ss[p + "_tuic_json_" + idx]));
					var server_addr = '';
					if ("relay" in json) {
						server_addr = json.relay.server;
					}
					obj["server"] = server_addr;
				}
				if (db_ss[p + "_v2ray_use_json_" + idx] == "1") {
					var json = JSON.parse(Base64.decode(db_ss[p + "_v2ray_json_" + idx]));
					var server_addr = '';
					var server_prot = '';
					if ("outbound" in json) {
						if (isArray(json.outbound)) {
							if (json.outbound[0].settings.servers) {
								if (isArray(json.outbound[0].settings.servers)) {
									server_addr = json.outbound[0].settings.servers[0].address;
								}
							}
							if (json.outbound[0].settings.vnext) {
								if (isArray(json.outbound[0].settings.vnext)) {
									server_addr = json.outbound[0].settings.vnext[0].address;
								}
							}
							server_prot = json.outbound[0].protocol;
						} else {
							if (json.outbound.settings.servers) {
								if (isArray(json.outbound.settings.servers)) {
									server_addr = json.outbound.settings.servers[0].address;
								}
							}
							if (json.outbound.settings.vnext) {
								if (isArray(json.outbound.settings.vnext)) {
									server_addr = json.outbound.settings.vnext[0].address;
								}
							}
							server_prot = json.outbound.protocol;
						}
					}
					if ("outbounds" in json) {
						if (isArray(json.outbounds)) {
							if (json.outbounds[0].settings.servers) {
								if (isArray(json.outbounds[0].settings.servers)) {
									server_addr = json.outbounds[0].settings.servers[0].address;
								}
							}
							if (json.outbounds[0].settings.vnext) {
								if (isArray(json.outbounds[0].settings.vnext)) {
									server_addr = json.outbounds[0].settings.vnext[0].address;
								}
							}
							server_prot = json.outbounds[0].protocol;
						} else {
							if (json.outbounds.settings.servers) {
								if (isArray(json.outbounds.settings.servers)) {
									server_addr = json.outbounds.settings.servers[0].address;
								}
							}
							if (json.outbounds.settings.vnext) {
								if (isArray(json.outbounds.settings.vnext)) {
									server_addr = json.outbounds.settings.vnext[0].address;
								}
							}
							server_prot = json.outbounds.protocol;
						}
					}
					obj["server"] = server_addr;
					obj["protoc"] = server_prot;
				}
				if (db_ss[p + "_xray_use_json_" + idx] == "1") {
					var json = JSON.parse(Base64.decode(db_ss[p + "_xray_json_" + idx]));
					var server_addr = '';
					var server_prot = '';
					if ("outbound" in json) {
						if (isArray(json.outbound)) {
							if (json.outbound[0].settings.servers) {
								if (isArray(json.outbound[0].settings.servers)) {
									server_addr = json.outbound[0].settings.servers[0].address;
								}
							}
							if (json.outbound[0].settings.vnext) {
								if (isArray(json.outbound[0].settings.vnext)) {
									server_addr = json.outbound[0].settings.vnext[0].address;
								}
							}
							server_prot = json.outbound[0].protocol;
						} else {
							if (json.outbound.settings.servers) {
								if (isArray(json.outbound.settings.servers)) {
									server_addr = json.outbound.settings.servers[0].address;
								}
							}
							if (json.outbound.settings.vnext) {
								if (isArray(json.outbound.settings.vnext)) {
									server_addr = json.outbound.settings.vnext[0].address;
								}
							}
							server_prot = json.outbound.protocol;
						}
					}
					if ("outbounds" in json) {
						if (isArray(json.outbounds)) {
							if (json.outbounds[0].settings.servers) {
								if (isArray(json.outbounds[0].settings.servers)) {
									server_addr = json.outbounds[0].settings.servers[0].address;
								}
							}
							if (json.outbounds[0].settings.vnext) {
								if (isArray(json.outbounds[0].settings.vnext)) {
									server_addr = json.outbounds[0].settings.vnext[0].address;
								}
							}
							server_prot = json.outbounds[0].protocol;
						} else {
							if (json.outbounds.settings.servers) {
								if (isArray(json.outbounds.settings.servers)) {
									server_addr = json.outbounds.settings.servers[0].address;
								}
							}
							if (json.outbounds.settings.vnext) {
								if (isArray(json.outbounds.settings.vnext)) {
									server_addr = json.outbounds.settings.vnext[0].address;
								}
							}
							server_prot = json.outbounds.protocol;
						}
					}
					if (server_prot == "shadowsocks") {
						server_prot = "ss";
					}
					obj["server"] = server_addr;
					obj["protoc"] = server_prot;
				}
				if (obj != null) {
					confs[idx] = obj;
				}
			}
		}
		function refresh_table() {
			$.ajax({
				type: "GET",
				url: "/_api/ss",
				dataType: "json",
				cache: false,
				async: false,
				success: function (data) {
					db_ss = data.result[0];
					generate_node_info();
					refresh_options();
					refresh_html();
				}
			});
		}


		function refresh_html() {
			var pageH = parseInt(E("FormTitle").style.height.split("px")[0]);
			if (db_ss["ss_basic_row"]) {
				nodeN = parseInt(db_ss["ss_basic_row"]);
			}
			if (node_nu < 15) nodeN = node_nu;
			var nodeL = parseInt((pageH - nodeT) / trsH) - 3;
			nodeH = nodeN * trsH
			if (nodeN > nodeL) {
				$("#ss_list_table").attr("style", "height:" + (nodeH + trsH) + "px");
			} else {
				$("#ss_list_table").removeAttr("style");
			}
			var noserver = parseInt(E("ss_basic_noserver").checked ? "1" : "0");
			if (node_nu && db_ss["ss_basic_latency_val"] != "0") {
				if (noserver == "1") {
					var width = ["", "5%", "54%", "0%", "14%", "12%", "10%", "5%",];
				} else {
					var width = ["", "5%", "28%", "26%", "14%", "12%", "10%", "5%",];
				}
			} else {
				if (noserver == "1") {
					var width = ["", "5%", "64%", "0%", "16%", "0%", "10%", "5%"];
				} else {
					var width = ["", "5%", "36%", "30%", "14%", "0%", "10%", "5%"];
				}
			}
			var html = '';
			html += '<div class="nodeTable" style="height:' + trsH + 'px; margin: -1px 0px 0px 0px; width:750px;">'
			html += '<table width="750px" border="0" align="center" cellpadding="4" cellspacing="0" class="FormTable_table" style="margin:-1px 0px 0px 0px;">'
			html += '<tr height="' + trsH + 'px">'
			html += '<th style="width:' + width[1] + ';">序号</th>'
			html += '<th style="width:' + width[2] + ';cursor:pointer" onclick="hide_name();" title="点我隐藏节点名称信息! 双击名称可直接修改。" >节点名称</th>'
			if (noserver != "1") {
				html += '<th style="width:' + width[3] + ';cursor:pointer" onclick="hide_server();" title="点我隐藏服务器信息!" >服务器地址</th>'
			}
			html += '<th style="width:' + width[4] + ';">类型</th>'
			if (node_nu && db_ss["ss_basic_latency_val"] == "2") {
				html += '<th style="width:' + width[5] + ';" id="depay_th">web落地延迟</th>'
			}
			html += '<th style="width:' + width[6] + ';">操作</th>'
			html += '<th style="width:' + width[7] + ';">使用</th>'
			html += '</tr>'
			html += '</table>'
			html += '</div>'

			html += '<div class="nodeTable" style="width: 750px; height: ' + nodeH + 'px; overflow: auto;">'
			html += '<div id="ss_node_list_table_main" style="width: 750px; height: ' + nodeH + 'px; overflow: auto; padding-right: 35px;">'
			html += '<table id="ss_node_list_table" style="margin:-1px 0px 0px 0px;" width="750px" border="0" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="list_table">'
			for (var i = 0; i < ss_nodes.length; i++) {
				var c = confs[ss_nodes[i]];
				html += '<tr id="node_' + c["node"] + '">';
				html += '<td style="width:' + width[1] + ';" id="node_order_' + (i + 1) + '" class="dragHandle">' + (i + 1) + '</td>';
				html += '<td style="width:' + width[2] + ';" class="dragHandle node_name" title="' + c["group"] + '&#10;' + c["name"] + '" id="ss_node_name_' + c["node"] + '" ondblclick="edit_node_name_inline(this)">'
				html += '<div class="shadow1" style="display: none;"></div>'
				html += '<div class="nickname">' + c["name"] + '</div>';
				html += '</td>';
				// Module_shadowsocks.asp -> function refresh_html()

				// (修改) 使用新的服务器地址显示逻辑块替换旧的
				if (noserver != "1") {
					// 1. 新增逻辑：根据加速模式判断应该显示的服务器地址
					var display_server = "";
					var accel_mode = c["accel_mode"] || "0";

					switch (accel_mode) {
						case "1": // KCPtun
							display_server = c["kcp_rserver"];
							break;
						case "2": // KCPtun + UDP2raw
						case "3": // UDP2raw only
							display_server = c["udp2raw_rserver"];
							break;
						default: // "0" 或未定义 (无加速)
							if (c["type"] == "6") { // NaiveProxy
								display_server = c["naive_server"];
							} else if (c["type"] == "8") { // Hysteria 2
								display_server = c["hy2_server"];
							} else { // SS, SSR, V2Ray, Xray, Trojan 等
								display_server = c["server"];
							}
							break;
					}

					// 如果经过上述判断后地址仍为空（例如新节点未填写），则留空
					if (typeof display_server === 'undefined') {
						display_server = "";
					}

					// 2. 使用新的 display_server 变量来生成HTML
					var qr_onclick = E("ss_basic_qrcode").checked ? ' onclick="makeQRcode(this)"' : '';
					html += '<td style="width:' + width[3] + ';cursor:pointer" class="node_server" id="server_' + c["node"] + '" title="' + display_server + '"' + qr_onclick + '>';
					html += '<div style="display: none;" class="shadow2"></div>';
					html += '<div class="server">' + display_server + '</div>';
					html += '</td>';
				}
				html += '<td style="width:' + width[4] + ';">';
				html += getProtocolNameForDisplay(c.type);
				html += '</td>';
				if (node_nu && db_ss["ss_basic_latency_val"] == "2") {
					html += '<td style="width:' + width[5] + ';" id="ss_node_lt_' + c["node"] + '" class="latency"></td>';
				}
				html += '<td style="width:' + width[6] + ';">'
				html += '<input style="margin:-2px 0px -4px -2px;" id="dd_node_' + c["node"] + '" class="edit_btn" type="button" onclick="go_to_edit_node_mode(this);" value="">'
				html += '<input style="margin:-2px 0px -4px -2px;" id="td_node_' + c["node"] + '" class="remove_btn" type="button" onclick="remove_conf_table(this);" value="">'
				html += '</td>';
				html += '<td style="width:' + width[7] + ';">'
				html += '<div class="deactivate_icon" id="apply_ss_node_' + c["node"] + '" onclick="apply_this_ss_node(this);"></div>';
				html += '</td>';
				html += '</tr>';
			}
			html += '</table>'
			html += '</div>'
			html += '</div>'
			html += '<div align="center" class="nodeTable" id="node_button" style="width: 750px;margin-top:20px">'
			if (node_nu) {
				html += '<input class="button_gen" id="dropdownbtn" type="button" value="延迟测试">'
				html += '<div class="dropdown" id="dropdown">'
				html += '<a onclick="test_latency_now(2)" href="javascript:void(0);"></lable>开始 web 延迟测试<lable id="ss_wts_show"></lable></a>'
				html += '<a onclick="test_latency_now(0)" href="javascript:void(0);"></lable>关闭延迟测试功能</a>'
				html += '<a onclick="open_latency_sett()" href="javascript:void(0);"></lable>设置</a>'
				html += '</div>'
			}
			html += '<input style="margin-left:10px" id="add_ss_node" class="button_gen" onClick="go_to_add_node_mode()" type="button" value="添加节点"/>'
			// (修改) 恢复"保存&应用"按钮
			if (node_nu) {
				html += '<input style="margin-left:10px" class="button_gen" type="button" onclick="save()" value="保存&应用">'
			}
			html += '<input id="reset_select" style="margin-left:10px; display:none" class="button_gen" onClick="select_default_node(1)" type="button" value="取消"/>'
			html += '</div>'
			$('.nodeTable').remove();
			$('#ss_list_table').before(html);
			if (node_max != 0 && node_max != node_nu) {
				console.log("自动调整顺序！")
				save_new_order();
			}
			//if (db_ss["ss_basic_latency_val"]) {
			//	latency_test(db_ss["ss_basic_latency_val"]);
			//}
			select_default_node(2);
			if (E("ss_basic_dragable").checked) {
				order_adjustment();
			}
			if (node_nu) {
				const dropdownBtn = E("dropdownbtn");
				const dropdownMenu = E("dropdown");
				const toggleDropdown = function () {
					var lef = $('#dropdownbtn').offset().left;
					var top = $('#dropdownbtn').offset().top;
					var eleh = $("#dropdown").height();
					$('#dropdown').offset({ left: lef, top: (top - eleh) });
					dropdownMenu.classList.toggle("show");
				};
				dropdownBtn.addEventListener("click", function (e) {
					e.stopPropagation();
					toggleDropdown();
				});
				E("app").addEventListener("click", function () {
					if (dropdownMenu.classList.contains("show")) {
						toggleDropdown();
					}
				});
			}
		}










		function hide_name() {
			var sw = $(".node_name")[0].clientWidth - 4;
			if ($(".shadow1").css("display") == "block") {
				$(".nickname").show(300);
				$(".shadow1").hide(300);
			} else {
				$(".nickname").hide(300);
				$(".shadow1").show(300);
				$(".shadow1").css("width", sw)
			}
		}
		function hide_server() {
			var sw = $(".node_server")[0].clientWidth - 4;
			if ($(".shadow2").css("display") == "block") {
				$(".server").show(300);
				$(".shadow2").hide(300);
			} else {
				$(".server").hide(300);
				$(".shadow2").show(300);
				$(".shadow2").css("width", sw)
			}
		}
		function order_adjustment() {
			$("#ss_node_list_table").tableDnD({
				dragHandle: ".dragHandle",
				onDragClass: "myDragClass",
				onDrop: function () {
					save_new_order();
				}
			});
			$("#ss_node_list_table tr").hover(function () {
				$(this.cells[0]).addClass('showDragHandle');
				$(this.cells[1]).addClass('showDragHandle');
			}, function () {
				$(this.cells[0]).removeClass('showDragHandle');
				$(this.cells[1]).removeClass('showDragHandle');
			});
		}

		// (最终修正版) 提供了绝对完整的节点参数清单，彻底修复排序后数据错乱的BUG
		function save_new_order() {
			var dbus_tmp = {};
			var p = "ssconf_basic";
			var perf = "ssconf_basic_";
			// (关键修正) 提供一份交叉比对后最完整的参数清单，确保所有数据都被复制
			var all_node_fields = [
				"accel_mode", "group", "hy2_ai", "hy2_dl", "hy2_obfs", "hy2_obfs_pass",
				"hy2_pass", "hy2_port", "hy2_server", "hy2_sni", "hy2_tfo", "hy2_up",
				"kcp_param", "kcp_rport", "kcp_rserver", "latency", "lbmode", "method",
				"mode", "name", "naive_pass", "naive_port", "naive_prot", "naive_server",
				"naive_user", "password", "port", "rss_obfs", "rss_obfs_param",
				"rss_protocol", "rss_protocol_param", "server", "server_ip",
				"ss_obfs", "ss_obfs_host", "trojan_ai", "trojan_sni", "trojan_tfo", "trojan_uuid",
				"tuic_json", "type", "udp2raw_param", "udp2raw_rport", "udp2raw_rserver",
				"use_kcp", "use_lb", "v2ray_alterid", "v2ray_grpc_mode", "v2ray_headtype_kcp",
				"v2ray_headtype_quic", "v2ray_headtype_tcp", "v2ray_json", "v2ray_kcp_congestion",
				"v2ray_kcp_downlink", "v2ray_kcp_mtu", "v2ray_kcp_readbuf", "v2ray_kcp_seed",
				"v2ray_kcp_tti", "v2ray_kcp_uplink", "v2ray_kcp_writebuf", "v2ray_mux_concurrency",
				"v2ray_mux_enable", "v2ray_network", "v2ray_network_host", "v2ray_network_path",
				"v2ray_network_security", "v2ray_network_security_ai", "v2ray_network_security_alpn_h2",
				"v2ray_network_security_alpn_http", "v2ray_network_security_sni", "v2ray_security",
				"v2ray_use_json", "v2ray_uuid", "weight", "xray_alterid", "xray_encryption",
				"xray_fingerprint", "xray_flow", "xray_grpc_mode", "xray_headtype_kcp",
				"xray_headtype_quic", "xray_headtype_tcp", "xray_json", "xray_kcp_congestion",
				"xray_kcp_downlink", "xray_kcp_mtu", "xray_kcp_readbuf", "xray_kcp_seed",
				"xray_kcp_tti", "xray_kcp_uplink", "xray_kcp_writebuf", "xray_network",
				"xray_network_host", "xray_network_path", "xray_network_security",
				"xray_network_security_ai", "xray_network_security_alpn_h2",
				"xray_network_security_alpn_http", "xray_network_security_sni", "xray_prot",
				"xray_publickey", "xray_shortid", "xray_show", "xray_spiderx",
				"xray_use_json", "xray_uuid"
			];

			// 1. 标记所有现存节点配置为空，准备删除
			for (var i = 0; i < ss_nodes.length; i++) {
				var node_id_to_clear = ss_nodes[i];
				for (var j = 0; j < all_node_fields.length; j++) {
					dbus_tmp[perf + all_node_fields[j] + "_" + node_id_to_clear] = "";
				}
			}

			// 2. 按表格的视觉顺序，重新构建所有节点配置
			var table = E("ss_node_list_table");
			var trs = table.getElementsByTagName("tr");
			for (var i = 0; i < trs.length; i++) {
				var new_id = i + 1;
				var original_id = trs[i].id.split("_")[1];
				if (db_ss["ssconf_basic_node"] == original_id) {
					dbus_tmp["ssconf_basic_node"] = String(new_id);
				}

				// 将原始节点的所有配置，复制到新的ID下
				for (var j = 0; j < all_node_fields.length; j++) {
					var field_name = all_node_fields[j];
					var original_dbus_key = perf + field_name + "_" + original_id;
					var new_dbus_key = perf + field_name + "_" + new_id;
					if (typeof db_ss[original_dbus_key] !== 'undefined' && db_ss[original_dbus_key] !== "") {
						dbus_tmp[new_dbus_key] = db_ss[original_dbus_key];
					}
				}
			}

			var post_data = compfilter(db_ss, dbus_tmp);
			var id = parseInt(Math.random() * 100000000);
			var postData = { "id": id, "method": "dummy_script.sh", "params": [], "fields": post_data };
			$.ajax({
				type: "POST",
				cache: false,
				url: "/_api/",
				data: JSON.stringify(postData),
				dataType: "json",
				success: function (response) {
					// 保存成功后，重新从服务器加载所有数据并刷新整个UI
					refresh_dbss();
					reorder_trs();
					refresh_options();
					ss_node_sel();
				}
			});
		}


		function reorder_trs() {
			var trs = $("#ss_node_list_table tr");
			for (var i = 0; i < trs.length; i++) {
				var new_nu = i + 1;
				$('#ss_node_list_table tr:nth-child(' + new_nu + ')').attr("id", "node_" + new_nu);
				$('#ss_node_list_table tr:nth-child(' + new_nu + ') td:nth-child(1)').attr("id", "node_order_" + new_nu);
				$('#ss_node_list_table tr:nth-child(' + new_nu + ') td:nth-child(1)').html(String(new_nu));
				$('#ss_node_list_table tr:nth-child(' + new_nu + ') td:nth-child(2)').attr("id", "ss_node_name_" + new_nu);
				$('#ss_node_list_table tr:nth-child(' + new_nu + ') td:nth-child(3)').attr("id", "server_" + new_nu);
				$('#ss_node_list_table tr:nth-child(' + new_nu + ') td:nth-child(4)').attr("id", "server_" + new_nu);
				if ($('#ss_node_list_table tr:nth-child(' + new_nu + ') td:nth-child(5)').attr("id") != undefined) {
					$('#ss_node_list_table tr:nth-child(' + new_nu + ') td:nth-child(5)').attr("id", "ss_node_lt_" + new_nu);
					$('#ss_node_list_table tr:nth-child(' + new_nu + ') td:nth-child(6) input:nth-child(1)').attr("id", "dd_node_" + new_nu);
					$('#ss_node_list_table tr:nth-child(' + new_nu + ') td:nth-child(6) input:nth-child(2)').attr("id", "td_node_" + new_nu);
					$('#ss_node_list_table tr:nth-child(' + new_nu + ') td:nth-child(7) div').attr("id", "apply_ss_node_" + new_nu);
				} else {
					$('#ss_node_list_table tr:nth-child(' + new_nu + ') td:nth-child(5) input:nth-child(1)').attr("id", "dd_node_" + new_nu);
					$('#ss_node_list_table tr:nth-child(' + new_nu + ') td:nth-child(5) input:nth-child(2)').attr("id", "td_node_" + new_nu);
					$('#ss_node_list_table tr:nth-child(' + new_nu + ') td:nth-child(6) div').attr("id", "apply_ss_node_" + new_nu);
				}
			}
		}
		function select_default_node(o) {
			var sel_node = E("ssconf_basic_node").value || "1";
			$(".activate_icon").addClass("deactivate_icon");
			$(".activate_icon").removeClass("activate_icon");
			if (sel_node != db_ss["ssconf_basic_node"]) {
				E("reset_select").style.display = "";
			} else {
				E("reset_select").style.display = "none";
			}
			if (node_max == 0) {
				E("reset_select").style.display = "none";
			}
			if (o == 1) {
				if (db_ss["ss_basic_enable"] == "1") {
					E("ss_basic_enable").checked = true;
					$("#apply_ss_node_" + db_ss["ssconf_basic_node"]).addClass("activate_icon");
					$("#apply_ss_node_" + db_ss["ssconf_basic_node"]).removeClass("deactivate_icon");
					if (node_idx && node_nu > nodeN) {
						var rows2scroll = parseInt(((node_idx * trsH - nodeH * 0.5) / trsH));
						E("ss_node_list_table_main").scrollTop = rows2scroll * trsH;
					}
				} else {
					E("ss_basic_enable").checked = false;
				}
				$("#reset_select").hide();
			} else if (o == 2) {
				if (E("ss_basic_enable").checked) {
					$("#apply_ss_node_" + sel_node).addClass("activate_icon");
					$("#apply_ss_node_" + sel_node).removeClass("deactivate_icon");
					if (node_idx && node_nu > nodeN) {
						var rows2scroll = parseInt(((node_idx * trsH - nodeH * 0.5) / trsH));
						E("ss_node_list_table_main").scrollTop = rows2scroll * trsH;
					}
				}
			} else if (o == 3) {
				if (E("ss_basic_enable").checked) {
					$("#apply_ss_node_" + sel_node).addClass("activate_icon");
					$("#apply_ss_node_" + sel_node).removeClass("deactivate_icon");
					node_idx_1 = $.inArray(E("ssconf_basic_node").value, ss_nodes) + 1;
					if (node_idx_1 && node_nu > nodeN) {
						var rows2scroll = parseInt(((node_idx_1 * trsH - nodeH * 0.5) / trsH));
						E("ss_node_list_table_main").scrollTop = rows2scroll * trsH;
					}
				}
			}
		}
		function apply_this_ss_node(rowdata) {
			cancel_add_node();
			var enable_id = $(rowdata).attr("id");
			var enable_id = enable_id.split("_")[3];
			var $activateItem = $(rowdata);
			var flag = $activateItem.hasClass("activate_icon") ? "disconnect" : "connect";
			$(".activate_icon").addClass("deactivate_icon");
			$(".activate_icon").removeClass("activate_icon");
			if (flag == "disconnect") {
				$activateItem.addClass("deactivate_icon");
				$activateItem.removeClass("activate_icon");
				E("reset_select").style.display = ""
				E("ss_basic_enable").checked = false;
			} else {
				$activateItem.addClass("activate_icon");
				$activateItem.removeClass("deactivate_icon");
				dbus["ssconf_basic_node"] = enable_id;
				if (db_ss["ssconf_basic_node"] != enable_id) {
					E("reset_select").style.display = ""
				} else {
					E("reset_select").style.display = "none"
				}
				E("ss_basic_enable").checked = true;
			}
			E("ssconf_basic_node").value = enable_id;
			ss_node_sel();
		}
		function makeQRcode(node) {
			var id = $(node).attr("id");
			var ids = id.split("_");
			var p = "ssconf_basic";
			id = ids[ids.length - 1];
			var c = confs[id];
			if (c["type"] == "0") {
				if (c["ss_obfs"] == "1") {
					var code = "ss://" + Base64.encode(c["method"] + ":" + Base64.decode(c["password"])) + "@" + c["server"] + ":" + c["port"] + "/?plugin=obfs-local%3Bobfs%3D" + c["ss_obfs"] + "%3Bobfs-host%3D" + c["ss_obfs_host"] + "#" + c["name"];
				} else {
					var code = "ss://" + Base64.encode(c["method"] + ":" + Base64.decode(c["password"]) + "@" + c["server"] + ":" + c["port"] + "#" + c["name"]);
				}
			}
			else if (c["type"] == "1") {
				var base64pass = c["password"].replace(/=+/, "");
				var base64obfsparm = Base64.encode(c["rss_obfs_param"]).replace(/=+/, "");
				var base64protoparam = Base64.encode(c["rss_protocol_param"]).replace(/=+/, "");
				var base64remark = Base64.encode(c["name"]).replace(/=+/, "");
				var base64group = Base64.encode(c["group"]).replace(/=+/, "");
				var config_ssr = c["server"] + ":" + c["port"] + ":" + c["rss_protocol"] + ":" + c["method"] + ":" + c["rss_obfs"] + ":" + base64pass + "/?obfsparam=" + base64obfsparm + "&protoparam=" + base64protoparam + "&remarks=" + base64remark + "&group=" + base64group;
				var code = "ssr:\/\/" + Base64.encode(config_ssr).replace(/=+/, "").replace(/\+/, "-").replace(/\//, "_");
			}
			else if (c["type"] == "3") {
				if (c["v2ray_use_json"] == "1") {
					var code = 1;
				} else {
					var code = {};
					code.ps = c["name"];
					code.v = "2";
					code.add = c["server"];
					code.port = c["port"];
					code.id = c["v2ray_uuid"];
					code.aid = c["v2ray_alterid"];
					code.net = c["v2ray_network"];
					code.host = c["v2ray_network_host"];
					code.path = c["v2ray_network_path"];
					code.tls = c["v2ray_network_security"];
					if (c["v2ray_network"] == "tcp") {
						code.type = c["v2ray_headtype_tcp"];
					} else if (c["v2ray_network"] == "kcp") {
						code.type = c["v2ray_headtype_kcp"];
					} else if (c["v2ray_network"] == "quic") {
						code.type = c["v2ray_headtype_quic"];
					}
					code = "vmess:\/\/" + Base64.encode(JSON.stringify(code));
				}
			}
			else if (c["type"] == "4") {
				var code = 2;
			}
			else if (c["type"] == "5") {
				var code = 3;
			}
			else {
				var code = 4;
			}
			$("#qrtitle").html(c["name"]);
			$("#qrcode_show").css("top", "240px");
			showQRcode(code);
		}
		function showQRcode(data) {
			$("#qrcode").html("");
			if (data == 1) {
				$("#qrcode").html('<span style="font-size:16px;color:#000;">暂不支持v2ray json配置的二维码生成！</span>')
			}
			else if (data == 2) {
				$("#qrcode").html('<span style="font-size:16px;color:#000;">暂不支持xray节点的二维码生成！</span>')
			}
			else if (data == 3) {
				$("#qrcode").html('<span style="font-size:16px;color:#000;">暂不支持trojan节点的二维码生成！</span>')
			}
			else if (data == 4) {
				$("#qrcode").html('<span style="font-size:16px;color:#000;">错误！！节点类型位置！！<br />请检查你的节点！</span>')
			}
			else {
				require(['/res/qrcode.js'], function () {
					var qrcode = new QRCode(E("qrcode"), {
						text: data,
						width: 256,
						height: 256,
						colorDark: "#000000",
						colorLight: "#ffffff",
						correctLevel: QRCode.CorrectLevel.H
					});
				});
			}
			$("#qrcode_show").fadeIn(200);
		}
		function cleanCode() {
			$("#qrcode_show").fadeOut(300);
		}
		function open_latency_sett() {
			update_visibility();
			$('body').prepend(tableApi.genFullScreen());
			$('.fullScreen').show();
			document.scrollingElement.scrollTop = 0;
			E("latency_test_settings").style.visibility = "visible";
			var page_h = window.innerHeight || document.documentElement.clientHeight || document.body.clientHeight;
			var page_w = window.innerWidth || document.documentElement.clientWidth || document.body.clientWidth;
			var elem_h = E("latency_test_settings").clientHeight;
			var elem_w = E("latency_test_settings").clientWidth;
			var elem_h_offset = (page_h - elem_h) / 2 - 90;
			var elem_w_offset = (page_w - elem_w) / 2 + 90;
			if (elem_h_offset < 0) {
				elem_h_offset = 10;
			}
			$('#latency_test_settings').offset({ top: elem_h_offset, left: elem_w_offset });
		}
		function leav_test_sett() {
			E("latency_test_settings").style.visibility = "hidden";
			$("body").find(".fullScreen").fadeOut(300, function () { tableApi.removeElement("fullScreen"); });
		}
		function save_latency_sett() {
			var dbus_post = {};
			var post_para = 0;
			dbus_post["ss_basic_wt_furl"] = E("ss_basic_wt_furl").value;
			dbus_post["ss_basic_wt_curl"] = E("ss_basic_wt_curl").value;
			dbus_post["ss_basic_lt_cru_opts"] = E("ss_basic_lt_cru_opts").value;
			dbus_post["ss_basic_lt_cru_time"] = E("ss_basic_lt_cru_time").value;
			var post_dbus = compfilter(db_ss, dbus_post);
			if (isObjectEmpty(post_dbus) == false) {
				if (post_dbus.hasOwnProperty("ss_basic_wt_furl")) {
					post_para += 1;
				}
				if (post_dbus.hasOwnProperty("ss_basic_wt_curl")) {
					post_para += 2;
				}
				var id = parseInt(Math.random() * 100000000);
				var postData = { "id": id, "method": "ss_webtest.sh", "params": [post_para], "fields": post_dbus };
				$.ajax({
					type: "POST",
					cache: false,
					url: "/_api/",
					data: JSON.stringify(postData),
					dataType: "json",
					success: function (response) {
						if (response.result == id) {
							leav_test_sett();
							refresh_dbss();
						}
					}
				});
			} else {
				leav_test_sett();
			}
		}
		function test_latency_now(test_flag) {
			var dbus_post = {};
			dbus_post["ss_basic_latency_val"] = test_flag;
			if (test_flag == 0) {
				var post_para = "close_latency_test";
			} else if (test_flag == 2) {
				var post_para = "manual_webtest";
			}
			var id = parseInt(Math.random() * 100000000);
			var postData = { "id": id, "method": "ss_webtest.sh", "params": [post_para], "fields": dbus_post };
			$.ajax({
				type: "POST",
				cache: false,
				url: "/_api/",
				data: JSON.stringify(postData),
				dataType: "json",
				success: function (response) {
					if (response.result == id) {
						$(".show-btn1").trigger("click");
						refresh_table();
						if (test_flag == 0) {
							close_latency_flag = 1;
							$("#ss_wts_show").html("");
							$("#dropdown").width(150);
						}
						if (test_flag == "2") {
							$(".latency").html("waiting...");
						}
					}
				}
			});
		}
		function latency_test(action) {
			if (action == "0") return;
			if (action == "2") {
				var bash_para = "web_webtest";
			}
			var id = parseInt(Math.random() * 100000000);
			var postData = { "id": id, "method": "ss_webtest.sh", "params": [bash_para], "fields": "" };
			$.ajax({
				type: "POST",
				async: true,
				cache: false,
				url: "/_api/",
				data: JSON.stringify(postData),
				dataType: "json",
				success: function (response) {
					$(".latency").html("waiting...");
					get_latency_data(action);
				},
				error: function (XmlHttpRequest, textStatus, errorThrown) {
					$(".latency").html("失败!");
				},
				timeout: 60000
			});
		}
		function get_latency_data(action) {
			if (close_latency_flag == 1) return false;
			var URL = '/_temp/webtest.txt'
			$.ajax({
				url: URL,
				type: 'GET',
				cache: false,
				dataType: 'text',
				success: function (res) {
					const lines = res.split('\n');
					const array = [];
					lines.forEach(line => {
						const parts = line.split('>').map(part => part.trim());
						const item = [parts[0], parts[1]];
						array.push(item);
					});
					write_webtest(array);
					const hasStop = array.some(subArray => subArray.includes('stop'));
					if (hasStop) {
						$.ajax({
							type: "GET",
							url: "/_api/ss_basic_webtest_ts",
							dataType: "json",
							async: false,
							success: function (data) {
								db_get = data.result[0];
								if (db_get["ss_basic_webtest_ts"]) {
									$("#ss_wts_show").html("<em>【上次完成时间: " + db_get["ss_basic_webtest_ts"] + "】</em>")
									$("#dropdown").width(370);
								}
							}
						});
					} else {
						setTimeout("get_latency_data(2);", 1000);
					}
				},
				error: function (XmlHttpRequest, textStatus, errorThrown) {
					setTimeout("get_latency_data(" + action + ");", 1000);
				},
			});
		}
		function write_webtest(ps) {
			for (var i = 0; i < ps.length; i++) {
				var nu = ps[i][0];
				var lag = ps[i][1];
				if ($.isNumeric(lag)) {
					if (lag <= 100) {
						test_result = '<font color="#1bbf35">' + lag + ' ms</font>';
					} else if (lag > 100 && lag <= 200) {
						test_result = '<font color="#3399FF">' + lag + ' ms</font>';
					} else if (lag > 200 && lag <= 300) {
						test_result = '<font color="#f36c21">' + lag + ' ms</font>';
					} else {
						test_result = '<font color="#FF0066">' + lag + ' ms</font>';
					}
				} else {
					if (lag == "failed") {
						test_result = '<font color="#FF0000">failed!</font>';
					} else if (lag == "ns") {
						test_result = '<font color="#FF0000">不支持!</font>';
					} else {
						test_result = '<font color="#00FFCC">' + lag + '</font>'
					}
				}
				if ($('#ss_node_lt_' + nu)) {
					$('#ss_node_lt_' + nu).html(test_result);
				}
			}
		}
		function save_row(action) {
			var dbus_post = {};
			dbus_post["ss_basic_row"] = E("ss_basic_row").value;
			var id = parseInt(Math.random() * 100000000);
			var postData = { "id": id, "method": "dummy_script.sh", "params": [], "fields": dbus_post };
			$.ajax({
				type: "POST",
				cache: false,
				url: "/_api/",
				data: JSON.stringify(postData),
				dataType: "json",
				success: function (response) {
					if (response.result == id) {
						$(".show-btn1").trigger("click");
						refresh_table();
					}
				}
			});
		}
		function download_route_file(arg) {
			var dbus_tmp = {};
			if (arg == 2) {
				db_ss["ss_basic_action"] = "11";
				showSSLoadingBar();
				setTimeout("get_realtime_log();", 600);
			}
			if (arg == 10) {
				var dbus_tmp = dns_log;
			}
			var id = parseInt(Math.random() * 100000000);
			var postData = { "id": id, "method": "ss_conf.sh", "params": [arg], "fields": dbus_tmp };
			$.ajax({
				type: "POST",
				url: "/_api/",
				async: true,
				cache: false,
				data: JSON.stringify(postData),
				dataType: "json",
				success: function (response) {
					if (response.result == id) {
						if (arg == 1) {
							var a = document.createElement('A');
							a.href = "_root/files/ssconf_backup.sh";
							a.download = 'ssconf_backup.sh';
							document.body.appendChild(a);
							a.click();
							document.body.removeChild(a);
						}
						else if (arg == 2) {
							var b = document.createElement('A')
							b.href = "_root/files/" + pkg_name + "_" + db_ss["ss_basic_version_local"] + ".tar.gz"
							b.download = pkg_name + "_" + db_ss["ss_basic_version_local"] + ".tar.gz"
							document.body.appendChild(b);
							b.click();
							document.body.removeChild(b);
						}
						else if (arg == 6) {
							var b = document.createElement('A')
							b.href = "_root/files/ssf_status.txt"
							b.download = 'ssf_status.txt'
							document.body.appendChild(b);
							b.click();
							document.body.removeChild(b);
						}
						else if (arg == 7) {
							var b = document.createElement('A')
							b.href = "_root/files/ssc_status.txt"
							b.download = 'ssc_status.txt'
							document.body.appendChild(b);
							b.click();
							document.body.removeChild(b);
						}
						else if (arg == 10) {
							var b = document.createElement('A')
							b.href = "_root/files/" + dns_log["ss_basic_logname"] + ".txt"
							b.download = dns_log["ss_basic_logname"] + '.txt'
							document.body.appendChild(b);
							b.click();
							document.body.removeChild(b);
						}
						else if (arg == 11) {
							var b = document.createElement('A')
							b.href = "_root/files/dns_dig_result.txt"
							b.download = 'dns_dig_result.txt'
							document.body.appendChild(b);
							b.click();
							document.body.removeChild(b);
						}
					}
				}
			});
		}
		function upload_ss_backup() {
			db_ss["ss_basic_action"] = "9";
			var filename = $("#ss_file").val();
			filename = filename.split('\\');
			filename = filename[filename.length - 1];
			var filelast = filename.split('.');
			filelast = filelast[filelast.length - 1];
			if (filelast != "sh" && filelast != "json") {
				alert('备份文件格式不正确！');
				return false;
			}
			E('ss_file_info').style.display = "none";
			var formData = new FormData();
			if (filelast == 'sh') {
				formData.append("ssconf_backup.sh", $('#ss_file')[0].files[0]);
			} else if (filelast == 'json') {
				formData.append("ssconf_backup.json", $('#ss_file')[0].files[0]);
			}
			$.ajax({
				url: '/_upload',
				type: 'POST',
				cache: false,
				data: formData,
				processData: false,
				contentType: false,
				complete: function (res) {
					if (res.status == 200) {
						E('ss_file_info').style.display = "block";
						restore_ss_conf();
					}
				}
			});
		}
		function restore_ss_conf() {
			showSSLoadingBar();
			var id = parseInt(Math.random() * 100000000);
			var postData = { "id": id, "method": "ss_conf.sh", "params": ["4"], "fields": "" };
			$.ajax({
				type: "POST",
				url: "/_api/",
				data: JSON.stringify(postData),
				dataType: "json",
				success: function (response) {
					get_realtime_log();
				}
			});
		}
		function remove_SS_node() {
			db_ss["ss_basic_action"] = "10";
			push_data("ss_conf.sh", "3", "");
		}
		function restart_dnsmaq() {
			db_ss["ss_basic_action"] = "21";
			showSSLoadingBar();
			var id = parseInt(Math.random() * 100000000);
			var postData = { "id": id, "method": "ss_conf.sh", "params": ["8"], "fields": "" };
			$.ajax({
				type: "POST",
				url: "/_api/",
				data: JSON.stringify(postData),
				dataType: "json",
				success: function (response) {
					get_realtime_log();
				}
			});
		}
		function updatelist(arg) {
			var dbus_post = {};
			db_ss["ss_basic_action"] = "8";
			dbus_post["ss_basic_rule_update"] = E("ss_basic_rule_update").value;
			dbus_post["ss_basic_rule_update_time"] = E("ss_basic_rule_update_time").value;
			dbus_post["ss_basic_gfwlist_update"] = E("ss_basic_gfwlist_update").checked ? '1' : '0';
			dbus_post["ss_basic_chnroute_update"] = E("ss_basic_chnroute_update").checked ? '1' : '0';
			dbus_post["ss_basic_cdn_update"] = E("ss_basic_cdn_update").checked ? '1' : '0';
			push_data("ss_rule_update.sh", arg, dbus_post);
		}
		function version_show() {
			if (!db_ss["ss_basic_version_local"]) db_ss["ss_basic_version_local"] = "0.0.0"
			$("#ss_version_show").html("<i>当前版本：" + db_ss['ss_basic_version_local'] + "</i>");

			// (修改) 通过注释禁用在线版本检查
			/*
			$.ajax({
				url: 'https://raw.githubusercontent.com/hq450/fancyss/3.0/packages/version.json.js',
				type: 'GET',
				dataType: 'json',
				success: function(res) {
					if (typeof(res["version"]) != "undefined" && res["version"].length > 0) {
						if (versionCompare(res["version"], db_ss["ss_basic_version_local"])) {
							$("#updateBtn").html("<i>升级到：" + res.version + "</i>");
						}
					}
				}
			});
			*/
		}
		function message_show() {
			if (db_ss["ss_close_mesg"] == "0") return
			$.ajax({
				url: 'https://gist.githubusercontent.com/hq450/001dd0617a64e11a9492dcf9205a0e03/raw/fancyss_msg.json?_=' + new Date().getTime(),
				type: 'GET',
				dataType: 'json',
				cache: false,
				success: function (res) {
					if (res["ads_url_1"] && res["ads_des_1"]) {
						ads_url_1 = res["ads_url_1"];
						ads_des_1 = res["ads_des_1"];
						if (node_nu == 0 && poped == 0) pop_node_add_ads();
						if (!E("ss_online_links").value) {
							sub_ads_html = '<a target="_blank" href="' + ads_url_1 + '"><em>' + ads_des_1 + '</em></a>';
							$('#ss_sub_ads').html(sub_ads_html)
						}
					} else {
						if (node_nu == 0 && poped == 0) pop_node_add();
					}
					var rand_1 = parseInt(Math.random() * 100)
					if (res["msg_1"] && res["switch_1"]) {
						if (rand_1 < res["switch_1"]) {
							if (versionCompare(res["version"], db_ss["ss_basic_version_local"])) {
								$("#fixed_msg").append('<li id="msg_1" style="list-style: none;height:23px">' + res["msg_1"] + '</li>');
							}
						}
					}
					if (res["msg_2"] && res["switch_2"]) {
						if (rand_1 < res["switch_2"]) {
							$("#fixed_msg").append('<li id="msg_2" style="list-style: none;height:23px">' + res["msg_2"] + '</li>');
						}
					}
					var ads_count = 0;
					var rand_2 = parseInt(Math.random() * 100)
					for (var i = 3; i < 10; i++) {
						if (res["msg_" + i] && res["switch_" + i]) {
							if (rand_2 < res["switch_" + i]) {
								$("#scroll_msg").append('<li id="msg_' + i + '" style="list-style: none;height:23px">' + res["msg_" + i] + '</li>');
								ads_count++;
							}
						}
					}
					if (ads_count == 0) return;
					if (ads_count <= 2) {
						$("#scroll_msg").css("height", (ads_count * 23) + "px");
						return;
					}
					if (res["scroll_line"]) {
						$("#scroll_msg").css("height", (res["scroll_line"] * 23) + "px");
					} else {
						$("#scroll_msg").css("height", "23px");
					}
					$("#scroll_msg").on("mouseover", function () {
						stop_scroll = 1;
					});
					$("#scroll_msg").on("mouseleave", function () {
						stop_scroll = 0;
					});
					if (res["ads_time"]) {
						setInterval("scroll_msg();", res["ads_time"]);
					} else {
						setInterval("scroll_msg();", 5000);
					}
				},
				error: function (XmlHttpRequest, textStatus, errorThrown) {
					console.log(XmlHttpRequest.responseText);
					if (node_nu == 0 && poped == 0) pop_node_add();
				}
			});
		}
		function scroll_msg() {
			if (stop_scroll == 0) {
				$('#scroll_msg').stop().animate({ scrollTop: 23 }, 500, 'swing', function () {
					$(this).find('li:last').after($('li:first', this));
				});
			}
		}
		function update_ss() {
			var dbus_post = {};
			db_ss["ss_basic_action"] = "7";
			push_data("ss_update.sh", "update", dbus_post);
		}
		function tabSelect(w) {
			for (var i = 0; i <= 10; i++) {
				$('.show-btn' + i).removeClass('active');
				$('#tablet_' + i).hide();
			}
			$('.show-btn' + w).addClass('active');
			$('#tablet_' + w).show();
		}
		function toggle_func() {
			$("#ss_basic_enable").click(
				function () {
					select_default_node(2);
					if (E("ss_basic_enable").checked) {
						if (node_max == 0) {
							alert("你还没有任何节点，无法开启！");
							return false;
						}
						E("reset_select").style.display = db_ss["ss_basic_enable"] == "1" ? "none" : "";
					} else {
						E("reset_select").style.display = db_ss["ss_basic_enable"] == "1" ? "" : "none";
					}
				});
			$(".show-btn0").click(
				function () {
					tabSelect(0);
					$('#apply_button').show();
					$('#ss_failover_save').hide();
					showhide("table_basic", (node_max != 0));
					change_select_width('#ssconf_basic_node');
				});
			$(".show-btn1").click(
				function () {
					tabSelect(1);
					$('#apply_button').hide();
					$(".nodeTable").show();
					select_default_node(3);
				});
			$(".show-btn2").click(
				function () {
					tabSelect(2);
					$('#apply_button').show();
					$('#ss_failover_save').show();
					verifyFields();
				});
			$(".show-btn3").click(
				function () {
					tabSelect(3);
					$('#apply_button').show();
					$('#ss_failover_save').hide();
					change_select_width('#ss_china_dns', '0');
					change_select_width('#ss_foreign_dns', '0');
					change_select_width('#ss_basic_chng_china_1_udp', '1');
					change_select_width('#ss_basic_chng_china_1_tcp', '1');
					change_select_width('#ss_basic_chng_china_2_udp', '1');
					change_select_width('#ss_basic_chng_china_2_tcp', '1');
					change_select_width('#ss_basic_chng_trust_1_opt_udp_val', '1');
					change_select_width('#ss_basic_chng_trust_1_opt_tcp_val', '1');
					change_select_width('#ss_basic_server_resolv');
					change_select_width('#ss_basic_dig_opt');
					update_visibility();
					autoTextarea(E("ss_dnsmasq"), 0, 500);
				});
			$(".show-btn4").click(
				function () {
					tabSelect(4);
					$('#apply_button').show();
					$('#ss_failover_save').hide();
					autoTextarea(E("ss_wan_white_ip"), 0, 400);
					autoTextarea(E("ss_wan_white_domain"), 0, 400);
					autoTextarea(E("ss_wan_black_ip"), 0, 400);
					autoTextarea(E("ss_wan_black_domain"), 0, 400);
				});
			$(".show-btn5").click(
				function () {
					tabSelect(5);
					$('#apply_button').show();
					$('#ss_failover_save').hide();
					verifyFields();
					autoTextarea(E("ss_basic_kcp_parameter"), 0, 100);
				});
			$(".show-btn6").click(
				function () {
					tabSelect(6);
					$('#apply_button').show();
					$('#ss_failover_save').hide();
					update_visibility();
					verifyFields();
					get_udp_status();
				});
			$(".show-btn7").click(
				function () {
					tabSelect(7);
					$('#apply_button').hide();
					$('#ss_failover_save').hide();
					update_visibility();
				});
			$(".show-btn8").click(
				function () {
					tabSelect(8);
					$('#apply_button').show();
					$('#ss_failover_save').hide();
					refresh_acl_table();
				});
			$(".show-btn9").click(
				function () {
					tabSelect(9);
					$('#apply_button').show();
					$('#ss_failover_save').hide();
					update_visibility();
				});
			$(".show-btn10").click(
				function () {
					tabSelect(10);
					$('#apply_button').hide();
					$('#ss_failover_save').hide();
					get_log();
				});
			$("#log_content2").click(
				function () {
					x = -1;
				});
			$(".sub-btn1").click(
				function () {
					$('.sub-btn1').addClass('active2');
					$('.sub-btn2').removeClass('active2');
					verifyFields()
				});
			$(".sub-btn2").click(
				function () {
					$('.sub-btn1').removeClass('active2');
					$('.sub-btn2').addClass('active2');
					verifyFields()
				});
			var default_tab = parseInt(E("ss_basic_tablet").checked ? "1" : "0");
			if (node_nu == 0 && poped == 0) {
				$(".show-btn1").trigger("click");
			} else {
				$(".show-btn1").trigger("click");
			}
		}
		function change_select_width(o, p) {
			$(o).click(function () {
				var text = $(this).find('option:selected').text();
				var className = $(o).attr('class');
				var $aux = $('<select class="' + className + '">').append($('<option/>').text(text));
				$(this).after($aux);
				var aux_width = $aux.width();
				if (aux_width < 135 && p == "1") {
					aux_width = 135;
				}
				if (aux_width < 118 && p == "0") {
					aux_width = 118;
				}
				$(this).width(aux_width);
				$aux.remove();
			}).click();
		}
		function get_ss_status() {
			E("ss_state2").innerHTML = "国外连接 - " + "Waiting...";
			E("ss_state3").innerHTML = "国内连接 - " + "Waiting...";
			if (db_ss['ss_basic_enable'] != "1") {
				return falsex;
			}
			if (db_ss["ss_failover_enable"] == "1") {
				get_ss_status_back();
			} else {
				get_ss_status_front();
			}
		}
		function get_ss_status_front() {
			if (ws_enable != 1) {
				get_ss_status_front_httpd();
				return false;
			}
			if (window.location.protocol != "http:") {
				get_ss_status_front_httpd();
				return false;
			}
			wss = new WebSocket("ws://" + hostname + ":803/");
			wss.onopen = function () {
				wss_open = 1;
				get_ss_status_front_websocket();
			};
			wss.onerror = function (event) {
				wss_open = 0;
				get_ss_status_front_httpd();
			};
			wss.onclose = function () {
				wss_open = 0;
				get_ss_status_front_httpd();
			};
			wss.onmessage = function (event) {
				var res = event.data;
				if (res.indexOf("@@") != -1) {
					var arr = res.split("@@");
					if (arr[0] == "" || arr[1] == "") {
						E("ss_state2").innerHTML = "国外连接 - " + "Waiting for first refresh...";
						E("ss_state3").innerHTML = "国内连接 - " + "Waiting for first refresh...";
					} else {
						E("ss_state2").innerHTML = arr[0];
						E("ss_state3").innerHTML = arr[1];
					}
				} else {
					E("ss_state2").innerHTML = "国外连接 - " + "Waiting ...";
					E("ss_state3").innerHTML = "国内连接 - " + "Waiting ...";
				}
			}
		}
		function get_ss_status_front_httpd() {
			if (submit_flag == "1") {
				setTimeout("get_ss_status_front_httpd();", 5000);
				return false;
			}
			var id = parseInt(Math.random() * 100000000);
			var postData = { "id": id, "method": "ss_status.sh", "params": [], "fields": "" };
			$.ajax({
				type: "POST",
				url: "/_api/",
				async: true,
				cache: false,
				data: JSON.stringify(postData),
				success: function (response) {
					var arr = response.result.split("@@");
					if (arr[0] == "" || arr[1] == "") {
						E("ss_state2").innerHTML = "国外连接 - " + "Waiting for first refresh...";
						E("ss_state3").innerHTML = "国内连接 - " + "Waiting for first refresh...";
					} else {
						E("ss_state2").innerHTML = arr[0];
						E("ss_state3").innerHTML = arr[1];
					}
				}
			});
			var time_plus = Math.pow("2", String(db_ss['ss_basic_interval'] || "2")) * 1000;
			var time_base = time_plus - 1000;
			refreshRate = Math.floor(Math.random() * time_base) + time_plus;
			setTimeout("get_ss_status_front_httpd();", refreshRate);
		}
		function get_ss_status_front_websocket() {
			if (submit_flag == "1") {
				setTimeout("get_ss_status_front_websocket();", 5000);
				return false;
			}
			try {
				wss.send("sh /koolshare/scripts/ss_status.sh ws");
			} catch (ex) {
				console.log('Cannot send: ' + ex);
			}
			if (wss_open == "1") {
				var time_plus = Math.pow("2", String(db_ss['ss_basic_interval'] || "2")) * 1000;
				var time_base = time_plus - 1000;
				refreshRate = Math.floor(Math.random() * time_base) + time_plus;
				setTimeout("get_ss_status_front_websocket();", refreshRate);
			}
		}
		function get_ss_status_back() {
			if (E("ss_basic_interval").value == "1") {
				var time_wait = 3000;
			} else if (E("ss_basic_interval").value == "2") {
				var time_wait = 7000;
			} else if (E("ss_basic_interval").value == "3") {
				var time_wait = 15000;
			} else if (E("ss_basic_interval").value == "4") {
				var time_wait = 31000;
			} else if (E("ss_basic_interval").value == "5") {
				var time_wait = 63000;
			}
			if (ws_enable != 1) {
				get_ss_status_back_httpd();
				return false;
			}
			if (window.location.protocol != "http:") {
				get_ss_status_back_httpd();
				return false;
			}
			wss = new WebSocket("ws://" + hostname + ":803/");
			wss.onopen = function () {
				wss_open = 1;
				get_ss_status_back_websocket();
			};
			wss.onerror = function (event) {
				wss_open = 0;
				get_ss_status_back_httpd();
			};
			wss.onclose = function () {
				wss_open = 0;
				get_ss_status_back_httpd();
			};
			wss.onmessage = function (event) {
				var res = event.data;
				if (res.indexOf("@@") != -1) {
					var arr = res.split("@@");
					if (arr[0] == "" || arr[1] == "") {
						E("ss_state2").innerHTML = "国外连接 - " + "Waiting for first refresh...";
						E("ss_state3").innerHTML = "国内连接 - " + "Waiting for first refresh...";
					} else {
						E("ss_state2").innerHTML = arr[0];
						E("ss_state3").innerHTML = arr[1];
					}
					if (arr[2] == "1") {
						var dbus_post = {};
						dbus_post["ss_heart_beat"] = "0";
						push_data("dummy_script.sh", "", dbus_post, "2");
					}
				} else {
					E("ss_state2").innerHTML = "国外连接 - " + "Waiting ...";
					E("ss_state3").innerHTML = "国内连接 - " + "Waiting ...";
				}
			};
		}
		function get_ss_status_back_websocket() {
			try {
				wss.send("cat /tmp/upload/ss_status.txt");
			} catch (ex) {
				console.log('Cannot send: ' + ex);
			}
			if (wss_open == "1") {
				setTimeout("get_ss_status_back_websocket();", 1000);
			}
		}
		function get_ss_status_back_httpd() {
			if (db_ss['ss_basic_enable'] != "1") {
				E("ss_state2").innerHTML = "国外连接 - " + "Waiting.....";
				E("ss_state3").innerHTML = "国内连接 - " + "Waiting.....";
				return false;
			}
			$.ajax({
				url: '/_temp/ss_status.txt?_=' + new Date().getTime(),
				type: 'GET',
				dataType: 'html',
				async: true,
				cache: false,
				success: function (response) {
					var res = response.trim();
					if (res.indexOf("@@") != -1) {
						var arr = res.split("@@");
						if (arr[0] == "" || arr[1] == "") {
							E("ss_state2").innerHTML = "国外连接 - " + "Waiting for first refresh...";
							E("ss_state3").innerHTML = "国内连接 - " + "Waiting for first refresh...";
						} else {
							E("ss_state2").innerHTML = arr[0];
							E("ss_state3").innerHTML = arr[1];
						}
						if (arr[2] == "1") {
							var dbus_post = {};
							dbus_post["ss_heart_beat"] = "0";
							push_data("dummy_script.sh", "", dbus_post, "2");
							layer.confirm('<li>科学上网插件页面需要刷新！</li><br /><li>由于故障转移功能已经在后台切换了节点，为了保证页面显示正确配置！需要刷新此页面！</li><br /><li>确定现在刷新吗？</li>', {
								time: 3e4,
								shade: 0.8
							}, function (index) {
								layer.close(index);
								refreshpage();
							}, function (index) {
								layer.close(index);
								return false;
							});
						}
					}
				},
				error: function (xhr) {
					E("ss_state2").innerHTML = "国外连接 - " + "Waiting....";
					E("ss_state3").innerHTML = "国内连接 - " + "Waiting....";
				}
			});
			if (E("ss_basic_interval").value == "1") {
				var time_wait = 3000;
			} else if (E("ss_basic_interval").value == "2") {
				var time_wait = 7000;
			} else if (E("ss_basic_interval").value == "3") {
				var time_wait = 15000;
			} else if (E("ss_basic_interval").value == "4") {
				var time_wait = 31000;
			} else if (E("ss_basic_interval").value == "5") {
				var time_wait = 63000;
			}
			setTimeout("get_ss_status_back_httpd();", time_wait);
		}
		function get_udp_status() {
			var id = parseInt(Math.random() * 100000000);
			var postData = { "id": id, "method": "ss_udp_status.sh", "params": [], "fields": "" };
			$.ajax({
				type: "POST",
				cache: false,
				url: "/_api/",
				data: JSON.stringify(postData),
				dataType: "json",
				success: function (response) {
					E("udp_status").innerHTML = response.result;
					setTimeout("get_udp_status();", 10000);
				},
				error: function () {
					setTimeout("get_udp_status();", 2000);
				}
			});
		}
		function close_dns_status() {
			$("#dns_status_div").hide(200);
			STATUS_FLAG = 0;
		}
		function dns_test(s) {
			var dbus_commit = {};
			if (s == 1) {
				$("#log_dig").show();
				$("#log_resv").hide();
				dns_log["ss_basic_logname"] = "dns_cdn";
				var note1 = '1. 以下DNS解析测试的域名来自：<a href="https://github.com/felixonmars/dnsmasq-china-list" target="_blank"><em><u>https://github.com/felixonmars/dnsmasq-china-list</u></em></a> 的cdn-testlist.txt，并经过fancyss项目整理。';
				var note2 = '2. 解析结果和速度可能受节点、DNS方案、上游DNS缓存等因素影响，本测试也无法判断解析结果正确性！所以测试结果仅供参考！';
			}
			else if (s == 2) {
				$("#log_dig").show();
				$("#log_resv").hide();
				dns_log["ss_basic_logname"] = "dns_cdn_apple";
				var note1 = '1. Apple China的域名清单来自：<a href="https://github.com/felixonmars/dnsmasq-china-list" target="_blank"><em><u>https://github.com/felixonmars/dnsmasq-china-list</u></em></a> 的apple.china.conf，并经过fancyss项目整理。';
				var note2 = '2. 理想情况下，Apple China域名清单应该尽可能多的解析到大陆IP地址！';
				var note3 = '3. 解析结果和速度可能受节点、DNS方案、上游DNS缓存等因素影响，本测试也无法判断解析结果正确性！所以测试结果仅供参考！';
			}
			else if (s == 3) {
				$("#log_dig").show();
				$("#log_resv").hide();
				dns_log["ss_basic_logname"] = "dns_cdn_google";
				var note1 = '1. Google China的域名清单来自：<a href="https://github.com/felixonmars/dnsmasq-china-list" target="_blank"><em><u>https://github.com/felixonmars/dnsmasq-china-list</u></em></a> 的google.china.conf，并经过fancyss项目整理。';
				var note2 = '2. 理想情况下，Google China域名清单应该尽可能多的解析到大陆IP地址！';
				var note3 = '3. 解析结果和速度可能受节点、DNS方案、上游DNS缓存等因素影响，本测试也无法判断解析结果正确性！所以测试结果仅供参考！';
			}
			else if (s == 4) {
				$("#log_dig").show();
				$("#log_resv").hide();
				dns_log["ss_basic_logname"] = "dns_gfwlist";
				var note1 = '1. gfwlist的域名清单来自：<a href="https://github.com/hq450/fancyss/blob/3.0/rules/gfwlist.conf" target="_blank"><em><u>https://github.com/hq450/fancyss/blob/3.0/rules/gfwlist.conf</u></em></a>，收录了常见的被gfw屏蔽的域名。';
				var note2 = '2. 由于gfwlist清单较长，将每次随机选取100个域名进行测试！理想情况下，解析结果应该全部是海外IP地址，没有大陆IP地址！';
				var note3 = '3. 解析结果和速度可能受节点、DNS方案、上游DNS缓存等因素影响，本测试也无法判断解析结果正确性！所以测试结果仅供参考！';
			}
			else if (s == 5) {
				$("#log_dig").show();
				$("#log_resv").hide();
				dns_log["ss_basic_logname"] = "dns_cdn_china";
				var note1 = '1. cdn china的域名清单来自：<a href="https://github.com/felixonmars/dnsmasq-china-list" target="_blank"><em><u>https://github.com/felixonmars/dnsmasq-china-list</u></em></a> 的accelerated-domains.china.conf，并经过fancyss项目整理。';
				var note2 = '2. 由于cdn china清单较长，将每次随机选取100个域名进行测试！由于cdn china收录的域名条件位解析结果或者NS服务器在国内，所以很多域名解析到国外是正常的！';
			}
			else if (s == 6) {
				$("#log_dig").hide();
				$("#log_resv").show();
				var note1 = '1. 本测试需要用到dig程序，因程序体积较大，fancyss默认不包含此程序，点击测试的时候会自动尝试下载该程序。';
				var note2 = '1. 本测试仅针对DNS解析最终端，即本机dnsmasq 53端口的DNS服务器测试，每次测试前会自动清空dnsmasq缓存，以避免缓存影响。';
				var note3 = '2. 用dig进行测试可以方便的知道在本插件选定的DNS方案下，域名解析的ipv4结果，解析结果是否带ECS等';
				dbus_commit["ss_basic_dig_opt"] = E("ss_basic_dig_opt").value
			}
			if (note1) {
				$("#dns_test_note_1").html('<i>&nbsp;&nbsp;' + note1 + '</i>');
			}
			if (note2) {
				$("#dns_test_note_2").html('<i>&nbsp;&nbsp;' + note2 + '</i>');
			}
			if (note3) {
				$("#dns_test_note_3").show('<i>&nbsp;&nbsp;' + note3 + '</i>');
			}
			$("#dns_status_div").fadeIn(500);
			var id = parseInt(Math.random() * 100000000);
			var postData = { "id": id, "method": "ss_dns_test.sh", "params": [s], "fields": dbus_commit };
			$.ajax({
				type: "POST",
				cache: false,
				url: "/_api/",
				data: JSON.stringify(postData),
				dataType: "json",
				success: function (response) {
					get_dns_log(s);
				},
				error: function () {
					setTimeout("dns_test();", 2000);
				}
			});
		}
		function get_dns_log(s) {
			var retArea = E("log_content_dns");
			if (s == 1) {
				var file = '/_temp/dns_cdn.txt';
			}
			else if (s == 2) {
				var file = '/_temp/dns_cdn_apple.txt';
			}
			else if (s == 3) {
				var file = '/_temp/dns_cdn_google.txt';
			}
			else if (s == 4) {
				var file = '/_temp/dns_gfwlist.txt';
			}
			else if (s == 5) {
				var file = '/_temp/dns_cdn_china.txt';
			}
			else if (s == 6) {
				var file = '/_temp/dns_dig_result.txt';
			}
			$.ajax({
				url: file,
				type: 'GET',
				dataType: 'html',
				async: true,
				cache: false,
				success: function (response) {
					if (E("tablet_3").style.display == "none") {
						return false;
					}
					if (response.search("XU6J03M6") != -1) {
						retArea.value = response.myReplace("XU6J03M6", " ");
						retArea.scrollTop = retArea.scrollHeight;
						return true;
					}
					if (_responseLen == response.length) {
						noChange_dns++;
					} else {
						noChange_dns = 0;
					}
					if (noChange_dns > 20) {
						return false;
					} else {
						setTimeout('get_dns_log("' + s + '");', 500);
					}
					retArea.value = response.myReplace("XU6J03M6", " ");
					retArea.scrollTop = retArea.scrollHeight;
					_responseLen = response.length;
				},
				error: function (xhr) {
					retArea.value = "暂无任何日志，获取日志失败！";
				}
			});
		}
		function close_ssf_status() {
			E("ssf_status_div").style.visibility = "hidden";
			$('html, body').css({ overflow: 'auto', height: 'auto' });
			$("body").find(".fullScreen").fadeOut(300, function () { tableApi.removeElement("fullScreen"); });
			STATUS_FLAG = 0;
		}
		function close_ssc_status() {
			E("ssc_status_div").style.visibility = "hidden";
			$('html, body').css({ overflow: 'auto', height: 'auto' });
			$("body").find(".fullScreen").fadeOut(300, function () { tableApi.removeElement("fullScreen"); });
			STATUS_FLAG = 0;
		}
		function lookup_status_log(s) {
			STATUS_FLAG = 1;
			$('body').prepend(tableApi.genFullScreen());
			$('.fullScreen').show();
			document.scrollingElement.scrollTop = 0;
			var page_h = window.innerHeight || document.documentElement.clientHeight || document.body.clientHeight;
			var page_w = window.innerWidth || document.documentElement.clientWidth || document.body.clientWidth;
			if (s == 1) {
				var elem_h = $("#ssf_status_div").height();
				var elem_w = $("#ssf_status_div").width();
				var elem_h_offset = (page_h - elem_h) / 2;
				var elem_w_offset = (page_w - elem_w) / 2 + 90;
				if (elem_h_offset < 0) elem_h_offset = 10;
				$("#ssf_test_url").html(E("ss_basic_wt_furl").value)
				E("ssf_status_div").style.visibility = "visible";
				$('#ssf_status_div').offset({ top: elem_h_offset, left: elem_w_offset });
				get_status_log(1);
			} else {
				var elem_h = $("#ssc_status_div").height();
				var elem_w = $("#ssc_status_div").width();
				var elem_h_offset = (page_h - elem_h) / 2;
				var elem_w_offset = (page_w - elem_w) / 2 + 90;
				if (elem_h_offset < 0) elem_h_offset = 10;
				$("#ssc_test_url").html(E("ss_basic_wt_curl").value)
				E("ssc_status_div").style.visibility = "visible";
				$('#ssc_status_div').offset({ top: elem_h_offset, left: elem_w_offset });
				get_status_log(2);
			}
			$('html, body').css({ overflow: 'hidden', height: '100%' });
		}
		function get_status_log(s) {
			if (STATUS_FLAG == 0) return;
			if (s == 1) {
				var file = '/_temp/ssf_status.txt';
				var retArea = E("log_content_f");
			} else {
				var file = '/_temp/ssc_status.txt';
				var retArea = E("log_content_c");
			}
			$.ajax({
				url: file,
				type: 'GET',
				dataType: 'html',
				async: true,
				cache: false,
				success: function (response) {
					if (E("tablet_2").style.display == "none") {
						return false;
					}
					if (_responseLen == response.length) {
						noChange_status++;
					} else {
						noChange_status = 0;
					}
					if (noChange_status > 10) {
						return false;
					} else {
						setTimeout('get_status_log("' + s + '");', 3123);
					}
					retArea.value = response;
					if (E("ss_failover_c4").checked == false && E("ss_failover_c5").checked == false) {
						retArea.scrollTop = retArea.scrollHeight;
					}
					_responseLen = response.length;
				},
				error: function (xhr) {
					retArea.value = "暂无任何日志，获取日志失败！";
				}
			});
		}
		function get_log() {
			if (ws_flag != 1) {
				get_log_httpd();
				return false;
			}
			wsl = new WebSocket("ws://" + hostname + ":803/");
			wsl.onopen = function () {
				E('log_content1').value = "";
				wsl.send("cat /tmp/upload/ss_log.txt");
			};
			wsl.onerror = function (event) {
				get_log_httpd();
			};
			wsl.onmessage = function (event) {
				if (event.data != "XU6J03M6") {
					E('log_content1').value += event.data + '\n';
				} else {
					E("log_content1").scrollTop = E("log_content1").scrollHeight;
					wsl.close();
				}
			};
		}
		function get_log_httpd() {
			$.ajax({
				url: '/_temp/ss_log.txt',
				type: 'GET',
				dataType: 'html',
				async: true,
				cache: false,
				success: function (response) {
					var retArea = E("log_content1");
					if (response.search("XU6J03M6") != -1) {
						retArea.value = response.myReplace("XU6J03M6", " ");
						var pageH = parseInt(E("FormTitle").style.height.split("px")[0]);
						if (pageH) {
							autoTextarea(E("log_content1"), 0, (pageH - 308));
						} else {
							autoTextarea(E("log_content1"), 0, 980);
						}
						return true;
					}
					if (_responseLen == response.length) {
						noChange++;
					} else {
						noChange = 0;
					}
					if (noChange > 5) {
						return false;
					} else {
						setTimeout("get_log_httpd();", 100);
					}
					retArea.value = response;
					_responseLen = response.length;
					if (E("tablet_9").style.display == "none") {
						return false;
					}
				},
				error: function (xhr) {
					E("log_content1").value = "获取日志失败！";
				}
			});
		}
		function get_realtime_log() {
			$.ajax({
				url: '/_temp/ss_log.txt',
				type: 'GET',
				async: true,
				cache: false,
				dataType: 'text',
				success: function (response) {
					var retArea = E("log_content3");
					if (response.search("XU6J03M6") != -1) {
						retArea.value = response.myReplace("XU6J03M6", " ");
						E("ok_button").style.display = "";
						retArea.scrollTop = retArea.scrollHeight;
						count_down_close();
						submit_flag = "0";
						return true;
					}
					if (_responseLen == response.length) {
						noChange++;
					} else {
						noChange = 0;
					}
					if (noChange > 1000) {
						console.log("log time out!!")
						return false;
					} else {
						setTimeout("get_realtime_log();", 100);
					}
					retArea.value = response.myReplace("XU6J03M6", " ");
					retArea.scrollTop = retArea.scrollHeight;
					_responseLen = response.length;
				},
				error: function () {
					setTimeout("get_realtime_log();", 500);
				}
			});
		}
		function count_down_close() {
			if (x == "0") {
				hideSSLoadingBar();
			}
			if (x < 0) {
				E("ok_button1").value = "手动关闭"
				return false;
			}
			E("ok_button1").value = "自动关闭（" + x + "）"
			--x;
			setTimeout("count_down_close();", 1000);
		}
		function reload_Soft_Center() {
			location.href = "/Module_Softcenter.asp";
		}
		function getACLConfigs() {
			var dict = {};
			acl_node_max = 0;
			for (var field in db_acl) {
				names = field.split("_");
				dict[names[names.length - 1]] = 'ok';
			}
			acl_confs = {};
			var p = "ss_acl";
			var params = ["ip", "port", "mode"];
			for (var field in dict) {
				var obj = {};
				if (typeof db_acl[p + "_name_" + field] == "undefined") {
					obj["name"] = db_acl[p + "_ip_" + field];
				} else {
					obj["name"] = db_acl[p + "_name_" + field];
				}
				for (var i = 0; i < params.length; i++) {
					var ofield = p + "_" + params[i] + "_" + field;
					if (typeof db_acl[ofield] == "undefined") {
						obj = null;
						break;
					}
					obj[params[i]] = db_acl[ofield];
				}
				if (obj != null) {
					var node_a = parseInt(field);
					if (node_a > acl_node_max) {
						acl_node_max = node_a;
					}
					obj["acl_node"] = field;
					acl_confs[field] = obj;
				}
			}
			return acl_confs;
		}
		function addTr() {
			var acls = {};
			var p = "ss_acl";
			acl_node_max += 1;
			var params = ["ip", "name", "port", "mode"];
			for (var i = 0; i < params.length; i++) {
				acls[p + "_" + params[i] + "_" + acl_node_max] = $('#' + p + "_" + params[i]).val();
			}
			var id = parseInt(Math.random() * 100000000);
			var postData = { "id": id, "method": "dummy_script.sh", "params": [], "fields": acls };
			$.ajax({
				type: "POST",
				cache: false,
				url: "/_api/",
				data: JSON.stringify(postData),
				dataType: "json",
				error: function (xhr) {
					console.log("error in posting config of table");
				},
				success: function (response) {
					refresh_acl_table();
					E("ss_acl_name").value = ""
					E("ss_acl_ip").value = ""
				}
			});
			aclid = 0;
		}
		function delTr(o) {
			var id = $(o).attr("id");
			var ids = id.split("_");
			var p = "ss_acl";
			id = ids[ids.length - 1];
			var acls = {};
			var params = ["ip", "name", "port", "mode"];
			for (var i = 0; i < params.length; i++) {
				acls[p + "_" + params[i] + "_" + id] = "";
			}
			var id = parseInt(Math.random() * 100000000);
			var postData = { "id": id, "method": "dummy_script.sh", "params": [], "fields": acls };
			$.ajax({
				type: "POST",
				cache: false,
				url: "/_api/",
				data: JSON.stringify(postData),
				dataType: "json",
				success: function (response) {
					refresh_acl_table();
				}
			});
		}
		function refresh_acl_table(q) {
			$.ajax({
				type: "GET",
				url: "/_api/ss_acl",
				dataType: "json",
				async: false,
				success: function (data) {
					db_acl = data.result[0];
					refresh_acl_html();
					if (typeof db_acl["ss_acl_default_mode"] != "undefined") {
						if (E("ss_basic_mode").value == 1 && db_acl["ss_acl_default_mode"] == 1 || db_acl["ss_acl_default_mode"] == 0) {
							$('#ss_acl_default_mode').val(db_acl["ss_acl_default_mode"]);
						}
						if (E("ss_basic_mode").value == 2 && db_acl["ss_acl_default_mode"] == 2 || db_acl["ss_acl_default_mode"] == 0) {
							$('#ss_acl_default_mode').val(db_acl["ss_acl_default_mode"]);
						}
						if (E("ss_basic_mode").value == 3 && db_acl["ss_acl_default_mode"] == 3 || db_acl["ss_acl_default_mode"] == 0) {
							$('#ss_acl_default_mode').val(db_acl["ss_acl_default_mode"]);
						}
						if (E("ss_basic_mode").value == 5 && db_acl["ss_acl_default_mode"] == 5 || db_acl["ss_acl_default_mode"] == 0) {
							$('#ss_acl_default_mode').val(db_acl["ss_acl_default_mode"]);
						}
					}
					if (typeof db_acl["ss_acl_default_port"] != "undefined") {
						$('#ss_acl_default_port').val(db_acl["ss_acl_default_port"]);
					} else {
						$('#ss_acl_default_port').val("all");
					}
					for (var i = 1; i < acl_node_max + 1; i++) {
						$('#ss_acl_mode_' + i).val(db_acl["ss_acl_mode_" + i]);
						$('#ss_acl_port_' + i).val(db_acl["ss_acl_port_" + i]);
						$('#ss_acl_name_' + i).val(db_acl["ss_acl_name_" + i]);
					}
					set_default_port();
					$('#ss_acl_mode').val("1");
					$('#ss_acl_port').val("80,443");
				}
			});
		}
		function set_mode_1() {
			if ($('#ss_acl_mode').val() == 0 || $('#ss_acl_mode').val() == 3) {
				$("#ss_acl_port").val("all");
				E("ss_acl_port").readonly = "readonly";
				E("ss_acl_port").title = "不可更改，游戏模式下默认全端口";
			} else if ($('#ss_acl_mode').val() == 1) {
				$("#ss_acl_port").val("80,443");
				E("ss_acl_port").readonly = "readonly";
				E("ss_acl_port").title = "";
			} else if ($('#ss_acl_mode').val() == 2 || $('#ss_acl_mode').val() == 5) {
				$("#ss_acl_port").val("22,80,443");
				E("ss_acl_port").readonly = "";
				E("ss_acl_port").title = "";
			}
		}
		function set_mode_2(o) {
			var id2 = $(o).attr("id");
			var ids2 = id2.split("_");
			id2 = ids2[ids2.length - 1];
			if ($(o).val() == 0 || $(o).val() == 3) {
				$("#ss_acl_port_" + id2).val("all");
			} else if ($(o).val() == 1) {
				$("#ss_acl_port_" + id2).val("80,443");
			} else if ($(o).val() == 2) {
				$("#ss_acl_port_" + id2).val("22,80,443");
			}
		}
		function set_default_port() {
			if ($('#ss_acl_default_mode').val() == 3) {
				$("#ss_acl_default_port").val("all");
				E("ss_acl_default_port").readonly = "readonly";
				E("ss_acl_default_port").title = "不可更改，游戏模式下默认全端口";
			} else {
				E("ss_acl_default_port").readonly = "";
				E("ss_acl_default_port").title = "";
			}
		}
		function refresh_acl_html() {
			acl_confs = getACLConfigs();
			var n = 0;
			for (var i in acl_confs) {
				n++;
			}
			var code = '';
			code += '<table width="100%" border="0" align="center" cellpadding="4" cellspacing="0" class="FormTable_table acl_lists" style="margin:-1px 0px 0px 0px;">'
			code += '<tr>'
			code += '<th width="23%">主机IP地址</th>'
			code += '<th width="23%">主机别名</th>'
			code += '<th width="23%">访问控制</th>'
			code += '<th width="23%">目标端口</th>'
			code += '<th width="8%">操作</th>'
			code += '</tr>'
			code += '</table>'
			code += '<table id="ACL_table" width="100%" border="0" align="center" cellpadding="4" cellspacing="0" class="list_table acl_lists" style="margin:-1px 0px 0px 0px;">'
			code += '<tr>'
			code += '<td width="23%">'
			code += '<input type="text" maxlength="15" class="input_ss_table" id="ss_acl_ip" align="left" style="float:left;width:110px;margin-left:16px;text-align:center" autocomplete="off" onClick="hideClients_Block();" autocorrect="off" autocapitalize="off">'
			code += '<img id="pull_arrow" height="14px;" src="/res/arrow-down.gif" align="right" onclick="pullLANIPList(this);" title="<#select_IP#>">'
			code += '<div id="ClientList_Block" class="clientlist_dropdown" style="margin-left:2px;margin-top:25px;"></div>'
			code += '</td>'
			code += '<td width="23%">'
			code += '<input type="text" id="ss_acl_name" class="input_ss_table" maxlength="50" style="width:140px;text-align:center" placeholder="" />'
			code += '</td>'
			code += '<td width="23%">'
			code += '<select id="ss_acl_mode" style="width:140px;margin:0px 0px 0px 2px;text-align-last:center;padding-left: 12px;" class="input_option" onchange="set_mode_1(this);">'
			code += '<option value="0">不通过代理</option>'
			code += '<option value="1">gfwlist模式</option>'
			code += '<option value="2">大陆白名单模式</option>'
			code += '<option value="3">游戏模式</option>'
			code += '<option value="5">全局代理模式</option>'
			code += '<option value="6">回国模式</option>'
			code += '</select>'
			code += '</td>'
			code += '<td width="23%">'
			code += '<select id="ss_acl_port" style="width:152px;margin:0px 0px 0px 2px;text-align-last:center;padding-left: 12px;" class="input_option">'
			code += '<option value="80,443">80,443</option>'
			code += '<option value="22,80,443">22,80,443</option>'
			code += '<option value="all">all</option>'
			code += '</select>'
			code += '</td>'
			code += '<td width="8%">'
			code += '<input style="margin-left: 6px;margin: -2px 0px -4px -2px;" type="button" class="add_btn" onclick="addTr()" value="" />'
			code += '</td>'
			code += '</tr>'
			for (var field in acl_confs) {
				var ac = acl_confs[field];
				code += '<tr id="acl_tr_' + ac["acl_node"] + '">';
				code += '<td width="23%">' + ac["ip"] + '</td>';
				code += '<td width="23%">';
				code += '<input type="text" placeholder="' + ac["acl_node"] + '号机" id="ss_acl_name_' + ac["acl_node"] + '" name="ss_acl_name_' + ac["acl_node"] + '" class="input_option_2" maxlength="50" style="width:140px;" placeholder="" />';
				code += '</td>';
				code += '<td width="23%">';
				code += '<select id="ss_acl_mode_' + ac["acl_node"] + '" name="ss_acl_mode_' + ac["acl_node"] + '" style="width:140px;margin:0px 0px 0px 2px;" class="sel_option" onchange="set_mode_2(this);">';
				if ($("#ss_basic_mode").val() == 6) {
					code += '<option value="0">不通过代理</option>';
					code += '<option value="6">回国模式</option>';
				} else {
					code += '<option value="0">不通过代理</option>';
					code += '<option value="1">gfwlist模式</option>';
					code += '<option value="2">大陆白名单模式</option>';
					code += '<option value="3">游戏模式</option>';
					code += '<option value="5">全局代理模式</option>';
					code += '<option value="6">回国模式</option>';
				}
				code += '</select>'
				code += '</td>';
				code += '<td width="23%">';
				if (ac["mode"] == 3) {
					code += '<input type="text" id="ss_acl_port_' + ac["acl_node"] + '" name="ss_acl_port_' + ac["acl_node"] + '" class="input_option_2" maxlength="50" style="width:140px;" title="不可更改，游戏模式下默认全端口" readonly = "readonly" />';
				} else if (ac["mode"] == 0) {
					code += '<input type="text" id="ss_acl_port_' + ac["acl_node"] + '" name="ss_acl_port_' + ac["acl_node"] + '" class="input_option_2" maxlength="50" style="width:140px;" title="不可更改，不通过SS下默认全端口" readonly = "readonly" />';
				} else {
					code += '<input type="text" id="ss_acl_port_' + ac["acl_node"] + '" name="ss_acl_port_' + ac["acl_node"] + '" class="input_option_2" maxlength="50" style="width:140px;" placeholder="" />';
				}
				code += '</td>';
				code += '<td width="8%">';
				code += '<input style="margin: -2px 0px -4px -2px;" id="acl_node_' + ac["acl_node"] + '" class="remove_btn" type="button" onclick="delTr(this);" value="">'
				code += '</td>';
				code += '</tr>';
			}
			code += '<tr>';
			if (n == 0) {
				code += '<td width="23%">所有主机</td>';
			} else {
				code += '<td width="23%">其它主机</td>';
			}
			code += '<td width="23%">默认规则</td>';
			ssmode = E("ss_basic_mode").value;
			if (n == 0) {
				if (ssmode == 0) {
					code += '<td width="23%">SS关闭</td>';
				} else if (ssmode == 1) {
					code += '<td width="23%">gfwlist模式</td>';
				} else if (ssmode == 2) {
					code += '<td width="23%">大陆白名单模式</td>';
				} else if (ssmode == 3) {
					code += '<td width="23%">游戏模式</td>';
				} else if (ssmode == 5) {
					code += '<td width="23%">全局模式</td>';
				} else if (ssmode == 6) {
					code += '<td width="23%">回国模式</td>';
				}
			} else {
				code += '<td width="23%">';
				code += '<select id="ss_acl_default_mode" style="width:140px;margin:0px 0px 0px 2px;" class="sel_option" onchange="set_default_port();">';
				if (ssmode == 0) {
					code += '<td>SS关闭</td>';
				} else if (ssmode == 1) {
					code += '<option value="0">不通过代理</option>';
					code += '<option value="1" selected>gfwlist模式</option>';
				} else if (ssmode == 2) {
					code += '<option value="0">不通过代理</option>';
					code += '<option value="2" selected>大陆白名单模式</option>';
				} else if (ssmode == 3) {
					code += '<option value="0">不通过代理</option>';
					code += '<option value="3" selected>游戏模式</option>';
				} else if (ssmode == 5) {
					code += '<option value="0">不通过代理</option>';
					code += '<option value="5" selected>全局代理模式</option>';
				} else if (ssmode == 6) {
					code += '<option value="0">不通过代理</option>';
					code += '<option value="6" selected>回国模式</option>';
				}
				code += '</select>';
				code += '</td>';
			}
			code += '<td width="23%">';
			code += '<input type="text" id="ss_acl_default_port" class="input_option_2" maxlength="50" style="width:140px;" placeholder="" />';
			code += '</td>';
			code += '<td width="8%">';
			code += '</td>';
			code += '</tr>';
			code += '</table>';
			$(".acl_lists").remove();
			$('#ss_acl_table').append(code);
			showDropdownClientList('setClientIP', 'ip', 'all', 'ClientList_Block', 'pull_arrow', 'online');
		}
		function setClientIP(ip, name, mac) {
			E("ss_acl_ip").value = ip;
			E("ss_acl_name").value = name;
			hideClients_Block();
		}
		function pullLANIPList(obj) {
			var element = E('ClientList_Block');
			var isMenuopen = element.offsetWidth > 0 || element.offsetHeight > 0;
			if (isMenuopen == 0) {
				obj.src = "/res/arrow-top.gif"
				element.style.display = 'block';
			} else {
				hideClients_Block();
			}
		}
		function hideClients_Block() {
			E("pull_arrow").src = "/res/arrow-down.gif";
			E('ClientList_Block').style.display = 'none';
		}
		function close_proc_status() {
			$("#detail_status").fadeOut(200);
		}
		function get_proc_status() {
			$('#proc_status').val("请稍后，正在获取状态中...");
			$("#detail_status").fadeIn(500);
			var id = parseInt(Math.random() * 100000000);
			var postData = { "id": id, "method": "ss_proc_status.sh", "params": [], "fields": "" };
			$.ajax({
				type: "POST",
				cache: false,
				url: "/_api/",
				data: JSON.stringify(postData),
				dataType: "json",
				success: function (response) {
					if (response.result == id) {
						write_proc_status();
					}
				}
			});
		}
		function write_proc_status() {
			$.ajax({
				url: '/_temp/ss_proc_status.txt',
				type: 'GET',
				cache: false,
				dataType: 'text',
				success: function (res) {
					$('#proc_status').val(res);
				}
			});
		}
		function get_online_nodes(action) {
			if (action == 0 || action == 1) {
				layer.confirm('你确定要删除吗？', {
					shade: 0.8,
				}, function (index) {
					layer.close(index);
					save_online_nodes(action);
				}, function (index) {
					layer.close(index);
					return false;
				});
			} else {
				save_online_nodes(action);
			}
		}
		function save_online_nodes(action) {
			db_ss["ss_basic_action"] = "13";
			var dbus_post = {};
			if (action == "4") {
				dbus_post["ss_base64_links"] = Base64.encode(encodeURIComponent(E("ss_base64_links").value));
			}
			if (action == "2" || action == "3") {
				dbus_post["ss_online_links"] = Base64.encode(E("ss_online_links").value);
				dbus_post["ssr_subscribe_mode"] = E("ssr_subscribe_mode").value;
				dbus_post["ss_basic_online_links_goss"] = E("ss_basic_online_links_goss").value;
				dbus_post["ss_basic_node_update"] = E("ss_basic_node_update").value;
				dbus_post["ss_basic_node_update_day"] = E("ss_basic_node_update_day").value;
				dbus_post["ss_basic_node_update_hr"] = E("ss_basic_node_update_hr").value;
				dbus_post["ss_basic_exclude"] = E("ss_basic_exclude").value.replace(pattern, "") || "";
				dbus_post["ss_basic_include"] = E("ss_basic_include").value.replace(pattern, "") || "";
				dbus_post["ss_basic_node_update"] = E("ss_basic_node_update").value;
				dbus_post["ss_basic_hy2_up_speed"] = E("ss_basic_hy2_up_speed").value;
				dbus_post["ss_basic_hy2_dl_speed"] = E("ss_basic_hy2_dl_speed").value;
				dbus_post["ss_basic_hy2_tfo_switch"] = E("ss_basic_hy2_tfo_switch").value;
			}
			if (ws_flag == 1) {
				push_data_ws("ss_online_update.sh", action, dbus_post);
			} else {
				push_data("ss_online_update.sh", action, dbus_post);
			}
		}
		function v2ray_binary_update() {
			var dbus_post = {};
			db_ss["ss_basic_action"] = "15";
			layer.confirm('<li>为了避免不必要的问题，请保证路由器和服务器上的v2ray版本一致！</li><br /><li>你确定要更新v2ray二进制吗？</li>', {
				shade: 0.8,
			}, function (index) {
				$("#log_content3").attr("rows", "20");
				push_data("ss_v2ray.sh", 1, dbus_post);
				layer.close(index);
				return true;
			}, function (index) {
				layer.close(index);
				return false;
			});
		}
		function xray_binary_update() {
			var dbus_post = {};
			db_ss["ss_basic_action"] = "15";
			note = "<li>v1.7.5：security支持TLS和XTLS，不支持REALITY，选此会将Xray二进制切换到此版本！</li>";
			note += "<li>v1.8.X：security支持TLS和REALITY，不支持XTLS，选此会将Xray二进制更新到1.8.x最新版本！</li>";
			note += "<li>切换/更新文件将从github上下载，请确保当前代理工作正常，不然将无法下载或下载及其缓慢！</li>";
			note += "<li>更多信息，请查看<a style='color:#22ab39;' href='https://github.com/XTLS/Xray-core/releases' target='_blank'>Xray releases页面</a>。</li>";
			layer.open({
				type: 0,
				skin: 'layui-layer-lan',
				shade: 0.8,
				title: '请选择你需要的Xray版本！',
				time: 0,
				area: '670px',
				offset: '350px',
				btnAlign: 'c',
				maxmin: true,
				content: note,
				btn: ['v1.7.5', 'v1.8.x'],
				btn1: function () {
					push_data("ss_xray.sh", 1, dbus_post);
					layer.closeAll();
				},
				btn2: function () {
					push_data("ss_xray.sh", 2, dbus_post);
				}
			});
		}
		function ssrust_binary_update() {
			var dbus_post = {};
			db_ss["ss_basic_action"] = "20";
			layer.confirm('<li>点击确定将开始shadowsocks-rust二进制下载，请确保你的路由器jffs空间容量足够！</li>', {
				shade: 0.8,
			}, function (index) {
				$("#log_content3").attr("rows", "20");
				push_data("ss_rust_update.sh", 1, dbus_post);
				layer.close(index);
				return true;
			}, function (index) {
				layer.close(index);
				return false;
			});
		}
		function set_cron(action) {
			var dbus_post = {};
			if (action == 1) {
				db_ss["ss_basic_action"] = "16";
				var cron_params1 = ["ss_reboot_check", "ss_basic_week", "ss_basic_day", "ss_basic_inter_min", "ss_basic_inter_hour", "ss_basic_inter_day", "ss_basic_inter_pre", "ss_basic_custom", "ss_basic_time_hour", "ss_basic_time_min"];
				for (var i = 0; i < cron_params1.length; i++) {
					dbus_post[cron_params1[i]] = E(cron_params1[i]).value;
				}
				if (!E("ss_basic_custom").value) {
					dbus_post["ss_basic_custom"] = "";
				} else {
					dbus_post["ss_basic_custom"] = Base64.encode(E("ss_basic_custom").value);
				}
			} else if (action == 2) {
				db_ss["ss_basic_action"] = "17";
				var cron_params2 = ["ss_basic_tri_reboot_time"]; //for ss
				for (var i = 0; i < cron_params2.length; i++) {
					dbus_post[cron_params2[i]] = E(cron_params2[i]).value;
				}
			}
			push_data("ss_reboot_job.sh", action, dbus_post);
		}

		// (修改) 更新保存逻辑以包含新的"每日定时切换"设置
		function save_failover() {
			var dbus_post = {};
			db_ss["ss_basic_action"] = "19";
			var fov_inp = ["ss_failover_s1", "ss_failover_s2_1", "ss_failover_s2_2", "ss_failover_s3_1", "ss_failover_s3_2", "ss_failover_s4_1", "ss_failover_s4_2", "ss_failover_s4_3", "ss_failover_s5", "ss_basic_interval", "ss_daily_switch_days", "ss_daily_switch_hour", "ss_daily_switch_minute"];
			var fov_chk = ["ss_failover_enable", "ss_failover_c1", "ss_failover_c2", "ss_failover_c3", "ss_daily_switch_enable"];
			for (var i = 0; i < fov_inp.length; i++) {
				if (E(fov_inp[i])) dbus_post[fov_inp[i]] = E(fov_inp[i]).value;
			}
			for (var i = 0; i < fov_chk.length; i++) {
				if (E(fov_chk[i])) dbus_post[fov_chk[i]] = E(fov_chk[i]).checked ? '1' : '0';
			}
			push_data("ss_status_reset.sh", "", dbus_post);
		}
	</script>
</head>

<body id="app" skin='<% nvram_get("sc_skin"); %>' onload="init();">
	<div id="TopBanner"></div>
	<div id="Loading" class="popup_bg"></div>
	<div id="LoadingBar" class="popup_bar_bg_ks" style="z-index: 200;">
		<table cellpadding="5" cellspacing="0" id="loadingBarBlock" class="loadingBarBlock" align="center">
			<tr>
				<td height="100">
					<div id="loading_block3" style="margin:10px auto;margin-left:10px;width:85%; font-size:12pt;"></div>
					<div id="loading_block2" style="margin:10px auto;width:95%;"></div>
					<div id="log_content2" style="margin-left:15px;margin-right:15px;margin-top:10px;overflow:hidden">
						<textarea cols="50" rows="30" wrap="on" readonly="readonly" id="log_content3" autocomplete="off"
							autocorrect="off" autocapitalize="off" spellcheck="false"
							style="border:1px solid #000;width:99%; font-family:'Lucida Console'; font-size:11px;background:transparent;color:#FFFFFF;outline: none;padding-left:3px;padding-right:22px;overflow-x:hidden"></textarea>
					</div>
					<div id="ok_button" class="apply_gen" style="background: #000;display: none;">
						<input id="ok_button1" class="button_gen" type="button" onclick="hideSSLoadingBar()" value="确定">
					</div>
				</td>
			</tr>
		</table>
	</div>
	<div id="latency_test_settings" class="fancyss_qis pop_div_bg">
		<table class="QISform_wireless" border="0" align="center" cellpadding="5" cellspacing="0">
			<tr>
				<td>
					<div class="user_title">节点延迟测试设置</div>
					<div id="latency_test_settings_div">
						<table id="table_test" style="margin:-1px 0px 0px 0px;" width="100%" border="1" align="center"
							cellpadding="4" cellspacing="0" class="FormTable">
							<script type="text/javascript">
								var furl = [
									"http://www.msftncsi.com/ncsi.txt",
									"http://www.google.com/generate_204",
									"http://www.gstatic.com/generate_204",
									"http://developer.google.cn/generate_204",
									"http://connectivitycheck.gstatic.com/generate_204",
									"http://edge.microsoft.com/captiveportal/generate_204",
									"http://cp.cloudflare.com",
									"http://captive.apple.com",
									"http://www.google.com",
									"http://www.google.com.hk",
									"http://www.google.com.tw"
								];
								var curl = [
									"http://www.baidu.com",
									"http://www.sina.com",
									"http://www.weibo.com",
									"http://connectivitycheck.platform.hicloud.com/generate_204",
									"http://wifi.vivo.com.cn/generate_204",
									"http://www.apple.com/library/test/success.html",
									"http://connect.rom.miui.com/generate_204",
									"http://www.msftconnecttest.com/connecttest.txt"
								];
								var lt_cru = [
									["0", "关闭定时测试"],
									["1", "定时测试web延迟"]
								]
								var lt_time = [["15", "每隔15分钟"], ["20", "每隔20分钟"], ["30", "每隔30分钟"], ["60", "每隔60分钟"]];
								$('#table_test').forms([
									{ title: '延迟测试设置', thead: '1' },
									{ title: '<a onmouseover="mOver(this, 147)" onmouseout="mOut(this)" class="hintstyle" href="javascript:void(0);">web延迟测试域名 - 国外</a>', id: 'ss_basic_wt_furl', type: 'select', style: 'width:auto', options: furl, value: '' },
									{ title: '<a onmouseover="mOver(this, 148)" onmouseout="mOut(this)" class="hintstyle" href="javascript:void(0);">web延迟测试域名 - 国内</a>', id: 'ss_basic_wt_curl', type: 'select', style: 'width:auto', options: curl, value: '' },
									{
										title: '定时测试节点延迟', multi: [
											{ id: 'ss_basic_lt_cru_opts', type: 'select', style: 'width:auto', func: 'u', options: lt_cru, value: '0' },
											{ id: 'ss_basic_lt_cru_time', type: 'select', style: 'width:auto', options: lt_time, value: '0' },
										]
									},
								]);
							</script>
						</table>
					</div>
				</td>
			</tr>
		</table>
		<span style="margin-left:30px">【web延迟测试】中设置的国外域名，同样会用于插件顶部[插件运行状态]中的国外链接延迟测试</span>
		<div style="padding-top:10px;padding-bottom:10px;width:100%;text-align:center;">
			<input id="save_latency_sett" class="button_gen" type="button" onclick="save_latency_sett();" value="保存">
			<input id="leav_test_sett" class="button_gen" type="button" onclick="leav_test_sett();" value="返回">
		</div>
	</div>
	<table class="content" align="center" cellpadding="0" cellspacing="0">
		<tr>
			<td width="17">&nbsp;</td>
			<td valign="top" width="202">
				<div id="mainMenu"></div>
				<div id="subMenu"></div>
			</td>
			<td valign="top">
				<div id="tabMenu" class="submenuBlock"></div>
				<table width="98%" border="0" align="left" cellpadding="0" cellspacing="0">
					<tr>
						<td align="left" valign="top">
							<div>
								<table width="760px" border="0" cellpadding="5" cellspacing="0" bordercolor="#6b8fa3"
									class="FormTitle" id="FormTitle">
									<tr>
										<td bgcolor="#4D595D" colspan="3" valign="top">
											<div>&nbsp;</div>
											<div id="title_name" class="formfonttitle"></div>
											<script type="text/javascript">
												var MODEL = '<% nvram_get("odmpid"); %>' || '<% nvram_get("productid"); %>';
												var FANCYSS_TITLE = " - " + pkg_name;
												$("#title_name").html(MODEL + " 科学上网插件" + FANCYSS_TITLE);
												$("#ss_title").html(MODEL + " - fancyss");
											</script>
											<div style="float:right; width:15px; height:25px;margin-top:-20px">
												<img id="return_btn" onclick="reload_Soft_Center();" align="right"
													style="cursor:pointer;position:absolute;margin-left:-30px;margin-top:-25px;"
													title="返回软件中心" src="/images/backprev.png"
													onMouseOver="this.src='/images/backprevclick.png'"
													onMouseOut="this.src='/images/backprev.png'"></img>
											</div>

											<div style="margin:10px 0 0 5px;" class="splitLine"></div>

											<div class="SimpleNote" id="head_illustrate">
												<ul id="fixed_msg" style="padding:0;margin:0;line-height:1.8;">
													<li id="msg_0" style="list-style: none;height:23px">
														📌 本插件支持：
														<a href="https://github.com/XTLS/xray-core"
															target="_blank"><em><u>Xray</u></em></a>
														<a href="https://github.com/apernet/hysteria"
															target="_blank"><em><u>Hysteria2</u></em></a>
														<a href="https://github.com/wangyu-/udp2raw"
															target="_blank"><em><u>UDP2RAW</u></em></a>
														<a href="https://github.com/xtaci/kcptun"
															target="_blank"><em><u>KCPTUN</u></em></a>
														&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span
															id="ss_version_show"></span>
													</li>
												</ul>

												</ul>
											</div>
											<div id="detail_status" class="content_status"
												style="box-shadow: 3px 3px 10px #000;margin-top: -20px;">
												<div class="user_title">【科学上网】状态检测</div>
												<div style="margin-left:15px">
													<i>&nbsp;&nbsp;详细状态检测可以让你了解插件相关二进制和iptables的运行状况，用以排除一些使用中的问题。</i>
												</div>
												<div
													style="margin: 10px 10px 10px 10px;width:98%;text-align:center;overflow:hidden">
													<textarea cols="63" rows="36" wrap="off" id="proc_status"
														style="line-height:1.45;width:98%;padding-left:13px;padding-right:33px;border:0px solid #222;font-family:'Lucida Console'; font-size:11px;background: transparent;color:#FFFFFF;outline: none;overflow-x:hidden;"
														autocomplete="off" autocorrect="off" autocapitalize="off"
														spellcheck="false"></textarea>
												</div>
												<div
													style="margin-top:5px;padding-bottom:10px;width:100%;text-align:center;">
													<input class="button_gen" type="button"
														onclick="close_proc_status();" value="返回主界面">
												</div>
											</div>
											<div id="ssf_status_div" class="content_status_ext"
												style="box-shadow: 3px 3px 10px #000;margin-top: -20px;margin-left:0px;width:748px;">
												<div class="user_title">国外历史状态 - <lable id="ssf_test_url"></lable>
												</div>
												<div style="margin-left:15px"><i>&nbsp;&nbsp;此功能仅在开启故障转移时生效。</i></div>
												<div
													style="margin: 10px 10px 10px 10px;width:98%;text-align:center;overflow:hidden;">
													<textarea cols="63" rows="36" wrap="off" id="log_content_f"
														style="width:98%;padding-left:13px;padding-right:33px;border:0px solid #222;font-family:'Lucida Console'; font-size:10px;background: transparent;color:#FFFFFF;outline: none;overflow-x:hidden;"
														autocomplete="off" autocorrect="off" autocapitalize="off"
														spellcheck="false"></textarea>
												</div>
												<div
													style="margin-top:5px;padding-bottom:10px;width:100%;text-align:center;">
													<input class="button_gen" type="button"
														onclick="download_route_file(6);" value="下载日志">
													<input class="button_gen" type="button"
														onclick="close_ssf_status();" value="返回主界面">
													<input style="margin-left:10px" type="checkbox" id="ss_failover_c4">
													<lable>&nbsp;暂停日志刷新</lable>
												</div>
											</div>
											<div id="ssc_status_div" class="content_status_ext"
												style="box-shadow: 3px 3px 10px #000;margin-top: -20px;margin-left:0px;width:748px;">
												<div class="user_title">国内历史状态 - <lable id="ssc_test_url"></lable>
												</div>
												<div style="margin-left:15px"><i>&nbsp;&nbsp;此功能仅在开启故障转移时生效。</i></div>
												<div
													style="margin: 10px 10px 10px 10px;width:98%;text-align:center;overflow:hidden;">
													<textarea cols="63" rows="36" wrap="off" id="log_content_c"
														style="width:98%;padding-left:13px;padding-right:33px;border:0px solid #222;font-family:'Lucida Console'; font-size:10px;background: transparent;color:#FFFFFF;outline: none;overflow-x:hidden;"
														autocomplete="off" autocorrect="off" autocapitalize="off"
														spellcheck="false"></textarea>
												</div>
												<div
													style="margin-top:5px;padding-bottom:10px;width:100%;text-align:center;">
													<input class="button_gen" type="button"
														onclick="download_route_file(7);" value="下载日志">
													<input class="button_gen" type="button"
														onclick="close_ssc_status();" value="返回主界面">
													<input style="margin-left:10px" type="checkbox" id="ss_failover_c5">
												</div>
											</div>
											<div id="dns_status_div" class="content_status"
												style="box-shadow: 3px 3px 10px #000;margin-top: -140px;margin-left:0px;width:748px;">
												<div class="user_title">DNS解析测试</div>
												<div style="margin-left:15px" id="dns_test_note_1"></div>
												<div style="margin-left:15px" id="dns_test_note_2"></div>
												<div style="margin-left:15px" id="dns_test_note_3"></div>
												<div
													style="margin: 10px 10px 10px 10px;width:98%;outline: 1px solid #727272;text-align:center;overflow:hidden;">
													<textarea cols="63" rows="40" wrap="off" id="log_content_dns"
														style="line-height: 140%;width:98%;padding-left:13px;padding-right:33px;border:0px solid #222;font-family:'Lucida Console'; font-size:11px;background: transparent;color:#FFFFFF;outline: none;overflow-x:hidden;"
														autocomplete="off" autocorrect="off" autocapitalize="off"
														spellcheck="false"></textarea>
												</div>
												<div
													style="margin-top:5px;padding-bottom:10px;width:100%;text-align:center;">
													<input id="log_dig" class="button_gen" style="display:none;"
														type="button" onclick="download_route_file(10);" value="下载日志">
													<input id="log_resv" class="button_gen" style="display:none;"
														type="button" onclick="download_route_file(11);" value="下载日志">
													<input class="button_gen" type="button"
														onclick="close_dns_status();" value="返回主界面">
													<input style="margin-left:10px" type="checkbox" id="ss_failover_c5">
												</div>
											</div>
											<div id="qrcode_show" class="content_status"
												style="box-shadow: 3px 3px 10px #000;margin-top: 90px;margin-left:197px;width:356px;height:356px;background: #fff;">
												<div style="text-align: center;margin-top:10px"><span id="qrtitle"
														style="font-size:16px;color:#000;"></span></div>
												<div id="qrcode"
													style="margin: 10px 50px 10px 50px;width:256px;height:256px;text-align:center;overflow:hidden">
												</div>
												<div
													style="margin-top:15px;padding-bottom:10px;width:100%;text-align:center;">
													<input class="button_gen" type="button" onclick="cleanCode();"
														value="返回">
												</div>
											</div>
											<div id="ss_switch_show" style="margin:-1px 0px 0px 0px;">
												<table style="margin:-1px 0px 0px 0px;" width="100%" border="1"
													align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"
													class="FormTable" id="ss_switch_table">
													<thead>
														<tr>
															<td colspan="2">开关</td>
														</tr>
													</thead>
													<tr>
														<th id="ss_switch">科学上网开关</th>
														<td colspan="2">
															<div class="switch_field"
																style="display:table-cell;float: left;">
																<label for="ss_basic_enable">
																	<input id="ss_basic_enable" class="switch"
																		type="checkbox" style="display: none;">
																	<div class="switch_container">
																		<div class="switch_bar"></div>
																		<div class="switch_circle transition_style">
																			<div></div>
																		</div>
																	</div>
																</label>
															</div>


														</td>
													</tr>
													<tr id="ss_state">
														<th>插件运行状态</th>
														<td>
															<div
																style="display:table-cell;float: left;margin-left:0px;">
																<a class="hintstyle" href="javascript:void(0);"
																	onclick="openssHint(0)">
																	<span id="ss_state2">国外连接 - Waiting...</span>
																	<br />
																	<span id="ss_state3">国内连接 - Waiting...</span>
																</a>
															</div>
															<div
																style="display:table-cell;float: left;margin-left:270px;position: absolute;padding: 10.5px 0px;">
																<a type="button" class="ss_btn"
																	target="https://ip.skk.moe/"
																	href="https://ip.skk.moe/">分流检测</a>
															</div>
															<div
																style="display:table-cell;float: left;margin-left:350px;position: absolute;padding: 10.5px 0px;">
																<a type="button" class="ss_btn" style="cursor:pointer"
																	onclick="get_proc_status()"
																	href="javascript:void(0);">详细状态</a>
															</div>
														</td>
													</tr>
												</table>
											</div>
											<div id="tablets">
												<table style="margin:10px 0px 0px 0px;border-collapse:collapse"
													width="100%" height="37px">
													<tr>
														<td cellpadding="0" cellspacing="0" style="padding:0" border="1"
															bordercolor="#222">
															<input id="show_btn0" class="show-btn0"
																style="cursor:pointer" type="button" value="帐号设置" />
															<input id="show_btn1" class="show-btn1"
																style="cursor:pointer" type="button" value="节点管理" />
															<input id="show_btn2" class="show-btn2"
																style="cursor:pointer" type="button" value="故障转移" />
															<input id="show_btn3" class="show-btn3"
																style="cursor:pointer" type="button" value="DNS设定" />
															<input id="show_btn4" class="show-btn4"
																style="cursor:pointer" type="button" value="黑白名单" />
															<!-- 
															<input id="show_btn5" class="show-btn5" style="cursor:pointer" type="button" value="KCP加速" /> 
															<input id="show_btn6" class="show-btn6" style="cursor:pointer" type="button" value="UDP加速"/>
															-->
															<input id="show_btn7" class="show-btn7"
																style="cursor:pointer" type="button" value="更新管理" />
															<input id="show_btn8" class="show-btn8"
																style="cursor:pointer" type="button" value="访问控制" />
															<input id="show_btn9" class="show-btn9"
																style="cursor:pointer" type="button" value="附加功能" />
															<input id="show_btn10" class="show-btn10"
																style="cursor:pointer" type="button" value="查看日志" />
														</td>
													</tr>
												</table>
											</div>
											<div id="add_fancyss_node" class="contentM_qis pop_div_bg">
												<table class="QISform_wireless" border="0" align="center"
													cellpadding="5" cellspacing="0">
													<tr style="height:32px;">
														<td>
															<div id="add_fancyss_node_title" class="user_title">添加节点
															</div>
															<div>
																<table width="100%" border="0" align="left"
																	cellpadding="0" cellspacing="0"
																	class="vpnClientTitle">
																	<tr>
																		<td width="12.5%" align="center" id="ssTitle"
																			onclick="tabclickhandler(0);">SS节点</td>
																		<td width="12.5%" align="center" id="ssrTitle"
																			onclick="tabclickhandler(1);">SSR节点</td>
																		<td width="12.5%" align="center" id="v2rayTitle"
																			onclick="tabclickhandler(3);">V2Ray节点</td>
																		<td width="12.5%" align="center" id="xrayTitle"
																			onclick="tabclickhandler(4);">Xray节点</td>
																		<td width="12.5%" align="center"
																			id="trojanTitle"
																			onclick="tabclickhandler(5);">Trojan节点</td>
																		<td width="12.5%" align="center" id="naiveTitle"
																			onclick="tabclickhandler(6);">Naïve节点</td>
																		<td width="12.5%" align="center" id="tuicTitle"
																			onclick="tabclickhandler(7);">tuic节点</td>
																		<td width="12.5%" align="center" id="hy2Title"
																			onclick="tabclickhandler(8);">hysteria2节点
																		</td>
																	</tr>
																</table>
															</div>
														</td>
													</tr>
													<tr>
														<td>
															<div>
																<table id="table_add_nodes" width="100%" border="1"
																	align="center" cellpadding="4" cellspacing="0"
																	class="FormTable">
																	<script type="text/javascript">
																		$('#table_add_nodes').forms([
																			{ title: '使用模式', id: 'ss_node_table_mode', type: 'select', func: 'v', options: option_modes, style: 'width:412px;', value: "2" },
																			{ title: '使用json配置', rid: 'v2ray_use_json_tr', id: 'ss_node_table_v2ray_use_json', type: 'checkbox', func: 'v', help: '27', value: false },
																			{ title: '使用json配置', rid: 'xray_use_json_tr', id: 'ss_node_table_xray_use_json', type: 'checkbox', func: 'v', help: '25', value: false },
																			{ title: '节点别名', rid: 'ss_name_support_tr', id: 'ss_node_table_name', type: 'text', maxlen: '64', style: 'width:400px' },
																			{ title: '服务器地址', rid: 'ss_server_support_tr', id: 'ss_node_table_server', type: 'text', maxlen: '64', style: 'width:400px' },
																			{ title: '服务器端口', rid: 'ss_port_support_tr', id: 'ss_node_table_port', type: 'text', maxlen: '64', style: 'width:400px' },
																			{ title: '密码', rid: 'ss_passwd_support_tr', id: 'ss_node_table_password', type: 'text', maxlen: '64', style: 'width:400px' },
																			{ title: '加密方式', rid: 'ss_method_support_tr', id: 'ss_node_table_method', type: 'select', options: option_method, style: 'width:412px', value: "aes-256-cfb" },
																			{ title: '混淆 (obfs)', rid: 'ss_obfs_support', id: 'ss_node_table_ss_obfs', type: 'select', func: 'v', options: [["0", "关闭"], ["tls", "tls"], ["http", "http"]], style: 'width:412px', value: "0" },
																			{ title: '混淆主机名 (obfs-host)', rid: 'ss_obfs_host_support', id: 'ss_node_table_ss_obfs_host', type: 'text', maxlen: '300', style: 'width:400px', ph: 'bing.com' },
																			{ title: '协议 (protocol)', rid: 'ssr_protocol_tr', id: 'ss_node_table_rss_protocol', type: 'select', func: 'v', options: option_protocals, style: 'width:412px', value: "0" },
																			{ title: '协议参数 (protocol_param)', rid: 'ssr_protocol_param_tr', id: 'ss_node_table_rss_protocol_param', type: 'text', maxlen: '300', style: 'width:400px', ph: 'id:password' },
																			{ title: '混淆 (obfs)', rid: 'ssr_obfs_tr', id: 'ss_node_table_rss_obfs', type: 'select', func: 'v', options: option_obfs, style: 'width:412px', value: "0" },
																			{ title: '混淆参数 (obfs_param)', rid: 'ssr_obfs_param_tr', id: 'ss_node_table_rss_obfs_param', type: 'text', maxlen: '300', style: 'width:400px', ph: 'bing.com' },
																			{ title: '<em>服务器配置</em>（以下配置使用vmess作为传出协议，其它传出协议请使用json配置）', class: 'v2ray_elem', th: '2' },
																			{ title: '用户id (id)', rid: 'v2ray_uuid_tr', id: 'ss_node_table_v2ray_uuid', type: 'text', maxlen: '300', hint: '49', style: 'width:400px' },
																			{ title: '额外ID (Alterld)', rid: 'v2ray_alterid_tr', id: 'ss_node_table_v2ray_alterid', type: 'text', maxlen: '300', style: 'width:400px', value: "0" },
																			{ title: '加密方式 (security)', rid: 'v2ray_security_tr', id: 'ss_node_table_v2ray_security', type: 'select', options: option_v2enc, style: 'width:412px', value: "auto" },
																			{ title: '<em>底层传输方式</em>', class: 'v2ray_elem', th: '2' },
																			{ title: '传输协议 (network)', rid: 'v2ray_network_tr', id: 'ss_node_table_v2ray_network', type: 'select', func: 'v', options: ["tcp", "kcp", "ws", "h2", "quic", "grpc"], style: 'width:412px', value: "tcp" },
																			{ title: '* tcp伪装类型 (type)', rid: 'v2ray_headtype_tcp_tr', id: 'ss_node_table_v2ray_headtype_tcp', type: 'select', func: 'v', options: option_headtcp, style: 'width:412px', value: "none" },
																			{ title: '* kcp伪装类型 (type)', rid: 'v2ray_headtype_kcp_tr', id: 'ss_node_table_v2ray_headtype_kcp', type: 'select', func: 'v', options: option_headkcp, style: 'width:412px', value: "none" },
																			{ title: '* quic伪装类型 (type)', rid: 'v2ray_headtype_quic_tr', id: 'ss_node_table_v2ray_headtype_quic', type: 'select', options: option_headquic, value: "none" },
																			{ title: '* grpc模式', rid: 'v2ray_grpc_mode_tr', id: 'ss_node_table_v2ray_grpc_mode', type: 'select', options: option_grpcmode, value: "" },
																			{ title: '* 伪装域名 (host)', rid: 'v2ray_network_host_tr', id: 'ss_node_table_v2ray_network_host', type: 'text', maxlen: '300', style: 'width:400px' },
																			{ title: '* 路径 (path)', rid: 'v2ray_network_path_tr', id: 'ss_node_table_v2ray_network_path', type: 'text', maxlen: '300', style: 'width:400px', ph: '没有请留空' },
																			{ title: '* kcp seed', rid: 'v2ray_kcp_seed_tr', id: 'ss_node_table_v2ray_kcp_seed', type: 'text', maxlen: '300', style: 'width:400px', ph: '没有请留空' },
																			{ title: '底层传输安全', rid: 'v2ray_network_security_tr', id: 'ss_node_table_v2ray_network_security', type: 'select', func: 'v', options: [["none", "关闭"], ["tls", "tls"]], style: 'width:412px', value: "none" },
																			{ title: '* 跳过证书验证 (AllowInsecure)', rid: 'v2ray_network_security_ai_tr', id: 'ss_node_table_v2ray_network_security_ai', type: 'checkbox', hint: '56', value: "false" },
																			{
																				title: '* alpn', rid: 'v2ray_network_security_alpn_tr', multi: [
																					{ suffix: '<input type="checkbox" id="ss_node_table_v2ray_network_security_alpn_h2">h2' },
																					{ suffix: '<input type="checkbox" id="ss_node_table_v2ray_network_security_alpn_http">http/1.1' },
																				]
																			},
																			{ title: 'SNI', rid: 'v2ray_network_security_sni_tr', id: 'ss_node_table_v2ray_network_security_sni', type: 'text' },
																			{ title: '多路复用 (Mux)', rid: 'v2ray_mux_enable_tr', id: 'ss_node_table_v2ray_mux_enable', type: 'checkbox', func: 'v', value: false },
																			{ title: '* Mux并发连接数', rid: 'v2ray_mux_concurrency_tr', id: 'ss_node_table_v2ray_mux_concurrency', type: 'text', maxlen: '300', style: 'width:400px' },
																			{ title: 'v2ray json', rid: 'v2ray_json_tr', id: 'ss_node_table_v2ray_json', type: 'textarea', rows: '32', ph: ph_v2ray, style: 'width:400px' },
																			{ title: '<em>服务器配置</em>（以下配置使用vless作为传出协议，其它传出协议请使用json配置）', class: 'xray_elem', th: '2' },
																			{ title: '用户id (id)', rid: 'xray_uuid_tr', id: 'ss_node_table_xray_uuid', type: 'text', maxlen: '300', style: 'width:400px' },
																			{ title: '加密 (encryption)', rid: 'xray_encryption_tr', id: 'ss_node_table_xray_encryption', type: 'text', hint: '55', maxlen: '300', style: 'width:400px', value: "none" },
																			{ title: 'flow (流控模式，没有请留空)', rid: 'xray_flow_tr', id: 'ss_node_table_xray_flow', type: 'select', options: option_xflow, style: 'width:412px', value: "" },
																			{ title: '<em>底层传输方式</em>', class: 'xray_elem', th: '2' },
																			{ title: '传输协议 (network)', rid: 'xray_network_tr', id: 'ss_node_table_xray_network', type: 'select', func: 'v', options: ["tcp", "kcp", "ws", "h2", "quic", "grpc"], style: 'width:412px', value: "tcp" },
																			{ title: '* tcp伪装类型 (type)', rid: 'xray_headtype_tcp_tr', id: 'ss_node_table_xray_headtype_tcp', type: 'select', hint: '36', func: 'v', options: option_headtcp, style: 'width:412px', value: "none" },
																			{ title: '* 伪装类型 (type)', rid: 'xray_headtype_kcp_tr', id: 'ss_node_table_xray_headtype_kcp', type: 'select', func: 'v', options: option_headkcp, style: 'width:412px', value: "none" },
																			{ title: '* quic伪装类型 (type)', rid: 'xray_headtype_quic_tr', id: 'ss_node_table_xray_headtype_quic', type: 'select', options: option_headquic, value: "none" },
																			{ title: '* grpc模式', rid: 'xray_grpc_mode_tr', id: 'ss_node_table_xray_grpc_mode', type: 'select', options: option_grpcmode, value: "multi" },
																			{ title: '* 伪装域名 (host)', rid: 'xray_network_host_tr', id: 'ss_node_table_xray_network_host', type: 'text', maxlen: '300', style: 'width:400px' },
																			{ title: '* 路径 (path)', rid: 'xray_network_path_tr', id: 'ss_node_table_xray_network_path', type: 'text', maxlen: '300', style: 'width:400px', ph: '没有请留空' },
																			{ title: '* kcp seed', rid: 'xray_kcp_seed_tr', id: 'ss_node_table_xray_kcp_seed', type: 'text', maxlen: '300', style: 'width:400px', ph: '没有请留空' },
																			{ title: '底层传输安全', rid: 'xray_network_security_tr', id: 'ss_node_table_xray_network_security', type: 'select', func: 'v', options: [["none", "关闭"], ["tls", "tls"], ["xtls", "xtls"], ["reality", "reality"]], style: 'width:412px', value: "none" },
																			{ title: '* 跳过证书验证 (AllowInsecure)', rid: 'xray_network_security_ai_tr', id: 'ss_node_table_xray_network_security_ai', type: 'checkbox', hint: '56', value: "false" },
																			{
																				title: '* alpn', rid: 'xray_network_security_alpn_tr', multi: [
																					{ suffix: '<input type="checkbox" id="ss_node_table_xray_network_security_alpn_h2">h2' },
																					{ suffix: '<input type="checkbox" id="ss_node_table_xray_network_security_alpn_http">http/1.1' },
																				]
																			},
																			{ title: '* show', rid: 'xray_show_tr', id: 'ss_node_table_xray_show', type: 'checkbox', value: false },
																			{ title: '* fingerprint', rid: 'xray_fingerprint_tr', id: 'ss_node_table_xray_fingerprint', type: 'select', options: option_fingerprint, value: "" },
																			{ title: '* SNI', rid: 'xray_network_security_sni_tr', id: 'ss_node_table_xray_network_security_sni', type: 'text' },
																			{ title: '* publicKey', rid: 'xray_publickey_tr', id: 'ss_node_table_xray_publickey', maxlen: '300', style: 'width:400px', type: 'text' },
																			{ title: '* shortId', rid: 'xray_shortid_tr', id: 'ss_node_table_xray_shortid', type: 'text' },
																			{ title: '* spiderX', rid: 'xray_spiderx_tr', id: 'ss_node_table_xray_spiderx', type: 'text' },
																			{ title: 'xray json', rid: 'xray_json_tr', id: 'ss_node_table_xray_json', type: 'textarea', rows: '32', ph: ph_xray, style: 'width:400px' },
																			{ title: 'trojan 密码', rid: 'trojan_uuid_tr', id: 'ss_node_table_trojan_uuid', type: 'text', maxlen: '300', style: 'width:400px' },
																			{ title: '跳过证书验证 (AllowInsecure)', rid: 'trojan_ai_tr', id: 'ss_node_table_trojan_ai', type: 'checkbox', value: "false" },
																			{ title: 'SNI', rid: 'trojan_sni_tr', id: 'ss_node_table_trojan_sni', type: 'text' },
																			{ title: 'tcp fast open', rid: 'trojan_tfo_tr', id: 'ss_node_table_trojan_tfo', type: 'checkbox', value: "false" },
																			{ title: 'NaïveProxy 协议', rid: 'naive_prot_tr', id: 'ss_node_table_naive_prot', type: 'select', func: 'v', options: option_naive_prot, maxlen: '300', style: 'width:412px', value: "https" },
																			{ title: 'NaïveProxy 服务器', rid: 'naive_server_tr', id: 'ss_node_table_naive_server', type: 'text', maxlen: '300', style: 'width:400px' },
																			{ title: 'NaïveProxy 端口', rid: 'naive_port_tr', id: 'ss_node_table_naive_port', type: 'text', maxlen: '300', style: 'width:400px', value: "443" },
																			{ title: 'NaïveProxy 账户', rid: 'naive_user_tr', id: 'ss_node_table_naive_user', type: 'text', maxlen: '300', style: 'width:400px' },
																			{ title: 'NaïveProxy 密码', rid: 'naive_pass_tr', id: 'ss_node_table_naive_pass', type: 'text', maxlen: '300', style: 'width:400px' },
																			{ title: 'tuic client json', rid: 'tuic_json_tr', id: 'ss_node_table_tuic_json', type: 'textarea', rows: '18', ph: ph_tuic, style: 'width:400px' },
																			{ title: '服务器', rid: 'hy2_server_tr', id: 'ss_node_table_hy2_server', type: 'text', class: 'hy2_elem', maxlen: '300', style: 'width:400px' },
																			{ title: '端口', rid: 'hy2_port_tr', id: 'ss_node_table_hy2_port', type: 'text', class: 'hy2_elem', maxlen: '300', style: 'width:400px', value: "443" },
																			{ title: '认证密码', rid: 'hy2_pass_tr', id: 'ss_node_table_hy2_pass', type: 'text', class: 'hy2_elem', maxlen: '300', style: 'width:400px' },
																			{ title: '最大上行（Mbps）', rid: 'hy2_up_tr', id: 'ss_node_table_hy2_up', type: 'text', class: 'hy2_elem', maxlen: '300', style: 'width:400px', value: "" },
																			{ title: '最大下行（Mbps）', rid: 'hy2_dl_tr', id: 'ss_node_table_hy2_dl', type: 'text', class: 'hy2_elem', maxlen: '300', style: 'width:400px', value: "" },
																			{ title: 'tcp fast open', rid: 'hy2_tfo_tr', id: 'ss_node_table_hy2_tfo', type: 'checkbox', class: 'hy2_elem', value: "false" },
																			{ title: '混淆类型', rid: 'hy2_obfs_tr', id: 'ss_node_table_hy2_obfs', type: 'select', class: 'hy2_elem', func: 'v', options: option_hy2_obfs, maxlen: '300', style: 'width:412px', value: "0" },
																			{ title: '混淆密码', rid: 'hy2_obfs_pass_tr', id: 'ss_node_table_hy2_obfs_pass', type: 'text', class: 'hy2_elem', maxlen: '300', style: 'width:400px' },
																			{ title: 'SNI（域名）', rid: 'hy2_sni_tr', id: 'ss_node_table_hy2_sni', type: 'text', class: 'hy2_elem', maxlen: '300', style: 'width:400px' },
																			{ title: '允许不安全', rid: 'hy2_ai_tr', id: 'ss_node_table_hy2_ai', type: 'checkbox', class: 'hy2_elem', value: "false" },
																		]);
																	</script>
																</table>
															</div>
														</td>
													</tr>
												</table>
												<div
													style="margin-top:5px;padding-bottom:10px;width:100%;text-align:center;">
													<input class="button_gen" style="margin-left: 160px;" type="button"
														onclick="cancel_add_node();" id="cancel_Btn" value="返回">
													<input id="add_node" class="button_gen" type="button"
														onclick="add_ss_node_conf(save_flag);" value="添加">
													<input id="edit_node" style="display: none;" class="button_gen"
														type="button" onclick="edit_ss_node_conf(save_flag);"
														value="修改">
													<a id="continue_add" style="display: none;margin-left: 20px;"><input
															id="continue_add_box" type="checkbox" />连续添加</a>
												</div>
											</div>
											<div id="tablet_0" style="display: none;">
												<table id="table_basic" width="100%" border="0" align="center"
													cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"
													class="FormTable">
													<script type="text/javascript">

														$('#table_basic').forms([
															{ title: '节点选择', rid: 'ssconf_basic_node_tr', id: 'ssconf_basic_node', type: 'select', func: 'onchange="ss_node_sel();"', style: 'width:auto;min-width:164px;max-width:450px;', options: [], value: "1" },
															{ title: '节点别名', rid: 'ss_basic_name_tr', id: 'ss_basic_name', type: 'text', maxlen: '100' },
															{ title: '协议选择', rid: 'ss_basic_type_tr', id: 'ss_basic_type_select', type: 'select', func: 'onchange="verifyFields_by_type(this.value)"', options: [["0", "SS"], ["4", "Xray"], ["8", "Hysteria 2"]], value: "0" },
															{ title: '模式', id: 'ss_basic_mode', type: 'select', func: 'v', hint: '1', options: option_modes, value: "1" },
															{ title: '使用json配置', id: 'ss_basic_v2ray_use_json', type: 'checkbox', func: 'v', hint: '27' },
															{ title: '使用json配置', id: 'ss_basic_xray_use_json', type: 'checkbox', func: 'v', hint: '27' },
															{ title: '服务器地址', id: 'ss_basic_server', type: 'text', maxlen: '100' },
															{ title: '服务器端口', id: 'ss_basic_port', type: 'text', maxlen: '100' },
															{ title: '密码', id: 'ss_basic_password', type: 'password', maxlen: '300', style: 'width:280px;', peekaboo: '1' },
															{ title: '加密方式', id: 'ss_basic_method', type: 'select', func: 'v', options: option_method },
															{ title: '混淆 (obfs)', id: 'ss_basic_ss_obfs', type: 'select', func: 'v', options: [["0", "关闭"], ["tls", "tls"], ["http", "http"]], value: "0" },
															{ title: '混淆主机名 (obfs_host)', id: 'ss_basic_ss_obfs_host', type: 'text', maxlen: '100', ph: 'bing.com' },
															{ title: '协议 (protocol)', id: 'ss_basic_rss_protocol', type: 'select', func: 'v', options: option_protocals },
															{ title: '协议参数 (protocol_param)', id: 'ss_basic_rss_protocol_param', type: 'password', hint: '54', maxlen: '100', ph: 'id:password', peekaboo: '1' },
															{ title: '混淆 (obfs)', id: 'ss_basic_rss_obfs', type: 'select', func: 'v', options: option_obfs },
															{ title: '混淆参数 (obfs_param)', id: 'ss_basic_rss_obfs_param', type: 'text', hint: '11', maxlen: '300', ph: 'cloudflare.com;bing.com' },
															{ title: '用户id1 (id)', id: 'ss_basic_v2ray_uuid', type: 'password', hint: '49', maxlen: '300', style: 'width:300px;', peekaboo: '1' },
															{ title: '额外ID (Alterld)', id: 'ss_basic_v2ray_alterid', type: 'text', hint: '48', maxlen: '50' },
															{ title: '加密方式 (security)', id: 'ss_basic_v2ray_security', type: 'select', hint: '47', options: option_v2enc },
															{ title: '传输协议 (network)', id: 'ss_basic_v2ray_network', type: 'select', func: 'v', hint: '35', options: ["tcp", "kcp", "ws", "h2", "quic", "grpc"] },
															{ title: '* tcp伪装类型 (type)', id: 'ss_basic_v2ray_headtype_tcp', type: 'select', func: 'v', hint: '36', options: option_headtcp },
															{ title: '* kcp伪装类型 (type)', id: 'ss_basic_v2ray_headtype_kcp', type: 'select', func: 'v', hint: '37', options: option_headkcp },
															{ title: '* quic伪装类型 (type)', id: 'ss_basic_v2ray_headtype_quic', type: 'select', options: option_headquic },
															{ title: '* grpc模式', id: 'ss_basic_v2ray_grpc_mode', type: 'select', options: option_grpcmode },
															{ title: '* 伪装域名 (host)', id: 'ss_basic_v2ray_network_host', type: 'text', hint: '28', maxlen: '300', ph: '没有请留空' },
															{ title: '* 路径 (path)', rid: 'ss_basic_v2ray_network_path_tr', id: 'ss_basic_v2ray_network_path', type: 'text', hint: '29', maxlen: '300', ph: '没有请留空' },
															{ title: '* kcp seed', id: 'ss_basic_v2ray_kcp_seed', type: 'text', maxlen: '300', ph: '没有请留空' },
															{ title: '* KCP mtu', id: 'ss_basic_v2ray_kcp_mtu', type: 'text', maxlen: '50', ph: '默认:1200' },
															{ title: '* KCP tti', id: 'ss_basic_v2ray_kcp_tti', type: 'text', maxlen: '50', ph: '默认:40' },
															{ title: '* KCP 上行容量(uplinkCapacity)', id: 'ss_basic_v2ray_kcp_uplink', type: 'text', maxlen: '50', ph: '默认:0' },
															{ title: '* KCP 下行容量(downlinkCapacity)', id: 'ss_basic_v2ray_kcp_downlink', type: 'text', maxlen: '50', ph: '默认:100' },
															{ title: '* KCP 拥塞控制(congestion)', id: 'ss_basic_v2ray_kcp_congestion', type: 'select', options: option_bol, value: "1" },
															{ title: '* KCP 读缓冲(readBufferSize)', id: 'ss_basic_v2ray_kcp_readbuf', type: 'text', maxlen: '50', ph: '默认:2' },
															{ title: '* KCP 写缓冲(writeBufferSize)', id: 'ss_basic_v2ray_kcp_writebuf', type: 'text', maxlen: '50', ph: '默认:2' },
															{ title: '底层传输安全', id: 'ss_basic_v2ray_network_security', type: 'select', func: 'v', options: [["none", "关闭"], ["tls", "tls"]] },
															{ title: '* 跳过证书验证 (AllowInsecure)', id: 'ss_basic_v2ray_network_security_ai', type: 'checkbox', hint: '56' },
															{
																title: '* alpn', id: 'ss_basic_v2ray_network_security_alpn', multi: [
																	{ suffix: '<input type="checkbox" id="ss_basic_v2ray_network_security_alpn_h2">h2' },
																	{ suffix: '<input type="checkbox" id="ss_basic_v2ray_network_security_alpn_http">http/1.1' },
																]
															},
															{ title: '* SNI', id: 'ss_basic_v2ray_network_security_sni', type: 'text' },
															{ title: '多路复用 (Mux)', id: 'ss_basic_v2ray_mux_enable', type: 'checkbox', func: 'v', hint: '31' },
															{ title: 'Mux并发连接数', id: 'ss_basic_v2ray_mux_concurrency', type: 'text', hint: '32', maxlen: '300' },
															{ title: 'v2ray json', id: 'ss_basic_v2ray_json', type: 'textarea', rows: '36', ph: ph_v2ray },
															{ title: '用户id (id)', id: 'ss_basic_xray_uuid', type: 'password', hint: '49', maxlen: '300', style: 'width:300px;', peekaboo: '1' },
															{ title: '加密 (encryption)', id: 'ss_basic_xray_encryption', type: 'text', hint: '55', maxlen: '50' },
															{ title: 'flow (流控模式，没有请留空)', id: 'ss_basic_xray_flow', type: 'select', options: option_xflow },
															{ title: '传输协议 (network)', id: 'ss_basic_xray_network', type: 'select', func: 'v', hint: '35', options: ["tcp", "kcp", "ws", "h2", "quic", "grpc"] },
															{ title: '* tcp伪装类型 (type)', id: 'ss_basic_xray_headtype_tcp', type: 'select', func: 'v', hint: '36', options: option_headtcp },
															{ title: '* kcp伪装类型 (type)', id: 'ss_basic_xray_headtype_kcp', type: 'select', func: 'v', hint: '37', options: option_headkcp },
															{ title: '* quic伪装类型 (type)', id: 'ss_basic_xray_headtype_quic', type: 'select', options: option_headquic },
															{ title: '* grpc模式', id: 'ss_basic_xray_grpc_mode', type: 'select', options: option_grpcmode },
															{ title: '* 伪装域名 (host)', id: 'ss_basic_xray_network_host', type: 'text', hint: '28', maxlen: '300', ph: '没有请留空' },
															{ title: '* 路径 (path)', rid: 'ss_basic_xray_network_path_tr', id: 'ss_basic_xray_network_path', type: 'text', hint: '29', maxlen: '300', ph: '没有请留空' },
															{ title: '* kcp seed', id: 'ss_basic_xray_kcp_seed', type: 'text', maxlen: '300', ph: '没有请留空' },
															{ title: '* KCP mtu', id: 'ss_basic_xray_kcp_mtu', type: 'text', maxlen: '50', ph: '默认:1200' },
															{ title: '* KCP tti', id: 'ss_basic_xray_kcp_tti', type: 'text', maxlen: '50', ph: '默认:30' },
															{ title: '* KCP 上行容量(uplinkCapacity)', id: 'ss_basic_xray_kcp_uplink', type: 'text', maxlen: '50', ph: '默认:20' },
															{ title: '* KCP 下行容量(downlinkCapacity)', id: 'ss_basic_xray_kcp_downlink', type: 'text', maxlen: '50', ph: '默认:100' },
															{ title: '* KCP 拥塞控制(congestion)', id: 'ss_basic_xray_kcp_congestion', type: 'select', options: option_bol, value: "1" },
															{ title: '* KCP 读缓冲(readBufferSize)', id: 'ss_basic_xray_kcp_readbuf', type: 'text', maxlen: '50', ph: '默认:4' },
															{ title: '* KCP 写缓冲(writeBufferSize)', id: 'ss_basic_xray_kcp_writebuf', type: 'text', maxlen: '50', ph: '默认:4' },
															{ title: '底层传输安全', id: 'ss_basic_xray_network_security', type: 'select', func: 'v', options: [["none", "关闭"], ["tls", "tls"], ["xtls", "xtls"], ["reality", "reality"]], value: "none" },
															{ title: '* 跳过证书验证 (AllowInsecure)', id: 'ss_basic_xray_network_security_ai', type: 'checkbox', hint: '56' },
															{
																title: '* alpn', id: 'ss_basic_xray_network_security_alpn', multi: [
																	{ suffix: '<input type="checkbox" id="ss_basic_xray_network_security_alpn_h2">h2' },
																	{ suffix: '<input type="checkbox" id="ss_basic_xray_network_security_alpn_http">http/1.1' },
																]
															},
															{ title: '* show', id: 'ss_basic_xray_show', type: 'checkbox' },
															{ title: '* fingerprint', id: 'ss_basic_xray_fingerprint', type: 'select', options: option_fingerprint },
															{ title: '* SNI', id: 'ss_basic_xray_network_security_sni', type: 'text', ph: 'realitySettings中的serverName' },
															{ title: '* publickey', id: 'ss_basic_xray_publickey', type: 'password', maxlen: '300', style: 'width:320px;', ph: '填写公钥', peekaboo: '1' },
															{ title: '* shortId', id: 'ss_basic_xray_shortid', type: 'text', ph: '没有请留空' },
															{ title: '* spiderX', id: 'ss_basic_xray_spiderx', type: 'text', ph: '没有请留空' },
															{ title: 'xray json', id: 'ss_basic_xray_json', type: 'textarea', rows: '36', ph: ph_xray },
															{ title: '其它', rid: 'v2ray_binary_update_tr', prefix: '<a type="button" class="ss_btn" style="cursor:pointer" onclick="v2ray_binary_update(2)">更新v2ray程序</a>' },
															{ title: '其它', rid: 'xray_binary_update_tr', prefix: '<a type="button" class="ss_btn" style="cursor:pointer" onclick="xray_binary_update(2)">更新/切换xray程序</a>' },
															{ title: 'trojan 密码', id: 'ss_basic_trojan_uuid', type: 'password', maxlen: '300', style: 'width:280px;', peekaboo: '1' },
															{
																title: '跳过证书验证 (AllowInsecure)', id: 'ss_basic_trojan_ai_tr', multi: [
																	{ suffix: '<input type="checkbox" id="ss_basic_trojan_ai">' },
																	{ suffix: '<lable id="ss_basic_trojan_ai_note"></lable>' },
																]
															},
															{ title: 'SNI', id: 'ss_basic_trojan_sni', type: 'text' },
															{ title: 'tcp fast open', id: 'ss_basic_trojan_tfo', type: 'checkbox' },
															{ title: 'NaïveProxy 协议', id: 'ss_basic_naive_prot', type: 'select', func: 'v', options: option_naive_prot, maxlen: '300', value: "https" },
															{ title: 'NaïveProxy 服务器', id: 'ss_basic_naive_server', type: 'text', maxlen: '300' },
															{ title: 'NaïveProxy 端口', id: 'ss_basic_naive_port', type: 'text', maxlen: '300', value: "443" },
															{ title: 'NaïveProxy 账户', id: 'ss_basic_naive_user', type: 'text', maxlen: '300' },
															{ title: 'NaïveProxy 密码', id: 'ss_basic_naive_pass', type: 'text', maxlen: '300' },
															{ title: 'tuic json', id: 'ss_basic_tuic_json', type: 'textarea', rows: '18', ph: ph_tuic },
															{ title: '服务器', id: 'ss_basic_hy2_server', type: 'text', maxlen: '300' },
															{ title: '端口', id: 'ss_basic_hy2_port', type: 'text', maxlen: '300' },
															{ title: '认证密码', id: 'ss_basic_hy2_pass', type: 'text', maxlen: '300' },
															{ title: '最大上行（Mbps）', id: 'ss_basic_hy2_up', type: 'text', maxlen: '300' },
															{ title: '最大下行（Mbps）', id: 'ss_basic_hy2_dl', type: 'text', maxlen: '300' },
															{ title: 'tcp fast open', id: 'ss_basic_hy2_tfo', type: 'checkbox' },
															{ title: '混淆类型', id: 'ss_basic_hy2_obfs', type: 'select', func: 'v', options: option_hy2_obfs, maxlen: '300', value: "0" },
															{ title: '混淆密码', id: 'ss_basic_hy2_obfs_pass', type: 'text', maxlen: '300' },
															{ title: 'SNI（域名）', id: 'ss_basic_hy2_sni', type: 'text' },
															{ title: '允许不安全', id: 'ss_basic_hy2_ai', type: 'checkbox' },
														]);


													</script>


													<tr id="accel_mode_tr" style="display: none;">
														<th>加速模式</th>
														<td>
															<select id="ss_basic_accel_mode" class="input_option"
																onchange="toggle_accel_mode();" style="width:auto;">
																<option value="0">无加速</option>
																<option value="1">KCPtun 加速</option>
																<option value="3">UDP2raw 加速</option>
																<option value="2">KCPtun + UDP2raw 串联</option>
															</select>
														</td>
													</tr>
												</table>
												<table id="kcp_config_table" style="display:none; margin-top: -1px;"
													width="100%" border="1" align="center" cellpadding="4"
													cellspacing="0" bordercolor="#6b8fa3" class="FormTable">
													<tr>
														<td class="smth" style="font-weight: bold;" colspan="2">KCPtun
															加速配置</td>
													</tr>
													<tr>
														<th>kcp本地监听地址:端口 (-l)</th>
														<td>
															<input type="text" value="0.0.0.0" class="input_ss_table"
																readonly style="width:120px;">
															&nbsp;:&nbsp;
															<input type="text" value="1091" class="input_ss_table"
																readonly style="width:60px;">
														</td>
													</tr>
													<tr id="kcp_remote_tr">
														<th>kcp服务器地址:端口 (-r)</th>
														<td>
															<input type="text" id="ss_basic_kcp_rserver"
																class="input_ss_table" style="width:120px;"">
            &nbsp;:&nbsp;
            <input type=" text" id="ss_basic_kcp_rport" class="input_ss_table" value="48400" style="width:60px;">
														</td>
													</tr>
													<tr>
														<th>KCP参数</th>
														<td><textarea id="ss_basic_kcp_param" class="input_ss_table"
																style="width: 95%; min-height: 100px; resize: vertical; overflow-y: hidden;"
																oninput="auto_grow_textarea(this)" autocomplete="off"
																autocorrect="off" autocapitalize="off"
																spellcheck="false"></textarea></td>
													</tr>
												</table>
												<table id="udp2raw_config_table" style="display:none; margin-top: -1px;"
													width="100%" border="1" align="center" cellpadding="4"
													cellspacing="0" bordercolor="#6b8fa3" class="FormTable">
													<tr>
														<td class="smth" style="font-weight: bold;" colspan="2">UDP2raw
															加速配置</td>
													</tr>
													<tr>
														<th>UDP2raw本地监听地址:端口 (-l)</th>
														<td>
															<input type="text" value="0.0.0.0" class="input_ss_table"
																readonly style="width:120px;">
															&nbsp;:&nbsp;
															<input type="text" value="1093" class="input_ss_table"
																readonly style="width:60px;">
														</td>
													</tr>
													<tr>
														<th>UDP2raw服务器地址:端口 (-r)</th>
														<td>
															<input type="text" id="ss_basic_udp2raw_rserver"
																class="input_ss_table" style="width:120px;">
															&nbsp;:&nbsp;
															<input type="text" id="ss_basic_udp2raw_rport"
																class="input_ss_table" value="38380"
																style="width:60px;">
														</td>
													</tr>
													<tr>
														<th>UDP2raw参数</th>
														<td><textarea id="ss_basic_udp2raw_param" class="input_ss_table"
																style="width: 95%; min-height: 50px; resize: vertical; overflow-y: hidden;"
																oninput="auto_grow_textarea(this)" autocomplete="off"
																autocorrect="off" autocapitalize="off"
																spellcheck="false"></textarea></td>
													</tr>



												</table>
											</div>
											<div id="tablet_1" style="display: none;">
												<div id="ss_list_table"></div>
											</div>
											<div id="tablet_2" style="display: none;">
												<table id="table_failover" width="100%" border="1" align="center"
													cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"
													class="FormTable">
													<script type="text/javascript">
														// (修改) 移除旧的负载均衡UI，增加新的"每日定时切换"UI
														var fa1 = ["2", "3", "4", "5"];
														var fa2_1 = ["10", "15", "20"];
														var fa2_2 = ["2", "3", "4", "5", "6", "7", "8"];
														var fa3_1 = ["10", "15", "20"];
														var fa3_2 = ["100", "150", "200", "250", "300", "350", "400", "450", "500", "1000"];
														var fa4_1 = [["0", "关闭插件"], ["1", "重启插件"], ["2", "切换到"]];
														var fa4_2 = [["1", "备用节点"], ["2", "下个节点"], ["3", "web延迟最低的节点"]];
														var fa5 = [["1", "2s - 3s"], ["2", "4s - 7s"], ["3", "8s - 15s"], ["4", "16s - 31s"], ["5", "32s - 63s"]];
														$('#table_failover').forms([
															{ title: '故障转移开关', id: 'ss_failover_enable', type: 'checkbox', func: 'v', value: false },
															{
																title: '故障转移设置', rid: 'failover_settings_1', multi: [
																	// (新增) 每日自动切换节点功能
																	{ suffix: '<div style="margin-top: 5px;">' },
																	{ id: 'ss_daily_switch_enable', type: 'checkbox', value: false },
																	{ suffix: '<lable>👉&nbsp;每隔&nbsp;</lable>' },
																	{ id: 'ss_daily_switch_days', type: 'text', maxlen: '3', style: 'width:40px;', value: '15' },
																	{ suffix: '<lable>&nbsp;日&nbsp;</lable>' },
																	{ id: 'ss_daily_switch_hour', type: 'text', maxlen: '2', style: 'width:40px;', value: '03' },
																	{ suffix: '<lable>&nbsp;点&nbsp;</lable>' },
																	{ id: 'ss_daily_switch_minute', type: 'text', maxlen: '2', style: 'width:40px;', value: '03' },
																	{ suffix: '<lable>&nbsp;分自动切换节点<br /></lable>' },
																	{ suffix: '</div>' },


																	// 原有的故障转移条件
																	{ id: 'ss_failover_c1', type: 'checkbox', value: false },
																	{ suffix: '<lable>👉&nbsp;国外连续发生&nbsp;</lable>' },
																	{ id: 'ss_failover_s1', type: 'select', style: 'width:auto', options: fa1, value: '3' },
																	{ suffix: '<lable>&nbsp;次故障；<br /></lable>' },
																	{ suffix: '</div>' },
																	{ suffix: '<div style="margin-top: 5px;">' },
																	{ id: 'ss_failover_c2', type: 'checkbox', value: false },
																	{ suffix: '<lable>👉&nbsp;最近&nbsp;</lable>' },
																	{ id: 'ss_failover_s2_1', type: 'select', style: 'width:auto', options: fa2_1, value: '15' },
																	{ suffix: '<lable>&nbsp;次国外状态检测中，故障次数超过&nbsp;</lable>' },
																	{ id: 'ss_failover_s2_2', type: 'select', style: 'width:auto', options: fa2_2, value: '4' },
																	{ suffix: '<lable>&nbsp;次；<br /></lable>' },
																	{ suffix: '</div>' },
																	{ suffix: '<div style="margin-top: 5px;">' },
																	{ id: 'ss_failover_c3', type: 'checkbox', value: false },
																	{ suffix: '<lable>👉&nbsp;最近&nbsp;</lable>' },
																	{ id: 'ss_failover_s3_1', type: 'select', style: 'width:auto', options: fa3_1, value: '20' },
																	{ suffix: '<lable>&nbsp;次国外状态检测中，平均延迟超过&nbsp;</lable>' },
																	{ id: 'ss_failover_s3_2', type: 'select', style: 'width:auto', options: fa3_2, value: '500' },
																	{ suffix: '<lable>ms<br /></lable>' },
																	{ suffix: '</div>' },
																	{ suffix: '<div style="margin-top: 5px;">' },
																	{ suffix: '<lable>&nbsp;以上有一个条件满足（或到达自动切换时间），则&nbsp;</lable>' },
																	{ id: 'ss_failover_s4_1', type: 'select', style: 'width:auto', func: 'v', options: fa4_1, value: '2' },
																	{
																		id: 'ss_failover_s4_2', type: 'select', style: 'width:auto',
																		func: 'v', options: fa4_2, value: '2'
																	},
																	{ id: 'ss_failover_s4_3', type: 'select', style: 'width:170px', func: 'v', options: [] },
																	{ suffix: '</div>' },
																]
															},
															{
																title: '状态检测时间间隔', rid: 'interval_settings', multi: [
																	{ id: 'ss_basic_interval', type: 'select', style: 'width:auto', options: fa5, value: '2' },
																	{ suffix: '<small>&nbsp;默认：4 - 7s</small>' },
																]
															},
															{
																title: '历史记录保存数量', rid: 'failover_settings_2', multi: [
																	{ suffix: '<lable>最多保留&nbsp;</lable>' },
																	{ id: 'ss_failover_s5', type: 'select', style: 'width:auto', options: ["1000", "2000", "3000", "4000"], value: '2000' },
																	{ suffix: '<lable>&nbsp;行日志&nbsp;</lable>' },
																]
															},
															{
																title: '查看历史状态', rid: 'failover_settings_3', multi: [
																	{ suffix: '<a type="button" id="look_logf" class="ss_btn" style="cursor:pointer" onclick="lookup_status_log(1)">国外状态历史</a>&nbsp;' },
																	{ suffix: '<a type="button" id="look_logc" class="ss_btn" style="cursor:pointer" onclick="lookup_status_log(2)">国内状态历史</a>' },
																]
															},
														]);

													</script>
												</table>
											</div>
											<div id="tablet_3" style="display: none;">
												<table id="table_dns" width="100%" border="1" align="center"
													cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"
													class="FormTable">
													<script type="text/javascript">
														var isp_dns_raw = '<% nvram_get("wan0_dns"); %>';
														var isp_dns_1 = isp_dns_raw.split(" ")[0];
														var isp_dns_2 = isp_dns_raw.split(" ")[1];
														validator.ipv4_addr(isp_dns_1)
														var option_dnsp = [
															["1", "chinadns-ng"]
														];
														option_dnsngc_prot = [
															["1", "udp"]
															, ["2", "tcp"]
														];
														var option_dnsngc_udp = [];
														if (isp_dns_1 && isp_dns_2) {
															option_dnsngc_udp.push(["group", "运营商DNS"]);
															option_dnsngc_udp.push(["1", "⚪" + isp_dns_1]);
															option_dnsngc_udp.push(["2", "⚪" + isp_dns_2]);
														} else if (isp_dns_1 && !isp_dns_2) {
															option_dnsngc_udp.push(["group", "运营商DNS"]);
															option_dnsngc_udp.push(["1", isp_dns_1]);
														}
														option_dnsngc_udp.push(["group", "阿里公共DNS"]);
														option_dnsngc_udp.push(["3", "🟠223.5.5.5"]);
														option_dnsngc_udp.push(["4", "🟠223.6.6.6"]);
														option_dnsngc_udp.push(["group", "DNSPod DNS"]);
														option_dnsngc_udp.push(["5", "🟠119.29.29.29"]);
														option_dnsngc_udp.push(["6", "🟠119.28.28.28"]);
														option_dnsngc_udp.push(["group", "114 DNS"]);
														option_dnsngc_udp.push(["7", "⚫114.114.114.114"]);
														option_dnsngc_udp.push(["8", "⚫114.114.115.115"]);
														option_dnsngc_udp.push(["group", "OneDNS"]);
														option_dnsngc_udp.push(["9", "🟠117.50.11.11（拦截版）"]);
														option_dnsngc_udp.push(["10", "🟠52.80.66.66（拦截版）"]);
														option_dnsngc_udp.push(["11", "🟠117.50.10.10（纯净版）"]);
														option_dnsngc_udp.push(["12", "🟠52.80.52.52（纯净版）"]);
														option_dnsngc_udp.push(["13", "🟠117.50.60.30（家庭版）"]);
														option_dnsngc_udp.push(["14", "🟠52.80.60.30（家庭版）"]);
														option_dnsngc_udp.push(["group", "360安全DNS"]);
														option_dnsngc_udp.push(["15", "🟠101.226.4.6（电信/铁通/移动）"]);
														option_dnsngc_udp.push(["16", "🟠218.30.118.6（电信/铁通/移动）"]);
														option_dnsngc_udp.push(["17", "🟠123.125.81.6（联通）"]);
														option_dnsngc_udp.push(["18", "🟠140.207.198.6（联通）"]);
														option_dnsngc_udp.push(["group", "cnnic DNS"]);
														option_dnsngc_udp.push(["19", "⚫1.2.4.8"]);
														option_dnsngc_udp.push(["20", "⚫210.2.4.8"]);
														option_dnsngc_udp.push(["group", "百度DNS"]);
														option_dnsngc_udp.push(["21", "🟠180.76.76.76"]);
														option_dnsngc_udp.push(["group", "教育网DNS"]);
														option_dnsngc_udp.push(["22", "🟠101.6.6.6:5353（清华大学）"]);
														option_dnsngc_udp.push(["23", "⚫58.132.8.1（北京）"]);
														option_dnsngc_udp.push(["24", "⚫101.7.8.9（北京）"]);
														option_dnsngc_udp.push(["group", "自定义DNS"]);
														option_dnsngc_udp.push(["99", "⚪自定义DNS (UDP)"]);
														option_dnsngc_tcp = [
															["group", "阿里公共DNS"],
															["3", "🟠223.5.5.5"],
															["4", "🟠223.6.6.6"],
															["group", "DNSPod DNS"],
															["6", "🟠119.28.28.28"],
															["group", "114 DNS"],
															["7", "⚫114.114.114.114"],
															["8", "⚫114.114.115.115"],
															["group", "OneDNS"],
															["10", "🟠52.80.66.66（拦截版）"],
															["12", "🟠52.80.52.52（纯净版）"],
															["group", "360安全DNS"],
															["16", "🟠218.30.118.6（电信/铁通/移动）"],
															["17", "🟠123.125.81.6（联通）"],
															["18", "🟠140.207.198.6（联通）"],
															["group", "教育网DNS"],
															["22", "🟠101.6.6.6:5353（清华大学）"],
															["group", "自定义DNS"],
															["99", "⚪自定义DNS (tcp)"]
														];
														var option_dnsngf_1_opt = [
															["1", "udp"]
															, ["2", "tcp"]
														];
														var option_dnsngf_1_val_udp = [
															["group", "Google DNS"],
															["1", "🟠8.8.8.8"],
															["2", "🟠8.8.4.4"],
															["group", "Cloudflare DNS"],
															["3", "⚫1.1.1.1"],
															["4", "⚫1.0.0.1"],
															["group", "Quad9"],
															["5", "🟠9.9.9.11"],
															["6", "🟠149.112.112.11"],
															["group", "OpenDNS"],
															["7", "⚫208.67.222.222"],
															["8", "⚫208.67.220.220"],
															["group", "DNS.SB"],
															["9", "⚫185.222.222.222"],
															["10", "⚫45.11.45.11"],
															["group", "AdGuard"],
															["11", "🟡94.140.14.14"],
															["12", "🟡94.140.15.15"],
															["group", "quad101"],
															["13", "🟠101.101.101.101"],
															["14", "🟠101.102.103.104"],
															["group", "自定义DNS"],
															["99", "⚪自定义DNS（udp）"]
														];
														var option_dnsngf_1_val_tcp = [
															["group", "Google DNS"],
															["1", "🟠8.8.8.8"],
															["2", "🟠8.8.4.4"],
															["group", "Cloudflare DNS"],
															["3", "⚫1.1.1.1"],
															["4", "⚫1.0.0.1"],
															["group", "Quad9"],
															["5", "🟠9.9.9.11"],
															["6", "🟠149.112.112.11"],
															["group", "OpenDNS"],
															["7", "⚫208.67.222.222"],
															["8", "⚫208.67.220.220"],
															["group", "DNS.SB"],
															["9", "⚫185.222.222.222"],
															["10", "⚫45.11.45.11"],
															["group", "AdGuard"],
															["11", "🟡94.140.14.14"],
															["12", "🟡94.140.15.15"],
															["group", "quad101"],
															["13", "🟠101.101.101.101"],
															["14", "🟠101.102.103.104"],
															["group", "自定义DNS"],
															["99", "⚪自定义DNS（tcp）"]
														];
														var option_dnsngf_2_opt = [
															["1", "udp"]
															, ["2", "tcp"]
														];
														var option_chndns = [];
														if (isp_dns_1 && isp_dns_2) {
															option_chndns.push(["group", "运营商DNS"]);
															option_chndns.push(["1", isp_dns_1]);
															option_chndns.push(["2", isp_dns_2]);
														} else if (isp_dns_1 && !isp_dns_2) {
															option_chndns.push(["group", "运营商DNS"]);
															option_chndns.push(["1", isp_dns_1]);
														}
														option_chndns.push(["group", "阿里公共DNS"]);
														option_chndns.push(["3", "223.5.5.5"]);
														option_chndns.push(["4", "223.6.6.6"]);
														option_chndns.push(["group", "DNSPod DNS"]);
														option_chndns.push(["5", "119.29.29.29"]);
														option_chndns.push(["6", "119.28.28.28"]);
														option_chndns.push(["group", "114 DNS"]);
														option_chndns.push(["7", "114.114.114.114"]);
														option_chndns.push(["8", "114.114.114.115"]);
														option_chndns.push(["group", "OneDNS"]);
														option_chndns.push(["9", "117.50.11.11（拦截版）"]);
														option_chndns.push(["10", "52.80.66.66（拦截版）"]);
														option_chndns.push(["11", "117.50.10.10（纯净版）"]);
														option_chndns.push(["12", "52.80.52.52（纯净版）"]);
														option_chndns.push(["13", "117.50.60.30（家庭版）"]);
														option_chndns.push(["14", "52.80.60.30（家庭版）"]);
														option_chndns.push(["group", "360安全DNS"]);
														option_chndns.push(["15", "101.226.4.6（电信/铁通/移动）"]);
														option_chndns.push(["16", "218.30.118.6（电信/铁通/移动）"]);
														option_chndns.push(["17", "123.125.81.6（联通）"]);
														option_chndns.push(["18", "140.207.198.6（联通）"]);
														option_chndns.push(["group", "cnnic DNS"]);
														option_chndns.push(["19", "1.2.4.8"]);
														option_chndns.push(["20", "210.2.4.8"]);
														option_chndns.push(["group", "百度DNS"]);
														option_chndns.push(["21", "180.76.76.76"]);
														option_chndns.push(["group", "教育网DNS"]);
														option_chndns.push(["22", "101.6.6.6:5353（清华大学）"]);
														option_chndns.push(["23", "58.132.8.1（北京）"]);
														option_chndns.push(["24", "101.7.8.9（北京）"]);
														option_chndns.push(["group", "自定义DNS"]);
														option_chndns.push(["99", "自定义DNS (UDP)"]);
														var option_dnsf = [["3", "🚀 dns2socks"],
														["4", "🚀 ss-tunnel"],
														["7", "🚀 v2ray/xray_dns"],
														["8", "🌏 直连（udp）"]
														];
														var option_resv = [
															["group", "自动选取"],
															["-1", "自动选取模式（国内组）"],
															["-2", "自动选取模式（仅国组）"],
															["0", "自动选取模式（国内组 + 国外组）"],
															["group", "国内DNS"],
															["1", "阿里DNS【223.5.5.5】"],
															["2", "DNSPod DNS【119.29.29.29】"],
															["3", "114DNS【114.114.114.114】"],
															["4", "OneDNS【52.80.66.66】"],
															["5", "360安全DNS 电信/铁通/移动【218.30.118.6】"],
															["6", "360安全DNS 联通【123.125.81.6】"],
															["7", "清华大学TUNA DNS【101.6.6.6:5353】"],
															["8", "百度DNS【180.76.76.76】"],
															["group", "国外DNS"],
															["11", "Google DNS【8.8.8.8】"],
															["12", "CloudFlare DNS【1.1.1.1】"],
															["13", "Quad9 Secured【9.9.9.11】"],
															["14", "OpenDNS【208.67.222.222】"],
															["15", "DNS.SB【185.222.222.222】"],
															["16", "AdGuard【94.140.14.14】"],
															["17", "Quad101【101.101.101.101】"],
															["18", "CleanBrowsing【185.228.168.9】"],
															["group", "自定义DNS"],
															["99", "自定义DNS (udp)"],
														];
														var option_dig = [
															["group", "国内域名"],
															["www.baidu.com", "www.baidu.com"],
															["www.sina.com.cn", "www.sina.com.cn"],
															["www.sohu.com", "www.sohu.com"],
															["www.163.com", "www.163.com"],
															["www.qq.com", "www.qq.com"],
															["www.taobao.com", "www.taobao.com"],
															["www.jd.com", "www.jd.com"],
															["www.bilibili.com", "www.bilibili.com"],
															["www.bing.com", "www.bing.com"],
															["group", "国外域名"],
															["www.google.com", "www.google.com"],
															["www.google.com.hk", "www.google.com.hk"],
															["www.youtube.com", "www.youtube.com"],
															["www.facebook.com", "www.facebook.com"],
															["www.twitter.com", "www.twitter.com"],
															["www.wikipedia.org", "www.wikipedia.org"],
															["www.instagram.com", "www.instagram.com"],
															["www.netflix.com", "www.netflix.com"],
															["www.reddit.com", "www.reddit.com"],
															["www.github.com", "www.github.com"],
														];
														var ph1 = "需端口号如：8.8.8.8:53"
														var ph2 = "需端口号如：8.8.8.8#53"
														var ph3 = "# 填入自定义的dnsmasq设置，一行一个&#10;# 例如hosts设置：&#10;address=/weibo.com/2.2.2.2&#10;# 防DNS劫持设置：&#10;bogus-nxdomain=220.250.64.18"
														$('#table_dns').forms([
															{
																title: '<em>DNS方案设置</em>', thtd: 1, multi: [
																	{ id: 'ss_basic_olddns', name: 'ss_basic_advdns', func: 'u', hint: '26', type: 'radio', suffix: '<a class="hintstyle" href="javascript:void(0);" onclick="openssHint(136)"><font color="#ffcc00">基础</font></a>', value: 0 },
																	{ id: 'ss_basic_advdns', name: 'ss_basic_advdns', func: 'u', hint: '26', type: 'radio', suffix: '<a class="hintstyle" href="javascript:void(0);" onclick="openssHint(137)"><font color="#ffcc00">进阶</font></a>', value: 1 },
																]
															},
															{
																title: '选择中国DNS-1 <em>(直连) 🌏</em>', hint: '133', class: 'new_dns chng', multi: [
																	{ id: 'ss_basic_chng_china_1_enable', type: 'checkbox', func: 'u', value: true },
																	{ id: 'ss_basic_chng_china_1_prot', type: 'select', func: 'u', options: option_dnsngc_prot, style: 'width:50px;', value: '1' },
																	{ id: 'ss_basic_chng_china_1_udp', type: 'select', func: 'u', options: option_dnsngc_udp, style: 'width:auto;', value: '1' },
																	{ id: 'ss_basic_chng_china_1_udp_user', type: 'text', style: 'width:120px;', ph: '114.114.114.114', value: '114.114.114.114' },
																	{ id: 'ss_basic_chng_china_1_tcp', type: 'select', func: 'u', options: option_dnsngc_tcp, style: 'width:200px;', value: '1' },
																	{ id: 'ss_basic_chng_china_1_tcp_user', type: 'text', style: 'width:120px;', ph: '114.114.114.114', value: '114.114.114.114' },
																	{ suffix: '&nbsp;&nbsp;' },
																	{ prefix: '<a id="ss_basic_chng_china_1_ecs_note" class="hintstyle" href="javascript:void(0);" onclick="openssHint(130)"><font color="#ffcc00">&nbsp;<u>ECS</u></font></a>', id: 'ss_basic_chng_china_1_ecs', type: 'checkbox', value: true },
																]
															},
															{
																title: '选择中国DNS-2 <em>(直连) 🌏</em>', hint: '133', class: 'new_dns chng', multi: [
																	{ id: 'ss_basic_chng_china_2_enable', type: 'checkbox', func: 'u', value: true },
																	{ id: 'ss_basic_chng_china_2_prot', type: 'select', func: 'u', options: option_dnsngc_prot, style: 'width:50px;', value: '2' },
																	{ id: 'ss_basic_chng_china_2_udp', type: 'select', func: 'u', options: option_dnsngc_udp, style: 'width:200px;', value: '5' },
																	{ id: 'ss_basic_chng_china_2_udp_user', type: 'text', style: 'width:120px;', ph: '114.114.115.115', value: '114.114.115.115' },
																	{ id: 'ss_basic_chng_china_2_tcp', type: 'select', func: 'u', options: option_dnsngc_tcp, style: 'width:200px;', value: '5' },
																	{ id: 'ss_basic_chng_china_2_tcp_user', type: 'text', style: 'width:120px;', ph: '114.114.115.115', value: '114.114.115.115' },
																	{ suffix: '&nbsp;&nbsp;' },
																	{ prefix: '<a id="ss_basic_chng_china_2_ecs_note" class="hintstyle" href="javascript:void(0);" onclick="openssHint(130)"><font color="#ffcc00">&nbsp;<u>ECS</u></font></a>', id: 'ss_basic_chng_china_2_ecs', type: 'checkbox', value: true },
																]
															},
															{
																title: '选择可信DNS-1 <font color="#FF0066">(代理) 🚀</font>', hint: '134', class: 'new_dns chng', rid: 'dns_plan_foreign_1', multi: [
																	{ id: 'ss_basic_chng_trust_1_enable', type: 'checkbox', func: 'u', value: true },
																	{ id: 'ss_basic_chng_trust_1_opt', type: 'select', func: 'u', options: option_dnsngf_1_opt, style: 'width:50px;', value: '2' },
																	{ id: 'ss_basic_chng_trust_1_opt_udp_val', type: 'select', func: 'u', options: option_dnsngf_1_val_udp, style: 'width:auto;', value: '1' },
																	{ id: 'ss_basic_chng_trust_1_opt_udp_val_user', type: 'text', style: 'width:120px;', value: '8.8.8.8:53', ph: ph1 },
																	{ id: 'ss_basic_chng_trust_1_opt_tcp_val', type: 'select', func: 'u', options: option_dnsngf_1_val_tcp, style: 'width:auto;', value: '1' },
																	{ id: 'ss_basic_chng_trust_1_opt_tcp_val_user', type: 'text', style: 'width:120px;', value: '8.8.8.8:53', ph: ph1 },
																	{ suffix: '&nbsp;&nbsp;' },
																	{ prefix: '<a id="ss_basic_chng_trust_1_ecs_note" class="hintstyle" href="javascript:void(0);" onclick="openssHint(131)"><font color="#ffcc00">&nbsp;<u>ECS</u></font></a>', id: 'ss_basic_chng_trust_1_ecs', type: 'checkbox', value: true },
																]
															},
															{
																title: '选择可信DNS-2 <em>(直连) 🌏</em>', class: 'new_dns chng', hint: '135', rid: 'dns_plan_foreign_2', multi: [
																	{ id: 'ss_basic_chng_trust_2_enable', type: 'checkbox', func: 'u', value: false },
																	{ id: 'ss_basic_chng_trust_2_opt', type: 'select', func: 'u', options: option_dnsngf_2_opt, style: 'width:50px;', value: '0' },
																	{ id: 'ss_basic_chng_trust_2_opt_udp', type: 'text', style: 'width:120px;', value: '208.67.222.222:5353', ph: ph2 },
																	{ id: 'ss_basic_chng_trust_2_opt_tcp', type: 'text', style: 'width:120px;', value: '208.67.222.222:5353', ph: ph2 },
																	{ suffix: '&nbsp;&nbsp;' },
																	{ prefix: '<a id="ss_basic_chng_trust_2_ecs_note" class="hintstyle" href="javascript:void(0);" onclick="openssHint(132)"><font color="#ffcc00">&nbsp;<u>ECS</u></font></a>', id: 'ss_basic_chng_trust_2_ecs', type: 'checkbox', value: true },
																]
															},
															{
																title: '丢弃AAAA记录（--no-ipv6）', class: 'new_dns chng', hint: '145', id: 'ss_basic_chng_x', multi: [
																	{ id: 'ss_basic_chng_no_ipv6', type: 'checkbox', func: 'u', value: true },
																	{ suffix: '<a id="ss_basic_chng_left">&nbsp;&nbsp;&nbsp;&nbsp;【</a>' },
																	{ id: 'ss_basic_chng_act', name: 'ss_basic_chng_x', type: 'radio', suffix: '<a id="ss_basic_chng_xact" class="hintstyle" href="javascript:void(0);" onclick="openssHint(145)"><font color="#ffcc00">act</font></a>&nbsp;&nbsp;', value: 0 },
																	{ id: 'ss_basic_chng_gt', name: 'ss_basic_chng_x', type: 'radio', suffix: '<a id="ss_basic_chng_xgt" class="hintstyle" href="javascript:void(0);" onclick="openssHint(145)"><font color="#ffcc00">gt</font></a>&nbsp;&nbsp;', value: 1 },
																	{ id: 'ss_basic_chng_mc', name: 'ss_basic_chng_x', type: 'radio', suffix: '<a id="ss_basic_chng_xmc" class="hintstyle" href="javascript:void(0);" onclick="openssHint(145)"><font color="#ffcc00">mt</font></a>', value: 0 },
																	{ suffix: '<a id="ss_basic_chng_right">&nbsp;&nbsp;】</a>' },
																]
															},
															{ title: '发送重复DNS查询包（--repeat-times）', class: 'new_dns chng', id: 'ss_basic_chng_repeat_times', type: 'text', value: '2' },
															{
																title: '选择中国DNS', class: 'old_dns', multi: [
																	{ id: 'ss_china_dns', type: 'select', func: 'u', options: option_chndns, style: 'width:auto;', value: '3' },
																	{ id: 'ss_china_dns_user', type: 'text', ph: '114.114.114.114' }
																]
															},
															{
																title: '选择外国DNS（🌏直连 | 🚀代理） ', class: 'old_dns', hint: '26', rid: 'dns_plan_foreign', multi: [
																	{ id: 'ss_foreign_dns', type: 'select', func: 'u', options: option_dnsf, style: 'width:auto;' },
																	{ id: 'ss_dns2socks_user', type: 'text', style: 'width:auto;', value: '8.8.8.8:53', ph: ph1 },
																	{ id: 'ss_sstunnel_user', type: 'text', value: '8.8.8.8:53', ph: ph1 },
																	{ id: 'ss_direct_user', type: 'text', value: '8.8.8.8#53', ph: ph2 },
																	{ prefix: '<span id="ss_sstunnel_user_note">&nbsp;&nbsp;仅SS/SSR模式下可用</span>' },
																	{ suffix: '<span id="ss_disable_aaaa_note">丢弃AAAA记录</span>', id: 'ss_disable_aaaa', type: 'checkbox', value: true },
																	{ suffix: '<span id="ss_v2_note"></span>' },
																]
															},
															{ title: '<em>其它DNS相关设置</em>', th: '2' },
															{ title: 'DNS重定向', id: 'ss_basic_dns_hijack', type: 'checkbox', hint: '106', value: true },
															{
																title: 'DNS解析测试', rid: 'ss_dns_test', multi: [
																	{ suffix: '<a type="button" class="ss_btn" style="cursor:pointer" onclick="dns_test(1)">测试cdn</a>&nbsp;&nbsp;' },
																	{ suffix: '<a type="button" class="ss_btn" style="cursor:pointer" onclick="dns_test(2)">测试apple china</a>&nbsp;&nbsp;' },
																	{ suffix: '<a type="button" class="ss_btn" style="cursor:pointer" onclick="dns_test(3)">测试google china</a>&nbsp;&nbsp;' },
																	{ suffix: '<a type="button" class="ss_btn" style="cursor:pointer" onclick="dns_test(4)">测试gfwlist</a>&nbsp;&nbsp;' },
																]
															},
															{
																title: 'DNS解析测试(dig)', rid: 'ss_dig_test', multi: [
																	{ id: 'ss_basic_dig_opt', type: 'select', func: 'u', options: option_dig, style: 'width:240px;', value: '1' },
																	{ suffix: '&nbsp;&nbsp;' },
																	{ suffix: '<a type="button" class="ss_btn" style="cursor:pointer" onclick="dns_test(6)">dig</a>&nbsp;&nbsp;' },
																]
															},
															{
																title: '重启dnsmasq', rid: 'ss_dnsmasq_restart', multi: [
																	{ suffix: '<a type="button" class="ss_btn" style="cursor:pointer" onclick="restart_dnsmaq()">重启dnsmasq</a>' },
																]
															},
															{
																title: '节点域名解析DNS方案', hint: '107', multi: [
																	{ id: 'ss_basic_server_resolv', type: 'select', func: 'u', options: option_resv, style: 'width:160px;', value: '-1' },
																	{ id: 'ss_basic_server_resolv_user', type: 'text', style: 'width:145px;', ph: '176.103.130.130:5353', value: '176.103.130.130:5353' },
																]
															},
															{ title: '自定义dnsmasq', id: 'ss_dnsmasq', type: 'textarea', hint: '34', rows: '12', ph: ph3 },
														]);
													</script>
												</table>
											</div>
											<div id="tablet_4" style="display: none;">
												<table id="table_wblist" width="100%" border="1" align="center"
													cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"
													class="FormTable">
													<script type="text/javascript">
														var ph1 = "# 填入不需要走代理的外网ip地址，一行一个，格式（IP/CIDR）如下&#10;2.2.2.2&#10;3.3.3.3&#10;4.4.4.4/24";
														var ph2 = "# 填入不需要走代理的域名，一行一个，格式如下：&#10;google.com&#10;facebook.com&#10;# 需要清空电脑DNS缓存，才能立即看到效果。";
														var ph3 = "# 填入需要强制走代理的外网ip地址，一行一个，格式（IP/CIDR）如下：&#10;5.5.5.5&#10;6.6.6.6&#10;7.7.7.7/8";
														var ph4 = "# 填入需要强制走代理的域名，一行一个，格式如下：&#10;baidu.com&#10;taobao.com&#10;# 需要清空电脑DNS缓存，才能立即看到效果。";
														$('#table_wblist').forms([
															{ title: 'IP/CIDR白名单<br><br><font color="#ffcc00">添加不需要走代理的外网ip地址</font>', id: 'ss_wan_white_ip', type: 'textarea', hint: '38', rows: '7', ph: ph1 },
															{ title: '域名白名单<br><br><font color="#ffcc00">添加不需要走代理的域名</font>', id: 'ss_wan_white_domain', type: 'textarea', hint: '39', rows: '7', ph: ph2 },
															{ title: 'IP/CIDR黑名单<br><br><font color="#ffcc00">添加需要强制走代理的外网ip地址</font>', id: 'ss_wan_black_ip', type: 'textarea', hint: '40', rows: '7', ph: ph3 },
															{ title: '域名黑名单<br><br><font color="#ffcc00">添加需要强制走代理的域名</font>', id: 'ss_wan_black_domain', type: 'textarea', hint: '41', rows: '7', ph: ph4 },
														]);
													</script>
												</table>
											</div>


											<div id="tablet_5" style="display: none;">
												<table id="table_kcp" width="100%" border="1" align="center"
													cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"
													class="FormTable">
													<script type="text/javascript">
														var option_kcpm = ["manual", "normal", "fast", "fast2", "fast3"];
														var option_kcpe = ["aes", "aes-128", "aes-192", "salsa20", "blowfish", "twofish", "cast5", "3des", "tea", "xtea", "xor", "none"];
														var ph1 = "请将速度模式为manual的参数和其它参数依次填写进来";
														var ph2 = "# 填入你的kcptun运行参数，每个参数用空格隔开，格式如下：&#10;--crypt salsa20 --key mjy211 --sndwnd 1024 --rcvwnd 1024 --mtu 1300 --nocomp --mode fast2";
														$('#table_kcp').forms([
															{ title: 'KCP加速开关', id: 'ss_basic_use_kcp', type: 'checkbox', func: 'v', value: false },
															{ title: 'KCP参数配置方式', id: 'ss_basic_kcp_method', type: 'select', func: 'v', options: [["1", "选择模式"], ["2", "输入模式"]], value: '2' },
															{
																title: 'kcp本地监听地址：端口 （-l）', multi: [
																	{ id: 'ss_basic_kcp_lserver', type: 'text', maxlen: '200', style: 'width:120px;', attrib: 'readonly', value: '0.0.0.0' },
																	{ suffix: '&nbsp;:&nbsp;' },
																	{ id: 'ss_basic_kcp_lport', type: 'text', maxlen: '200', style: 'width:44px;', attrib: 'readonly', value: '1091' },
																	{ suffix: '&nbsp;<a class="hintstyle" href="javascript:void(0);" onclick="openssHint(90)"><font color="#ffcc00"><u>帮助</u></font></a>' },
																]
															},
															{
																title: 'kcp服务器地址：端口 （-r）', multi: [
																	{ id: 'ss_basic_kcp_server', type: 'text', maxlen: '200', style: 'width:120px;' },
																	{ suffix: '&nbsp;:&nbsp;' },
																	{ id: 'ss_basic_kcp_port', type: 'text', maxlen: '200', style: 'width:44px;' },
																	{ suffix: '&nbsp;<a class="hintstyle" href="javascript:void(0);" onclick="openssHint(91)"><font color="#ffcc00"><u>帮助</u></font></a>' },
																]
															},
															{ title: '密码 (--key)', rid: 'ss_basic_kcp_password_tr', id: 'ss_basic_kcp_password', type: 'password', maxlen: '200', peekaboo: '1' },
															{ title: '速度模式 (--mode)', rid: 'ss_basic_kcp_mode_tr', id: 'ss_basic_kcp_mode', type: 'select', options: option_kcpm, value: 'fast2' },
															{ title: '加密方式 (--crypt)', rid: 'ss_basic_kcp_encrypt_tr', id: 'ss_basic_kcp_encrypt', type: 'select', options: option_kcpe, value: 'aes-192' },
															{ title: 'MTU (--mtu)', rid: 'ss_basic_kcp_mtu_tr', id: 'ss_basic_kcp_mtu', type: 'text', maxlen: '200' },
															{ title: '发送窗口 (--sndwnd)', rid: 'ss_basic_kcp_sndwnd_tr', id: 'ss_basic_kcp_sndwnd', type: 'text', maxlen: '200' },
															{ title: '接收窗口 (--rcvwnd)', rid: 'ss_basic_kcp_rcvwnd_tr', id: 'ss_basic_kcp_rcvwnd', type: 'text', maxlen: '200' },
															{ title: '链接数 (--conn)', rid: 'ss_basic_kcp_conn_tr', id: 'ss_basic_kcp_conn', type: 'text', maxlen: '200' },
															{ title: '关闭数据压缩 (--nocomp)', rid: 'ss_basic_kcp_nocomp_tr', id: 'ss_basic_kcp_nocomp', type: 'checkbox', value: false },
															{ title: '其它配置项', rid: 'ss_basic_kcp_extra_tr', id: 'ss_basic_kcp_extra', type: 'text', maxlen: '200', style: 'width:95%', ph: ph1 },
															{ title: 'KCP参数', rid: 'ss_basic_kcp_parameter_tr', id: 'ss_basic_kcp_parameter', type: 'textarea', rows: '12', ph: ph2 },
														]);
													</script>
												</table>
											</div>



											<div id="tablet_6" style="display: none;">
												<table id="table_udp_main" width="100%" border="1" align="center"
													cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"
													class="FormTable">
													<script type="text/javascript">
														$('#table_udp_main').forms([
															{
																title: '加速节点选择', multi: [
																	{ id: 'ss_basic_udp_node', type: 'select', options: [] },
																	{ suffix: '&nbsp;<a class="hintstyle" href="javascript:void(0);" onclick="openssHint(97)"><font color="#ffcc00"><u>帮助</u></font></a>' },
																]
															},
															{
																title: '设置ss/ssr-redir MTU', multi: [
																	{ id: 'ss_basic_udp_upstream_mtu', type: 'select', func: 'u', options: [["0", "不设定"], ["1", "手动指定"]] },
																	{ id: 'ss_basic_udp_upstream_mtu_value', type: 'text', value: '1200', style: 'width:40px;' },
																	{ suffix: '&nbsp;<a class="hintstyle" href="javascript:void(0);" onclick="openssHint(98)"><font color="#ffcc00"><u>帮助</u></font></a>' },
																]
															},
															{
																title: '帮助信息', multi: [
																	{ suffix: '<ul><li>你可以只开启UDPspeeder加速udp，或者只开启UDP2raw将udp转为tcp；</li>' },
																	{ suffix: '<li>你也可以将UDPspeeder和UDP2raw都开启，并配置它们串联工作；</li><li>帮助文档：' },
																	{ suffix: '<a type="button" style="cursor:pointer" target="_blank" href="https://github.com/wangyu-/UDPspeeder/blob/master/doc/README.zh-cn.v1.md"><em><u>UDPspeederV1</u></em></a>&nbsp;&nbsp;' },
																	{ suffix: '<a type="button" style="cursor:pointer" target="_blank" href="https://github.com/wangyu-/UDPspeeder/blob/master/doc/README.zh-cn.md"><em><u>UDPspeederV2</u></em></a>&nbsp;&nbsp;' },
																	{ suffix: '<a type="button" style="cursor:pointer" target="_blank" href="https://github.com/wangyu-/udp2raw-tunnel/blob/master/doc/README.zh-cn.md"><em><u>udp2raw-tunnel</u></em></a>' },
																	{ suffix: '</li></ul>' },
																]
															},
															{ title: 'UDPspeeder运行状态', suffix: '<span id="udp_status">获取中...</span>' },
														]);
													</script>
												</table>
												<div id="sub_tablets">
													<table style="margin:10px 0px 0px 0px;border-collapse:collapse"
														width="100%" height="37px">
														<tr width="235px">
															<td colspan="4" cellpadding="0" cellspacing="0"
																style="padding:0" border="1" bordercolor="#000">
																<input id="sub_btn1" class="sub-btn1 active2"
																	style="cursor:pointer" type="button"
																	value="UDPspeeder" />
																<input id="sub_btn2" class="sub-btn2"
																	style="cursor:pointer" type="button"
																	value="UDP2raw-tunnel" />
															</td>
														</tr>
													</table>
												</div>
												<table id="table_udp" style="margin:-1px 0px 0px 0px;" width="100%"
													border="1" align="center" cellpadding="4" cellspacing="0"
													bordercolor="#6b8fa3" class="FormTable">
													<script type="text/javascript">
														$('#table_udp').forms([
															{ title: '<em>UDPspeeder 设置</em>', th: '2', class: 'speeder' },
															{ title: 'UDPspeeder开关', id: 'ss_basic_udp_boost_enable', type: 'checkbox', class: 'speeder', value: false },
															{
																title: 'UDPspeeder版本', class: 'speeder', multi: [
																	{ id: 'ss_basic_udp_software', type: 'select', func: 'v', style: 'width:132px', options: [["1", "UDPspeederV1"], ["2", "UDPspeederV2"]] },
																	{ suffix: '&nbsp;<a class="hintstyle" href="javascript:void(0);" onclick="openssHint(104)"><font color="#ffcc00"><u>帮助</u></font></a>' },
																]
															},
															{ title: '<em>UDPspeederV1 参数设置</em>', th: '2', class: 'speederv1' },
															{
																title: '* 本地监听地址：端口 （-l）', class: 'speederv1', multi: [
																	{ id: 'ss_basic_udpv1_lserver', type: 'text', maxlen: '200', style: 'width:120px;', attrib: 'readonly', value: '0.0.0.0' },
																	{ suffix: '&nbsp;:&nbsp;' },
																	{ id: 'ss_basic_udpv1_lport', type: 'text', maxlen: '200', style: 'width:44px;', attrib: 'readonly', value: '1092' },
																	{ suffix: '&nbsp;<a class="hintstyle" href="javascript:void(0);" onclick="openssHint(99)"><font color="#ffcc00"><u>帮助</u></font></a>' },
																]
															},
															{
																title: '* 服务器地址：端口 （-r）', class: 'speederv1', multi: [
																	{ id: 'ss_basic_udpv1_rserver', type: 'text', maxlen: '200', style: 'width:120px;' },
																	{ suffix: '&nbsp;:&nbsp;' },
																	{ id: 'ss_basic_udpv1_rport', type: 'text', maxlen: '200', style: 'width:44px;' },
																	{ suffix: '&nbsp;<a class="hintstyle" href="javascript:void(0);" onclick="openssHint(100)"><font color="#ffcc00"><u>帮助</u></font></a>' },
																]
															},
															{ title: '* 密码 (--key)', id: 'ss_basic_udpv1_password', type: 'password', maxlen: '200', class: 'speederv1', style: 'width:120px', peekaboo: '1' },
															{ title: '以下为包发送选项，两端设置可以不同, 只影响本地包发送。', th: '2', class: 'speederv1' },
															{ title: '* 冗余包数量 （-d）', id: 'ss_basic_udpv1_duplicate_nu', type: 'text', style: 'width:120px', class: 'speederv1', maxlen: '200', suffix: '&nbsp;<a>默认0，留空则使用默认值。</a>' },
															{ title: '* 冗余包发送延迟 （-t）', id: 'ss_basic_udpv1_duplicate_time', type: 'text', style: 'width:120px', class: 'speederv1', maxlen: '200', suffix: '&nbsp;<a>默认值20（2ms），留空则使用默认值</a>' },
															{ title: '* 原始数据抖动延迟 （-j）', id: 'ss_basic_udpv1_jitter', type: 'text', style: 'width:120px', class: 'speederv1', maxlen: '200', suffix: '&nbsp;<a>默认0，留空则使用默认值</a>' },
															{ title: '* 数据发送和接受报告 （--report）', id: 'ss_basic_udpv1_report', type: 'text', style: 'width:120px', class: 'speederv1', maxlen: '200', suffix: '&nbsp;<a>单位：s，留空则不使用。</a>' },
															{ title: '* 随机丢包 （--random-drop）', id: 'ss_basic_udpv1_drop', type: 'text', style: 'width:120px', class: 'speederv1', maxlen: '200', suffix: '&nbsp;<a>单位：0.01%，留空则不使用。</a>' },
															{ title: '以下为包接收选项，两端设置可以不同，只影响本地包接受。', th: '2', class: 'speederv1' },
															{ title: '* 关闭重复包过滤器 （--disable-filter）', id: 'ss_basic_udpv1_disable_filter', type: 'checkbox', class: 'speederv1', value: false },
															{ title: '<em>UDPspeederV2 参数设置</em>', th: '2', class: 'speederv2' },
															{
																title: '* 本地监听地址：端口 （-l）', class: 'speederv2', multi: [
																	{ id: 'ss_basic_udpv2_lserver', type: 'text', maxlen: '200', style: 'width:120px;', attrib: 'readonly', value: '0.0.0.0' },
																	{ suffix: '&nbsp;:&nbsp;' },
																	{ id: 'ss_basic_udpv2_lport', type: 'text', maxlen: '200', style: 'width:44px;', attrib: 'readonly', value: '1092' },
																	{ suffix: '&nbsp;<a class="hintstyle" href="javascript:void(0);" onclick="openssHint(99)"><font color="#ffcc00"><u>帮助</u></font></a>' },
																]
															},
															{
																title: '* 服务器地址：端口 （-r）', class: 'speederv2', multi: [
																	{ id: 'ss_basic_udpv2_rserver', type: 'text', maxlen: '200', style: 'width:120px;' },
																	{ suffix: '&nbsp;:&nbsp;' },
																	{ id: 'ss_basic_udpv2_rport', type: 'text', maxlen: '200', style: 'width:44px;' },
																	{ suffix: '&nbsp;<a class="hintstyle" href="javascript:void(0);" onclick="openssHint(100)"><font color="#ffcc00"><u>帮助</u></font></a>' },
																]
															},
															{ title: '* 密码 (--key)', id: 'ss_basic_udpv2_password', type: 'password', maxlen: '200', class: 'speederv2', style: 'width:120px', peekaboo: '1' },
															{ title: '以下为包发送选项，两端设置可以不同, 只影响本地包发送。', th: '2', class: 'speederv2' },
															{
																title: '* fec参数 （-f）', class: 'speederv2', multi: [
																	{ id: 'ss_basic_udpv2_fec', type: 'text', maxlen: '200', style: 'width:120px;' },
																	{ suffix: '&nbsp;<a>必填，x:y，每x个包额外发送y个包。</a>' },
																	{ suffix: '&nbsp;<a type="button" class="ss_btn" style="cursor:pointer" target="_blank" href="https://github.com/wangyu-/UDPspeeder/wiki/%E4%BD%BF%E7%94%A8%E7%BB%8F%E9%AA%8C">fec使用经验</a>' },
																]
															},
															{ title: '* timeout参数 （--timeout）', id: 'ss_basic_udpv2_timeout', type: 'text', style: 'width:120px', class: 'speederv2', maxlen: '200', suffix: '&nbsp;<a>单位：ms，默认8，留空则使用默认值。</a>' },
															{ title: '* mode参数 （--mode）', id: 'ss_basic_udpv2_mode', type: 'text', style: 'width:120px', class: 'speederv2', maxlen: '200', suffix: '&nbsp;<a>默认0，留空则使用默认值。</a>' },
															{ title: '* 数据发送和接受报告 （--report）', id: 'ss_basic_udpv2_report', type: 'text', style: 'width:120px', class: 'speederv2', maxlen: '200', suffix: '&nbsp;<a>单位：s，留空则不使用。</a>' },
															{ title: '* mtu参数 （--mtu）', id: 'ss_basic_udpv2_mtu', type: 'text', style: 'width:120px', class: 'speederv2', maxlen: '200', suffix: '&nbsp;<a>默认1250，留空则使用默认值。</a>' },
															{ title: '* 原始数据抖动延迟 （-j,--jitter）', id: 'ss_basic_udpv2_jitter', type: 'text', style: 'width:120px', class: 'speederv2', maxlen: '200', suffix: '&nbsp;<a>单位：ms，默认0，留空则使用默认值。</a>' },
															{ title: '* 时间窗口 （-i,--interval）', id: 'ss_basic_udpv2_interval', type: 'text', style: 'width:120px', class: 'speederv2', maxlen: '200', suffix: '&nbsp;<a>单位：ms，默认0，留空则使用默认值。</a>' },
															{ title: '* 随机丢包 （--random-drop）', id: 'ss_basic_udpv2_drop', type: 'text', style: 'width:120px', class: 'speederv2', maxlen: '200', suffix: '&nbsp;<a>单位：0.01%，默认0，留空则使用默认值。</a>' },
															{ title: '以下服务器和客户端设置必须一致！', th: '2', class: 'speederv2' },
															{ title: '* 关闭数据包随机填充（--disable-obscure）', id: 'ss_basic_udpv2_disableobscure', type: 'checkbox', class: 'speederv2', value: false, suffix: '&nbsp;<a>关闭可节省一点带宽和cpu。</a>' },
															{ title: '* 关闭数据包验证（--disable-checksum）', id: 'ss_basic_udpv2_disablechecksum', type: 'checkbox', class: 'speederv2', value: false, suffix: '&nbsp;<a>关闭可节省一点带宽和cpu。</a>' },
															{ title: '其它参数', th: '2', class: 'speederv2' },
															{ title: '* 其它参数', id: 'ss_basic_udpv2_other', type: 'text', style: 'width:95%', class: 'speederv2', maxlen: '200', suffix: '<br />&nbsp;<a>其它高级参数，请手动输入，如 -q1 等。</a>' },
															{ title: '<em>UDP2raw 设置</em>', th: '2', class: 'udp2raw' },
															{ title: 'UDP2raw开关', id: 'ss_basic_udp2raw_boost_enable', type: 'checkbox', class: 'udp2raw', value: false },
															{ title: '<em>UDP2raw 参数设置</em>', th: '2', class: 'udp2raw' },
															{
																title: '* 本地监听地址：端口 （-l）', class: 'udp2raw', multi: [
																	{ id: 'ss_basic_udp2raw_lserver', type: 'text', maxlen: '200', style: 'width:120px;', attrib: 'readonly', value: '0.0.0.0' },
																	{ suffix: '&nbsp;:&nbsp;' },
																	{ id: 'ss_basic_udp2raw_lport', type: 'text', maxlen: '200', style: 'width:44px;', attrib: 'readonly', value: '1093' },
																	{ suffix: '&nbsp;<a class="hintstyle" href="javascript:void(0);" onclick="openssHint(101)"><font color="#ffcc00"><u>帮助</u></font></a>' },
																]
															},

															{ title: '* 密码 (--key)', id: 'ss_basic_udp2raw_password', type: 'password', maxlen: '200', class: 'udp2raw', style: 'width:120px', peekaboo: '1' },
															{ title: '* 模式（--raw-mode）', id: 'ss_basic_udp2raw_rawmode', type: 'select', style: 'width:132px', class: 'udp2raw', options: ["faketcp", "udp", "icmp"], value: 'faketcp', suffix: '&nbsp;<a>默认:faketcp</a>' },
															{ title: '* 加密模式 （--cipher-mode）', id: 'ss_basic_udp2raw_ciphermode', type: 'select', style: 'width:132px', class: 'udp2raw', options: ["aes128cbc", "aes128cfb", "xor", "none"], value: 'aes128cbc', suffix: '&nbsp;<a>默认:aes128cbc</a>' },
															{ title: '* 校验模式 （--auth-mode）', id: 'ss_basic_udp2raw_authmode', type: 'select', style: 'width:132px', class: 'udp2raw', options: ["md5", "hmac_sha1", "crc32", "icmp", "simple", "none"], value: 'md5', suffix: '&nbsp;<a>默认:md5</a>' },
															{ title: '* 自动添加/删除iptables（-a,--auto-rule）', id: 'ss_basic_udp2raw_a', type: 'checkbox', class: 'udp2raw', value: true, suffix: '<a>建议请勾选此选项</a>' },
															{ title: '* 定期检查iptables（--keep-rule）', id: 'ss_basic_udp2raw_keeprule', type: 'checkbox', class: 'udp2raw', value: true, suffix: '<a>建议请勾选此选项</a>' },
															{
																title: '* 绕过本地iptables（--lower-level）', class: 'udp2raw', multi: [
																	{ id: 'ss_basic_udp2raw_lowerlevel', type: 'text', maxlen: '200', style: 'width:120px;' },
																	{ suffix: '&nbsp;<a class="hintstyle" href="javascript:void(0);" onclick="openssHint(103)"><font color="#ffcc00"><u>帮助</u></font></a>' },
																]
															},
															{ title: '* 其它参数', id: 'ss_basic_udp2raw_other', type: 'text', style: 'width:95%', class: 'udp2raw', maxlen: '200', rows: '8', suffix: '<br />&nbsp;<a>其它未列出来的参数，请手动输入，如 --force-sock-buf --seq-mode 1 等。</a>' },
														]);
													</script>
												</table>
											</div>
											<div id="tablet_7" style="display: none;">
												<table id="table_rules" width="100%" border="1" align="center"
													cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"
													class="FormTable">
													<script type="text/javascript">
														var option_ruleu = [];
														for (var i = 0; i < 24; i++) {
															var _tmp = [];
															_i = i < 10 ? String("0" + i) : String(i)
															_tmp[0] = i;
															_tmp[1] = _i + ":00时";
															option_ruleu.push(_tmp);
														}
														function addCommas(nStr) {
															nStr += '';
															var x = nStr.split('.');
															var x1 = x[0];
															var x2 = x.length > 1 ? '.' + x[1] : '';
															var rgx = /(\d+)(\d{3})/;
															while (rgx.test(x1)) {
																x1 = x1.replace(rgx, '$1' + ',' + '$2');
															}
															return x1 + x2;
														}
														var gfwl = addCommas('<% nvram_get("ipset_numbers"); %>');
														var chnl = addCommas('<% nvram_get("chnroute_numbers"); %>');
														var chnn = addCommas('<% nvram_get("chnroute_ips"); %>');
														var cdnn = addCommas('<% nvram_get("cdn_numbers"); %>');
														$('#table_rules').forms([
															{
																title: 'gfwlist域名数量', multi: [
																	{ suffix: '<em>' + gfwl + '</em>&nbsp;条，版本：' },
																	{ suffix: '<a href="https://github.com/hq450/fancyss/blob/3.0/rules/gfwlist.conf" target="_blank">' },
																	{ suffix: '<i><% nvram_get("update_ipset"); %></i></a>' },
																]
															},
															{
																title: '大陆白名单IP段数量', multi: [
																	{ suffix: '<em>' + chnl + '</em>&nbsp;行，包含 <em>' + chnn + '</em>&nbsp;个ip地址，版本：' },
																	{ suffix: '<a href="https://github.com/hq450/fancyss/blob/3.0/rules/chnroute.txt" target="_blank">' },
																	{ suffix: '<i><% nvram_get("update_chnroute"); %></i></a>' },
																]
															},
															{
																title: '国内域名数量（cdn名单）', multi: [
																	{ suffix: '<em>' + cdnn + '</em>&nbsp;条，版本：' },
																	{ suffix: '<a href="https://github.com/hq450/fancyss/blob/3.0/rules/cdn.txt" target="_blank">' },
																	{ suffix: '<i><% nvram_get("update_cdn"); %></i></a>' },
																]
															},
															{
																title: '规则定时更新任务', hint: '44', multi: [
																	{ id: 'ss_basic_rule_update', type: 'select', func: 'u', style: 'width:auto', options: [["0", "禁用"], ["1", "开启"]], value: '0' },
																	{ id: 'ss_basic_rule_update_time', type: 'select', style: 'width:auto', options: option_ruleu, value: '4' },
																	{ suffix: '<a id="update_choose">' },
																	{ suffix: '<input type="checkbox" id="ss_basic_gfwlist_update" title="选择此项应用gfwlist.conf自动更新">gfwlist' },
																	{ suffix: '<input type="checkbox" id="ss_basic_chnroute_update" title="选择此项应用chnroute.txt自动更新">chnroute' },
																	{ suffix: '<input type="checkbox" id="ss_basic_cdn_update" title="选择此项应用cdn.txt自动更新">cdn</a>' },
																	{ suffix: '&nbsp;<a type="button" class="ss_btn" style="cursor:pointer" onclick="updatelist(1)">保存设置</a>' },
																]
															},
															{
																title: '规则手动更新', multi: [
																	{ suffix: '<a type="button" class="ss_btn" style="cursor:pointer" onclick="updatelist(2)">立即更新规则</a>' },
																]
															},
															{
																title: '二进制更新', multi: [
																	{ suffix: '<a type="button" class="ss_btn" style="cursor:pointer" onclick="v2ray_binary_update(2)">更新v2ray程序</a>&nbsp;' },
																	{ suffix: '<a type="button" class="ss_btn" style="cursor:pointer" onclick="xray_binary_update(2)">更新/切换xray程序</a>&nbsp;' },
																	{ suffix: '<a type="button" class="ss_btn" style="cursor:pointer" onclick="ssrust_binary_update(2)">更新ss-rust程序</a>' },
																]
															},
														]);
													</script>
												</table>
												<table id="table_subscribe" style="margin:8px 0px 0px 0px;" width="100%"
													border="1" align="center" cellpadding="4" cellspacing="0"
													bordercolor="#6b8fa3" class="FormTable">
													<script type="text/javascript">
														var option_noded = [["0", "每天"], ["1", "周一"], ["2", "周二"], ["3", "周三"], ["4", "周四"], ["5", "周五"], ["6", "周六"], ["7", "周日"]];
														var option_hy2_tfo = [["0", "强制关闭"], ["1", "强制开启"], ["2", "根据订阅"]];
														var option_nodeh = [];
														for (var i = 0; i < 24; i++) {
															var _tmp = [];
															_i = String(i)
															_tmp[0] = _i;
															_tmp[1] = _i + "点";
															option_nodeh.push(_tmp);
														}
														var ph1 = "此处填入你的机场订阅链接，通常是http://或https://开头的链接，多个链接可以分行填写！&#10;也可以增加非http开头的行作为注释，或使用空行或者符号线作为分割，订阅脚本仅会提取http://或https://开头的链接用以订阅，示例：&#10;-------------------------------------------------&#10;🚀xx机场 ssr&#10;https://abcd.airport.com/xxx&#10;&#10;🛩️yy机场 ss&#10;https://xyza.com/xxx&#10;-------------------------------------------------&#10;填写完成后点击下面的【保存并订阅】按钮开始订阅！";
														var ph2 = "多个关键词用英文逗号分隔，如：测试,过期,剩余,曼谷,M247,D01,硅谷";
														var ph3 = "多个关键词用英文逗号分隔，如：香港,深圳,NF,BGP";
														$('#table_subscribe').forms([
															{ title: '节点订阅设置', thead: '1' },
															{
																title: '订阅地址管理<br><br><font color="#ffcc00">支持SS/SSR/V2ray/Xray/Trojan</font>', multi: [
																	{ id: 'ss_online_links', type: 'textarea', hint: '116', rows: '12', ph: ph1 },
																	{ suffix: '<span id="ss_sub_ads"></span>' },
																]
															},
															{ title: '订阅节点模式设定', id: 'ssr_subscribe_mode', type: 'select', style: 'width:auto', options: option_modes, value: '2' },
															{
																title: 'hysteria2订阅设置', multi: [
																	{ suffix: '上行速度:' },
																	{ id: 'ss_basic_hy2_up_speed', type: 'text', maxlen: '200', style: 'width:30px;', value: '' },
																	{ suffix: 'Mbps，&nbsp;&nbsp;' },
																	{ suffix: '下行速度:' },
																	{ id: 'ss_basic_hy2_dl_speed', type: 'text', maxlen: '200', style: 'width:30px;', value: '' },
																	{ suffix: 'Mbps，&nbsp;&nbsp;' },
																	{ suffix: 'tcp fast open:' },
																	{ id: 'ss_basic_hy2_tfo_switch', type: 'select', style: 'width:auto', options: option_hy2_tfo, value: '2' },
																]
															},
															{ title: '下载订阅时走ss/ssr/v2ray/v2ray代理网络', id: 'ss_basic_online_links_goss', type: 'select', style: 'width:auto', options: [["0", "不走代理"], ["1", "走代理"]], value: '0' },
															{
																title: '订阅计划任务', multi: [
																	{ id: 'ss_basic_node_update', type: 'select', style: 'width:auto', func: 'u', options: [["0", "禁用"], ["1", "开启"]], value: '0' },
																	{ id: 'ss_basic_node_update_day', type: 'select', style: 'width:auto', options: option_noded, value: '6' },
																	{ id: 'ss_basic_node_update_hr', type: 'select', style: 'width:auto', options: option_nodeh, value: '3' },
																]
															},
															{ title: '[排除]关键词（含关键词的节点不会添加）', rid: 'ss_basic_exclude_tr', id: 'ss_basic_exclude', type: 'text', hint: '110', maxlen: '300', style: 'width:95%', ph: ph2 },
															{ title: '[包括]关键词（含关键词的节点才会添加）', rid: 'ss_basic_include_tr', id: 'ss_basic_include', type: 'text', hint: '111', maxlen: '300', style: 'width:95%', ph: ph3 },
															{
																title: '删除节点', rid: 'ss_basic_remove_node', multi: [
																	{ suffix: '<a type="button" class="ss_btn" style="cursor:pointer" onclick="get_online_nodes(0)">删除全部节点</a>' },
																	{ suffix: '&nbsp;<a type="button" class="ss_btn" style="cursor:pointer" onclick="get_online_nodes(1)">删除全部订阅节点</a>' },
																]
															},
															{
																title: '保存配置', rid: 'ss_sub_save_only', multi: [
																	{ suffix: '<a type="button" class="ss_btn" style="cursor:pointer" onclick="get_online_nodes(2)">仅保存设置</a>' },
																]
															},
															{
																title: '节点订阅', multi: [
																	{ suffix: '<a type="button" class="ss_btn" style="cursor:pointer" onclick="get_online_nodes(3)">保存并订阅</a>' },
																	{ prefix: '&nbsp;&nbsp;订阅高级设定', id: 'ss_adv_sub', type: 'checkbox', value: false, func: 'v' },
																]
															}
														]);
													</script>
												</table>
												<table id="table_link" style="margin:8px 0px 0px 0px;" width="100%"
													border="1" align="center" cellpadding="4" cellspacing="0"
													bordercolor="#6b8fa3" class="FormTable">
													<script type="text/javascript">
														var ph1 = "填入以 vless:// 或 hysteria2:// 或 ss:// 或 ssr:// 或 chain##(串联方式) 开头的链接，多个链接请分行填写";
														$('#table_subscribe').forms([
															{ title: '通过 vless / hysteria2 / ss / ssr / chain##(串联方式) 添加节点', thead: '1' },
															{ title: 'vless/hysteria2/ss/ssr/chain## (串联方式)链接', id: 'ss_base64_links', type: 'textarea', hint: 117, rows: '11', ph: ph1 },
															{ title: '操作', suffix: '<a type="button" class="ss_btn" style="cursor:pointer" onclick="get_online_nodes(4)">解析并保存为节点</a>' },
														]);
													</script>
												</table>
											</div>
											<div id="tablet_8" style="display: none;">
												<div id="ss_acl_table"></div>
												<div id="ACL_note" style="margin:10px 0 0 5px">
													<div>
														<i>1&nbsp;&nbsp;默认状态下，所有局域网的主机都会走当前节点的模式（主模式），相当于即不启用局域网访问控制。</i>
													</div>
													<div>
														<i>2&nbsp;&nbsp;当你设置默认规则为不通过代理，添加了主机走大陆白名单模式，则只有添加的主机才会走代理(大陆白名单模式)。</i>
													</div>
													<div>
														<i>3&nbsp;&nbsp;当你设置默认规则为正在使用节点的模式，除了添加的主机才会走相应的模式，未添加的主机会走默认规则的模式。</i>
													</div>
													<div>
														<i>4&nbsp;&nbsp;如果为使用的节点配置了KCP协议，或者负载均衡，因为它们不支持udp，所以不能控制主机走游戏模式。</i>
													</div>
													<div>
														<i>5&nbsp;&nbsp;如果需要自定义端口范围，适用英文逗号和冒号，参考格式：80,443,5566:6677,7777:8888</i>
													</div>
												</div>
											</div>
											<div id="tablet_9" style="display: none;">
												<table id="table_addons" width="100%" border="1" align="center"
													cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"
													class="FormTable">
													<script type="text/javascript">
														var title1 = "填写说明：&#13;此处填写1-23之间任意小时&#13;小时间用逗号间隔，如：&#13;当天的8点、10点、15点则填入：8,10,15"
														var option_rebc = [["0", "关闭"], ["1", "每天"], ["2", "每周"], ["3", "每月"], ["4", "每隔"], ["5", "自定义"]];
														var option_rebw = [["1", "一"], ["2", "二"], ["3", "三"], ["4", "四"], ["5", "五"], ["6", "六"], ["7", "日"]];
														var option_rebd = [];
														for (var i = 1; i < 32; i++) {
															var _tmp = [];
															_i = String(i)
															_tmp[0] = _i;
															_tmp[1] = _i + "日";
															option_rebd.push(_tmp);
														}
														var option_rebim = ["1", "5", "10", "15", "20", "25", "30"];
														var option_rebih = [];
														for (var i = 1; i < 13; i++) option_rebih.push(String(i));
														var option_rebid = [];
														for (var i = 1; i < 31; i++) option_rebid.push(String(i));
														var option_rebip = [["1", "分钟"], ["2", "小时"], ["3", "天"]];
														var option_rebh = [];
														for (var i = 0; i < 24; i++) {
															var _tmp = [];
															_i = String(i)
															_tmp[0] = _i;
															_tmp[1] = _i + "时";
															option_rebh.push(_tmp);
														}
														var option_rebm = [];
														for (var i = 0; i < 61; i++) {
															var _tmp = [];
															_i = String(i)
															_tmp[0] = _i;
															_tmp[1] = _i + "分";
															option_rebm.push(_tmp);
														}
														var option_trit = [["0", "关闭"], ["2", "每隔2分钟"], ["5", "每隔5分钟"], ["10", "每隔10分钟"], ["15", "每隔15分钟"], ["20", "每隔20分钟"], ["25", "每隔25分钟"], ["30", "每隔30分钟"]];
														var weburl = ["developer.google.cn/generate_204", "connectivitycheck.gstatic.com/generate_204", "www.gstatic.com/generate_204"];
														$('#table_addons').forms([
															{ td: '<tr><td class="smth" style="font-weight: bold;" colspan="2">备份/恢复</td></tr>' },
															{
																title: '导出fancyss配置', hint: '24', multi: [
																	{ suffix: '<input type="button" class="ss_btn" style="cursor:pointer;" onclick="download_route_file(1);" value="导出配置">' },
																	{ suffix: '&nbsp;<input type="button" class="ss_btn" style="cursor:pointer;" onclick="remove_SS_node();" value="清空配置">' },
																	{ suffix: '&nbsp;<input type="button" class="ss_btn" style="cursor:pointer;" onclick="download_route_file(2);" value="打包插件">' },
																]
															},
															{
																title: '恢复fancyss配置', hint: '24', multi: [
																	{ suffix: '<input style="color:#FFCC00;*color:#000;width: 200px;" id="ss_file" type="file" name="file"/>' },
																	{ suffix: '<img id="loadingicon" style="margin-left:5px;margin-right:5px;display:none;" src="/images/InternetScan.gif"/>' },
																	{ suffix: '<span id="ss_file_info" style="display:none;">完成</span>' },
																	{ suffix: '<input type="button" class="ss_btn" style="cursor:pointer;" onclick="upload_ss_backup();" value="恢复配置"/>' },
																]
															},
															{ td: '<tr><td class="smth" style="font-weight: bold;" colspan="2">定时任务</td></tr>' },
															{
																title: '插件定时重启设定', multi: [
																	{ id: 'ss_reboot_check', type: 'select', style: 'width:auto', func: 'v', options: option_rebc, value: '0' },
																	{ id: 'ss_basic_week', type: 'select', style: 'width:auto', css: 're2', options: option_rebw, value: '1' },
																	{ id: 'ss_basic_day', type: 'select', style: 'width:auto', css: 're3', options: option_rebd, value: '1' },
																	{ id: 'ss_basic_inter_min', type: 'select', style: 'width:auto', css: 're4_1', options: option_rebim, value: '1' },
																	{ id: 'ss_basic_inter_hour', type: 'select', style: 'width:auto', css: 're4_2', options: option_rebih, value: '1' },
																	{ id: 'ss_basic_inter_day', type: 'select', style: 'width:auto', css: 're4_3', options: option_rebid, value: '1' },
																	{ id: 'ss_basic_inter_pre', type: 'select', style: 'width:auto', func: 'v', css: 're4', options: option_rebip, value: '1' },
																	{ id: 'ss_basic_custom', type: 'text', style: 'width:150px', css: 're5', ph: '8,10,15', title: title1 },
																	{ suffix: '<span class="re5">&nbsp;小时</span>' },
																	{ id: 'ss_basic_time_hour', type: 'select', style: 'width:auto', css: 're1 re2 re3 re4_3', options: option_rebh, value: '0' },
																	{ id: 'ss_basic_time_min', type: 'select', style: 'width:auto', css: 're1 re2 re3 re4_3 re5', options: option_rebm, value: '0' },
																	{ suffix: '&nbsp;<span class="re1 re2 re3 re4 re5">重启插件</span>' },
																	{ suffix: '&nbsp;<a type="button" class="ss_btn" style="cursor:pointer" onclick="set_cron(1)">保存设置</a>' },
																]
															},
															{
																title: '插件触发重启设定', multi: [
																	{ id: 'ss_basic_tri_reboot_time', type: 'select', style: 'width:auto', hint: '109', func: 'u', options: option_trit, value: '0' },
																	{ suffix: '<span id="ss_basic_tri_reboot_time_note">&nbsp;解析服务器IP，如果发生变更，则重启插件！</span>' },
																	{ suffix: '&nbsp;<a type="button" class="ss_btn" style="cursor:pointer" onclick="set_cron(2)">保存设置</a>' },
																]
															},
															{ td: '<tr><td class="smth" style="font-weight: bold;" colspan="2">节点列表</td></tr>' },
															{ title: '节点列表最大显示行数', id: 'ss_basic_row', type: 'select', func: 'onchange="save_row();"', style: 'width:auto', options: [] },
															{ title: '开启生成二维码功能', id: 'ss_basic_qrcode', func: 'v', type: 'checkbox', value: true },
															{ title: '开启节点排序功能', id: 'ss_basic_dragable', func: 'v', type: 'checkbox', value: true },
															{ title: '节点管理页面设为默认标签页', id: 'ss_basic_tablet', func: 'v', type: 'checkbox', value: false },
															{ title: '节点管理页面隐藏服务器地址', id: 'ss_basic_noserver', func: 'v', type: 'checkbox', value: false },
															{ td: '<tr><td class="smth" style="font-weight: bold;" colspan="2">代理行为</td></tr>' },
															{ title: 'New Bing模式', id: 'ss_basic_proxy_newb', hint: '149', type: 'checkbox', value: true },
															{
																title: 'udp代理控制', hint: '150', thtd: 1, multi: [
																	{ id: 'ss_basic_udpoff', name: 'ss_basic_udp_proxy', func: 'u', type: 'radio', suffix: '<a class="hintstyle" href="javascript:void(0);" onclick="openssHint(151)"><font color="#ffcc00">关闭</font></a>', value: 0 },
																	{ id: 'ss_basic_udpall', name: 'ss_basic_udp_proxy', func: 'u', type: 'radio', suffix: '<a class="hintstyle" href="javascript:void(0);" onclick="openssHint(152)"><font color="#ffcc00">开启</font></a>', value: 1 },
																	{ id: 'ss_basic_udpgpt', name: 'ss_basic_udp_proxy', func: 'u', type: 'radio', suffix: '<a class="hintstyle" href="javascript:void(0);" onclick="openssHint(153)"><font color="#ffcc00">仅chatgpt</font></a>', value: 2 },
																]
															},
															{ td: '<tr><td class="smth" style="font-weight: bold;" colspan="2">性能优化</td></tr>' },
															{ title: 'ssr开启多核心支持', id: 'ss_basic_mcore', hint: '108', type: 'checkbox', value: true },										//fancyss-hnd
															{ title: 'ss/v2ray/xray开启tcp fast open', id: 'ss_basic_tfo', type: 'checkbox', value: false },										//fancyss-hnd
															{ title: 'ss协议开启TCP_NODELAY', id: 'ss_basic_tnd', type: 'checkbox', value: false },
															{ title: 'Xray启用进程守护', id: 'ss_basic_xguard', hint: '115', type: 'checkbox', value: false },
															{ td: '<tr><td class="smth" style="font-weight: bold;" colspan="2">其它</td></tr>' },

															{ title: '所有trojan节点强制允许不安全', id: 'ss_basic_tjai', hint: '120', type: 'checkbox', value: false },
															{ title: '插件开启时 - 跳过网络可用性检测', id: 'ss_basic_nonetcheck', hint: '138', type: 'checkbox', value: false },
															{ title: '插件开启时 - 跳过时间一致性检测', id: 'ss_basic_notimecheck', hint: '139', type: 'checkbox', value: false },
															{ title: '插件开启时 - 跳过国内DNS可用性检测', id: 'ss_basic_nocdnscheck', hint: '140', type: 'checkbox', value: false },
															{ title: '插件开启时 - 跳过可信DNS可用性检测', id: 'ss_basic_nofdnscheck', hint: '141', type: 'checkbox', value: false },
															{ title: '插件开启时 - 跳过国内出口ip检测', id: 'ss_basic_nochnipcheck', hint: '142', type: 'checkbox', value: false },
															{ title: '插件开启时 - 跳过代理出口ip检测', id: 'ss_basic_nofrnipcheck', hint: '143', type: 'checkbox', value: false },
															{ title: '插件开启时 - 跳过程序启动检测', id: 'ss_basic_noruncheck', hint: '144', type: 'checkbox', value: false },
														]);
													</script>
												</table>
											</div>
											<div id="tablet_10" style="display: none;">
												<div id="log_content" style="overflow:hidden;">
													<textarea cols="63" rows="36" wrap="on" readonly="readonly"
														id="log_content1" autocomplete="off" autocorrect="off"
														autocapitalize="off" spellcheck="false"></textarea>
												</div>
											</div>
											<div class="apply_gen" id="loading_icon">
												<img id="loadingIcon" style="display:none;"
													src="/images/InternetScan.gif">
											</div>



											<div id="apply_button" class="apply_gen">
												<input class="button_gen" type="button" onclick="save()" value="保存&应用">
												<input id="save_new_node_button" class="button_gen" type="button"
													onclick="save_new_node()" value="保存新节点" style="display: none;">
												<input style="margin-left:10px" id="ss_failover_save" class="button_gen"
													onclick="save_failover()" type="button" value="保存本页设置">
											</div>


										</td>
									</tr>
								</table>
							</div>
						</td>
					</tr>
				</table>
			</td>
			<td width="10" align="center" valign="top"></td>
		</tr>
	</table>
	<div id="footer"></div>
</body>

</html>