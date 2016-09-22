#################################################
#
#            HOMER & OpenSIPs
#
#################################################

log_level=4
log_stderror=no
log_facility=LOG_LOCAL0

children=4

listen=hep_udp:0.0.0.0:LISTEN_PORT
listen=hep_tcp:0.0.0.0:LISTEN_PORT


### CHANGEME path to your opensips modules here
mpath="/usr/lib/x86_64-linux-gnu/opensips/modules/"

loadmodule "cfgutils.so"
loadmodule "signaling.so"
loadmodule "sl.so"
loadmodule "tm.so"
loadmodule "rr.so"
loadmodule "maxfwd.so"
loadmodule "sipmsgops.so"
loadmodule "mi_fifo.so"
loadmodule "uri.so"
loadmodule "db_mysql.so"
loadmodule "sipcapture.so"
loadmodule "proto_hep.so"
loadmodule "cachedb_local.so"
loadmodule "avpops.so"
loadmodule "mmgeoip.so"
loadmodule "exec.so"
loadmodule "json.so"
loadmodule "statistics.so"
loadmodule "rest_client.so"

#settings

### CHANGEME hep interface
# should be loaded After proto_hep

#Cache
modparam("cachedb_local", "cache_table_size", 10)
modparam("cachedb_local", "cache_clean_period", 600)

modparam("tm", "fr_timeout", 2)
modparam("tm", "fr_inv_timeout", 3)
modparam("tm", "restart_fr_on_each_reply", 0)
modparam("tm", "onreply_avp_mode", 1)

#### Record Route Module
/* do not append from tag to the RR (no need for this script) */
modparam("rr", "append_fromtag", 0)

#### FIFO Management Interface

modparam("mi_fifo", "fifo_name", "/tmp/opensips_fifo")
modparam("mi_fifo", "fifo_mode", 0666)

#### SIP MSG OPerationS module
#### URI module
#### MAX ForWarD module

modparam("uri", "use_uri_table", 0)

### CHANGEME mysql uri here if you do sip_capture()
modparam("sipcapture", "db_url", "mysql://DB_USER:DB_PASS@DB_HOST/homer_data")
modparam("sipcapture", "capture_on", 1)
modparam("sipcapture", "hep_capture_on", 1)
modparam("sipcapture", "hep_route", "my_hep_route")


### hep version here 1, 2 or 3
#modparam("proto_hep", "hep_version", 3)

#
modparam("avpops","db_url","mysql://DB_USER:DB_PASS@DB_HOST/homer_statistic")


modparam("mmgeoip", "mmgeoip_city_db_path", "/usr/share/GeoIP/GeoIP.dat")


route{

	update_stat("method::total", "+1");
	update_stat("packet::count", "+1");
	cache_add("local", "packet::size", $ml, 320); # TODO: add variable increment?

	# XXX: isn't t_check_trans() more elegant/fast?
	if(cache_fetch("local","msg:$rm::$cs::$ci",$var(tmpvar))) {
		xlog("TEST: $var(tmpvar)\n");
		route(STORE);
		exit;
	}

	cache_store("local", "msg:$rm::$cs::$ci", "yes", 320);
	update_stat("method::all", "+1");


	if (is_method("INVITE|REGISTER")) {

		if($ua =~ "(friendly-scanner|sipvicious|sipcli)") {
			avp_db_query("INSERT INTO alarm_data_mem (create_date, type, total, source_ip, description) VALUES(NOW(), 'scanner', 1, '$si', 'Friendly scanner alarm!') ON DUPLICATE KEY UPDATE total=total+1");
			route(KILL_VICIOUS);
		}

		#IP Method
		avp_db_query("INSERT INTO stats_ip_mem ( method, source_ip, total) VALUES('$rm', '$si', 1) ON DUPLICATE KEY UPDATE total=total+1");

		#GEO
		if(mmg_lookup("lon:lat","$si","$avp(lat_lon)")) {
			avp_db_query("INSERT INTO stats_geo_mem ( method, country, lat, lon, total) VALUES('$rm', '$(avp(lat_lon)[3])', '$(avp(lat_lon)[0])', '$(avp(lat_lon)[1])', 1) ON DUPLICATE KEY UPDATE total=total+1");
		};


		if (is_method("INVITE")) {

		        if (has_totag()) {
				update_stat("method::reinvite", "+1");
			}
			else {
				update_stat("method::invite", "+1");
				if($adu != "") {
					update_stat("method::invite::auth", "+1");
				}

				if($ua != "") {
					avp_db_query("INSERT INTO stats_useragent_mem (useragent, method, total) VALUES('$ua', 'INVITE', 1) ON DUPLICATE KEY UPDATE total=total+1");
				}

			}
		}
		else {
			update_stat("method::register", "+1");

			if($adu != "") {
				update_stat("method::register::auth", "+1");
			}

			if($ua != "") {
				avp_db_query("INSERT INTO stats_useragent_mem (useragent, method, total) VALUES('$ua', 'REGISTER', 1) ON DUPLICATE KEY UPDATE total=total+1");
			}
		}
	}

	else if(is_method("BYE")) {

		update_stat("method::bye", "+1");

		if(is_present_hf("Reason")) {
                       $var(cause) = $(hdr(Reason){param.value,cause}{s.int});
                       if($var(cause) != 16 && $var(cause) !=17) {
				update_stat("stats::sdf", "+1");
		       }
		}

	}
	else if(is_method("CANCEL")) {
		update_stat("method::cancel", "+1");
	}
	else if(is_method("OPTIONS")) {
		update_stat("method::options", "+1");
	}
	else if(is_method("REFER")) {
		update_stat("method::refer", "+1");
	}
	else if(is_method("UPDATE")) {
		update_stat("method::update", "+1");
	}
	else if(is_method("PUBLISH"))
        {
                if(has_body("application/vq-rtcpxr") && $(rb{s.substr,0,1}) != "x") {
                        $var(table) = "report_capture";
			$var(reg) = "/.*CallID:((\d|\-|\w|\@){5,120}).*$/\1/s";
                        $var(callid) = $(rb{re.subst,$var(reg)});
			#Local IP. Only for stats
			xlog("PUBLISH: $var(callid)\n");
			report_capture("report_capture", "$var(callid)", "1");
                        drop;
                }
        }

	else if(is_method("ACK")) {
		update_stat("method::ack", "+1");
        }
        else {
		update_stat("method::unknown", "+1");
        }

	#Store
	route(STORE);
	exit;

}

onreply_route {

	update_stat("method::total", "+1");

	if(cache_fetch("local","msg:$rs::$cs::$rm::$ci",$var(tmpvar))) {
		xlog("TEST: $var(tmpvar)\n");
		route(STORE);
		exit;
	}

	cache_store("local", "msg:$rs::$cs::$rm::$ci", "yes", 320);
	update_stat("method::all", "+1");

	#413 Too large
	if(status == "413") {
		update_stat("response::413", "+1");
                update_stat("alarm::413", "+1");
	}
	#403 Unauthorize
        else if(status == "403") {
		update_stat("response::403", "+1");
                update_stat("alarm::403", "+1");
        }
	# Too many hops
	else if(status == "483") {
		update_stat("response::483", "+1");
                update_stat("alarm::483", "+1");
	}
	# loops
	else if(status == "482") {
		update_stat("response::482", "+1");
                update_stat("alarm::482", "+1");
	}
	# Call Transaction Does not exist
	else if(status == "481") {
                update_stat("alarm::481", "+1");
	}
	# 408 Timeout
	else if(status == "408") {
                update_stat("alarm::408", "+1");
	}
	# 400
	else if(status == "400") {
                update_stat("alarm::400", "+1");
	}
	# MOVED
	else if(status =~ "^(30[012])$") {
                update_stat("response::300", "+1");
	}

	if($rm == "INVITE") {
		#ISA
		if(status =~ "^(408|50[03])$") {
	                update_stat("stats::isa", "+1");
		}
		#Bad486
		if(status =~ "^(486|487|603)$") {
	                update_stat("stats::bad::invite", "+1");
		}

		#SD
		if(status =~ "^(50[034])$") {
	                update_stat("stats::sd", "+1");
		}

		if(status == "407") {
	                update_stat("response::407::invite", "+1");
		}
		else if(status == "401") {
	                update_stat("response::401::invite", "+1");
		}
		else if(status == "200") {
	                update_stat("response::200::invite", "+1");
		}
		#Aditional stats
	        else if(status == "100") {
	                update_stat("response::100::invite", "+1");
                }
                else if(status == "180") {
	                update_stat("response::180::invite", "+1");
                }
                else if(status == "183") {
	                update_stat("response::183::invite", "+1");
                }
	}
	else if($rm == "BYE") {

		if(status == "407") {
	                update_stat("response::407::bye", "+1");
		}
		else if(status == "401") {
	                update_stat("response::401::bye", "+1");
		}
		else if(status == "200") {
	                update_stat("response::200::bye", "+1");
		}
	}

	#Store
	route(STORE);
	drop;
}

route[KILL_VICIOUS] {
	xlog("Kill-Vicious ! si : $si ru : $ru ua : $ua\n");
	return;
}



timer_route[stats_alarms_update, 60] {

	#xlog("timer routine: time is $Ts\n");
	route(CHECK_ALARM);
	#Check statistics
	route(CHECK_STATS);

}

route[SEND_ALARM] {
	exec('echo "Value: $var(thvalue), Type: $var(atype), Desc: $var(aname)" | mail -s "Homer Alarm $var(atype) - $var(thvalue)" $var(aemail) ') ;
}

route[CHECK_ALARM]
{

	#POPULATE ALARM THRESHOLDS
	#Homer 5 sql schema
	avp_db_query("SELECT type,value,name,notify,email FROM alarm_config WHERE NOW() between startdate AND stopdate AND active = 1", "$avp(type);$avp(value);$avp(name);$avp(notify);$avp(email)");
	$var(i) = 0;
	while ( $(avp(type)[$var(i)]) != NULL )
	{
		$var(atype) = $(avp(type)[$var(i)]);
		$var(avalue) = $(avp(value)[$var(i)]);
		$var(aname) = $(avp(name)[$var(i)]);
		$var(anotify) = $(avp(notify)[$var(i)]);
		$var(aemail) = $(avp(email)[$var(i)]);
		$avp($var(atype)) = $var(avalue);

		$var(anotify) = $(var(anotify){s.int});

		if($stat(alarm::$var(atype)) != NULL) {
			$var(thvalue) = $stat(alarm::$var(atype));
			$stat(alarm::$var(atype)) = 0;

			#If Alarm - go here
			if($var(thvalue) > $var(avalue)) {

				avp_db_query("INSERT INTO alarm_data (create_date, type, total, description) VALUES(NOW(), '$var(aname)', $var(thvalue), '$var(aname) - $var(atype)');");
				#Notif
				if($var(anotify) == 1) {
					route(SEND_ALARM);
				}
			}

			#Alarm for Scanner;
			if($var(atype) == "scanner") {
				avp_db_query("DELETE FROM alarm_data_mem WHERE type='scanner' AND total < $var(avalue)");
				if($var(anotify) == 1)
				{
					avp_db_query("SELECT * FROM alarm_data_mem WHERE type='scanner' AND total  >= $var(avalue) LIMIT 2", "$avp(as)");
					if($(avp(as){s.int}) > 0) {
						route(SEND_ALARM);
					}
				}
			}
		}

		$var(i) = $var(i) + 1;
	}

	avp_db_query("DELETE FROM alarm_data WHERE create_date < DATE_SUB(NOW(), INTERVAL 5 DAY)");
}


route[CHECK_STATS] {

	#xlog("TIMER UPDATE\n");
	#SQL STATS

	$var(interval) = 5;
	$var(tz) = $ctime(min);
	$var(tm) = ($ctime(min) % 10);

	#xlog("TIMER MIN: $var(tz) $var(tm)\n");

	if($var(tm) != 0 && $var(tm) != $var(interval)) return;

	#xlog("TIMER IN: $var(tz)  $var(tm)\n");

	$var(t1) = $Ts;
	$var(t2) = $var(t1) - (30*60);

	$var(t_date) = "FROM_UNIXTIME(" + $var(t1) + ", '%Y-%m-%d %H:%i:00')";
	$var(f_date) = "FROM_UNIXTIME(" + $var(t2) + ", '%Y-%m-%d %H:%i:00')";

	$var(body) = "";
	$var(isotime) = $time(%Y-%m-%dT%TZ);
	$var(today) = $time(%d.%m.%Y);
	$var(host) = "homer5"; # TODO change with something appropriate

	#ALARM SCANNERS
	avp_db_query("INSERT INTO alarm_data (create_date, type, total, source_ip, description) SELECT create_date, type, total, source_ip, description FROM alarm_data_mem;");
	avp_db_query("TRUNCATE TABLE alarm_data_mem");

	#STATS Useragent
	avp_db_query("INSERT INTO stats_useragent (from_date, to_date, useragent, method, total) SELECT $var(f_date) as from_date, $var(t_date) as to_date, useragent, method, total FROM stats_useragent_mem;");
	avp_db_query("TRUNCATE TABLE stats_useragent_mem");

	#STATS IP
	avp_db_query("INSERT INTO stats_ip (from_date, to_date, method, source_ip, total) SELECT $var(f_date) as from_date, $var(t_date) as to_date, method, source_ip, total FROM stats_ip_mem;");
	avp_db_query("TRUNCATE TABLE stats_ip_mem");

	avp_db_query("INSERT INTO stats_geo (from_date, to_date, method, country, lat, lon, total) SELECT $var(f_date) as from_date, $var(t_date) as to_date, method, country, lat, lon, total FROM stats_geo_mem;");
	avp_db_query("TRUNCATE TABLE stats_geo_mem");

	#Packet HEP stats
	$var(stats_start) = "{\"index\":{\"_index\":\"homer-" + $var(today) +
		"\",\"_type\":\"stats_data\"}}\n{\"host\":\"" + $var(host) +
		"\",\"timestamp\":\"" + $var(isotime) + "\",\"name\":";

	if($stat(packet::count) != NULL && $stat(packet::count) > 0) {
		$var(stat) = "\"packet_count\",\"value\":" + $stat(packet::count) + "}\n";
		$var(body) = $var(body) + $var(stats_start) + $var(stat);
		$stat(packet::count) = 0;
	}
	if(cache_fetch("local","packet::size",$var(tmpvar))) {
		$var(stat) = "\"packet_size\",\"bytes\":" + $var(tmpvar) + "}\n";
		$var(body) = $var(body) + $var(stats_start) + $var(stat);
		cache_remove("local","packet::size");
	}

	#SDF
	if($stat(stats::sdf) != NULL && $stat(stats::sdf) > 0) {
		$var(stat) = "\"sdf\",\"value\":" + $stat(stats::sdf) + "}\n";
		$var(body) = $var(body) + $var(stats_start) + $var(stat);
		$stat(stats::sdf) = 0;
	}

	#ISA
	if($stat(stats::isa) != NULL && $stat(stats::isa) > 0) {
		$var(stat) = "\"isa\",\"value\":" + $stat(stats::isa) + "}\n";
		$var(body) = $var(body) + $var(stats_start) + $var(stat);
		$stat(stats::isa) = 0;
	}

	#SD
	if($stat(stats::sd) != NULL && $stat(stats::sd) > 0) {
		$var(stat) = "\"sd\",\"value\":" + $stat(stats::sd) + "}\n";
		$var(body) = $var(body) + $var(stats_start) + $var(stat);
		$stat(stats::sd) = 0;
	}

	#SSR
	if($stat(stats::ssr) != NULL && $stat(stats::ssr) > 0) {
		$var(stat) = "\"ssr\",\"value\":" + $stat(stats::ssr) + "}\n";
		$var(body) = $var(body) + $var(stats_start) + $var(stat);
		$stat(stats::ssr) = 0;
	}

	#ASR
	$var(asr) = 0;
	$var(ner) = 0;
	if($stat(method::invite) != NULL && $stat(method::invite) > 0) {
		if ($stat(response::407) == NULL) $stat(response::407) = 0;
		if ($stat(response::200) == NULL) $stat(response::200) = 0;
		if ($stat(response::bad) == NULL) $stat(response::bad) = 0;

		$var(d) = $stat(method::invite) - $stat(response::407);
		if($var(d) > 0) {
			$var(asr) =  $stat(response::200) * 100 / $var(d);
			if($var(asr) > 100)  $var(asr) = 100;
			$var(ner) = ($stat(response::200) + $stat(response::bad)) * 100 / $var(d);
			if($var(ner) > 100)  $var(ner) = 100;
		}
	}

	#Stats DATA
	$var(stat) = "\"asr\",\"value\":" + $var(asr) + "}\n";
	$var(body) = $var(body) + $var(stats_start) + $var(stat);

	$var(stat) = "\"ner\",\"value\":" + $var(ner) + "}\n";
	$var(body) = $var(body) + $var(stats_start) + $var(stat);

	# TODO: decide whether we should send now or wait to gather everything
	route(TO_ES);

	#Packet Methods stats
	$var(stats_start) = "{\"index\":{\"_index\":\"homer-" + $var(today) +
		"\",\"_type\":\"stats_method\"}}\n{\"host\":\"" + $var(host) +
		"\",\"timestamp\":\"" + $var(isotime) + "\",\"method\":";

	#INVITE
	if($stat(method::reinvite) != NULL && $stat(method::reinvite) > 0) {
		$var(stat) = "\"INVITE\",\"totag\":true,\"value\":" +
			$stat(method::reinvite) + "}\n";
		$var(body) = $var(body) + $var(stats_start) + $var(stat);
		$stat(method::reinvite) = 0;
	}

	#INVITE
	if($stat(method::invite) != NULL && $stat(method::invite) > 0) {
		$var(stat) = "\"INVITE\",\"value\":" + $stat(method::invite) + "}\n";
		$var(body) = $var(body) + $var(stats_start) + $var(stat);
		$stat(method::invite) = 0;
	}

	#INVITE AUTH
	if($stat(method::invite::auth) != NULL && $stat(method::invite::auth) > 0) {
		$var(stat) = "\"INVITE\",\"auth\":true,\"value\":" +
			$stat(method::invite::auth) + "}\n";
		$var(body) = $var(body) + $var(stats_start) + $var(stat);
		$stat(method::invite::auth) = 0;
	}

	#REGISTER
	if($stat(method::register) != NULL && $stat(method::register) > 0) {
		$var(stat) = "\"REGISTER\",\"value\":" + $stat(method::register) + "}\n";
		$var(body) = $var(body) + $var(stats_start) + $var(stat);
		$stat(method::register) = 0;
	}

	#REGISTER AUTH
	if($stat(method::register::auth) != NULL && $stat(method::register::auth) > 0) {
		$var(stat) = "\"REGISTER\",\"auth\":true,\"value\":" +
			$stat(method::register::auth) + "}\n";
		$var(body) = $var(body) + $var(stats_start) + $var(stat);
		$stat(method::register::auth) = 0;
	}

	#BYE
	if($stat(method::bye) != NULL && $stat(method::bye) > 0) {
		$var(stat) = "\"BYE\",\"value\":" + $stat(method::bye) + "}\n";
		$var(body) = $var(body) + $var(stats_start) + $var(stat);
		$stat(method::bye) = 0;
	}

	#CANCEL
	if($stat(method::cancel) != NULL && $stat(method::cancel) > 0) {
		$var(stat) = "\"CANCEL\",\"value\":" + $stat(method::cancel) + "}\n";
		$var(body) = $var(body) + $var(stats_start) + $var(stat);
		$stat(method::bye) = 0;
	}

	#OPTIONS
	if($stat(method::options) != NULL && $stat(method::options) > 0) {
		$var(stat) = "\"OPTIONS\",\"value\":" + $stat(method::options) + "}\n";
		$var(body) = $var(body) + $var(stats_start) + $var(stat);
		$stat(method::options) = 0;
	}

	if($stat(method::unknown) != NULL && $stat(method::unknown) > 0) {
		$var(stat) = "\"UNKNOWN\",\"value\":" + $stat(method::unknown) + "}\n";
		$var(body) = $var(body) + $var(stats_start) + $var(stat);
		$stat(method::unknown) = 0;
	}

	#ACK
	if($stat(method::ack) != NULL && $stat(method::ack) > 0) {
		$var(stat) = "\"ACK\",\"value\":" + $stat(method::ack) + "}\n";
		$var(body) = $var(body) + $var(stats_start) + $var(stat);
		$stat(method::ack) = 0;
	}

	#REFER
	if($stat(method::refer) != NULL && $stat(method::refer) > 0) {
		$var(stat) = "\"REFER\",\"value\":" + $stat(method::refer) + "}\n";
		$var(body) = $var(body) + $var(stats_start) + $var(stat);
		$stat(method::refer) = 0;
	}

	#UPDATE
	if($stat(method::update) != NULL && $stat(method::update) > 0) {
		$var(stat) = "\"UPDATE\",\"value\":" + $stat(method::update) + "}\n";
		$var(body) = $var(body) + $var(stats_start) + $var(stat);
		$stat(method::update) = 0;
	}

	route(TO_ES);

	#RESPONSE
	#300
	if($stat(response::300) != NULL && $stat(response::300) > 0) {
		$var(stat) = "\"300\",\"value\":" + $stat(response::300) + "}\n";
		$var(body) = $var(body) + $var(stats_start) + $var(stat);
		$stat(response::300) = 0;
	}

	#407 INVITE
	if($stat(response::407::invite) != NULL && $stat(response::407::invite) > 0) {
		$var(stat) = "\"407\",\"cseq\":\"INVITE\",\"value\":" +
			$stat(response::407::invite) + "}\n";
		$var(body) = $var(body) + $var(stats_start) + $var(stat);
		$stat(response::407::invite) = 0;
	}

	#401 INVITE
	if($stat(response::401::invite) != NULL && $stat(response::401::invite) > 0) {
		$var(stat) = "\"401\",\"cseq\":\"INVITE\",\"value\":" +
			$stat(response::401::invite) + "}\n";
		$var(body) = $var(body) + $var(stats_start) + $var(stat);
		$stat(response::401::invite) = 0;
	}

	#100 INVITE
	if($stat(response::100::invite) != NULL && $stat(response::100::invite) > 0) {
		$var(stat) = "\"100\",\"cseq\":\"INVITE\",\"value\":" +
			$stat(response::100::invite) + "}\n";
		$var(body) = $var(body) + $var(stats_start) + $var(stat);
		$stat(response::100::invite) = 0;
	}

	#180 INVITE
	if($stat(response::180::invite) != NULL && $stat(response::180::invite) > 0) {
		$var(stat) = "\"180\",\"cseq\":\"INVITE\",\"value\":" +
			$stat(response::180::invite) + "}\n";
		$var(body) = $var(body) + $var(stats_start) + $var(stat);
		$stat(response::180::invite) = 0;
	}

	#183 INVITE
	if($stat(response::183::invite) != NULL && $stat(response::183::invite) > 0) {
		$var(stat) = "\"183\",\"cseq\":\"INVITE\",\"value\":" +
			$stat(response::183::invite) + "}\n";
		$var(body) = $var(body) + $var(stats_start) + $var(stat);
		$stat(response::183::invite) = 0;
	}

	#200 INVITE
	if($stat(response::200::invite) != NULL && $stat(response::200::invite) > 0) {
		$var(stat) = "\"200\",\"cseq\":\"INVITE\",\"value\":" +
			$stat(response::200::invite) + "}\n";
		$var(body) = $var(body) + $var(stats_start) + $var(stat);
		$stat(response::200::invite) = 0;
	}

	#407 BYE
	if($stat(response::407::bye) != NULL && $stat(response::407::bye) > 0) {
		$var(stat) = "\"407\",\"cseq\":\"BYE\",\"value\":" +
			$stat(response::407::bye) + "}\n";
		$var(body) = $var(body) + $var(stats_start) + $var(stat);
		$stat(response::407::bye) = 0;
	}

	#401 BYE
	if($stat(response::401::bye) != NULL && $stat(response::401::bye) > 0) {
		$var(stat) = "\"401\",\"cseq\":\"BYE\",\"value\":" +
			$stat(response::401::bye) + "}\n";
		$var(body) = $var(body) + $var(stats_start) + $var(stat);
		$stat(response::401::bye) = 0;
	}

	#200 BYE
	if($stat(response::200::bye) != NULL && $stat(response::200::bye) > 0) {
		$var(stat) = "\"200\",\"cseq\":\"BYE\",\"value\":" +
			$stat(response::200::bye) + "}\n";
		$var(body) = $var(body) + $var(stats_start) + $var(stat);
		$stat(response::200::bye) = 0;
	}

	#ALL TRANSACTIONS MESSAGES
	if($stat(method::all) != NULL && $stat(method::all) > 0) {
		$var(stat) = "\"ALL\",\"value\":" + $stat(method::all) + "}\n";
		$var(body) = $var(body) + $var(stats_start) + $var(stat);
		$stat(method::all) = 0;
	}

	#ALL MESSAGES ON INTERFACE
	if($stat(method::total) != NULL && $stat(method::total) > 0) {
		$var(stat) = "\"TOTAL\",\"value\":" + $stat(method::total) + "}\n";
		$var(body) = $var(body) + $var(stats_start) + $var(stat);
		$stat(method::total) = 0;
	}

	route(TO_ES);
}

route[TO_ES] {

	# perform all the inserts as bulk
	rest_post("ES_URL/_bulk", "$var(body)",
			"application/json; charset=UTF-8",
			"$var(ret_body)", ,
			"$var(ret_code)");
	if ($rc < 0)
		xlog("L_ERR", "ElasticSearch replied with $var(ret_code): [$var(ret_body)]\n");
	$var(body) = "";
}


route[STORE] {

	if($rm == "REGISTER") {
		$var(table) = "sip_capture_registration";
	}
	else if($rm =~ "(INVITE|UPDATE|BYE|ACK|PRACK|REFER|CANCEL)$")
	{
		$var(table) = "sip_capture_call";
	}
	else if($rm =~ "(NOTIFY)$" && is_present_hf("Event") && $hdr(Event)=~"refer;")
	{
		$var(table) = "sip_capture_call";
	}
	else if($rm =~ "(INFO)$")
	{
		$var(table) = "sip_capture_call";
	}
	else if($rm =~ "(OPTIONS)$" )
	{
		$var(table) = "sip_capture_rest";
	}
	else {
		$var(table) = "sip_capture_rest";
	}

	#$var(utc) = "%Y%m%d";

	if($var(table) == "sip_capture_call") sip_capture("sip_capture_call_%Y%m%d");
	else if($var(table) == "sip_capture_registration") sip_capture("sip_capture_registration_%Y%m%d");
	else sip_capture("sip_capture_rest_%Y%m%d");
}


route[my_hep_route] {

	### hep_get([data type,] chunk_id, vendor_id_pvar, chunk_data_pvar)
	### data type is optional for most of the generic chunks
	### Full list here: http://www.opensips.org/html/docs/modules/2.2.x/sipcapture#hep_set_id

	#Protocol ID
	hep_get("11", "$var(vid)", "$var(data)");

	$var(proto) = $(var(data){s.int});

	#Logs Or Stats
	if($var(proto) == 100 || $var(proto) == 99) {

		#hep_set("uint8", "2", , "1");
		hep_get("utf8-string", "0x11", "$var(vid)", "$var(correlation_id)");
		report_capture("logs_capture", "$var(correlation_id)", "1");
		exit;
	}

	hep_resume_sip();

}
