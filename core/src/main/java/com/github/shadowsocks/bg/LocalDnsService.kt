/*******************************************************************************
 *                                                                             *
 *  Copyright (C) 2017 by Max Lv <max.c.lv@gmail.com>                          *
 *  Copyright (C) 2017 by Mygod Studio <contact-shadowsocks-android@mygod.be>  *
 *                                                                             *
 *  This program is free software: you can redistribute it and/or modify       *
 *  it under the terms of the GNU General Public License as published by       *
 *  the Free Software Foundation, either version 3 of the License, or          *
 *  (at your option) any later version.                                        *
 *                                                                             *
 *  This program is distributed in the hope that it will be useful,            *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of             *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the              *
 *  GNU General Public License for more details.                               *
 *                                                                             *
 *  You should have received a copy of the GNU General Public License          *
 *  along with this program. If not, see <http://www.gnu.org/licenses/>.       *
 *                                                                             *
 *******************************************************************************/

package com.github.shadowsocks.bg

import com.github.shadowsocks.Core
import com.github.shadowsocks.Core.app
import com.github.shadowsocks.acl.Acl
import com.github.shadowsocks.net.HostsFile
import com.github.shadowsocks.preference.DataStore
import com.github.shadowsocks.utils.asIterable
import com.github.shadowsocks.utils.parseNumericAddress
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.Inet4Address
import java.net.Inet6Address

object LocalDnsService {
    interface Interface : BaseService.Interface {
        override suspend fun startProcesses(hosts: HostsFile) {
            super.startProcesses(hosts)
            val data = data
            val profile = data.proxy!!.profile
            val acl = if (profile.route == Acl.ALL) null else Acl().fromReader(Acl.getFile(profile.route).bufferedReader())
            val remotedns = acl?.remoteDns
            val proxyDomains = File(Core.deviceStorage.noBackupFilesDir, "proxyDomains")
            val bypassDomains = File(Core.deviceStorage.noBackupFilesDir, "bypassDomains")
            val dotpattern = "(?:[Tt][Ll][Ss])://[\\w-.]+(:853)@((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3}".toRegex()

            if(acl!=null){
                for (domain in acl.proxyHostnames.asIterable()) {
                    proxyDomains.appendText("\n" + domain)
                }
                for (domain in acl.bypassHostnames.asIterable()) {
                    bypassDomains.appendText("\n" + domain)
                }
            }

            fun makeDns(name: String, address: String, timeout: Int, proxy: Boolean = true) = JSONObject().apply {
                put("Name", name)
                put("Address", when (address.parseNumericAddress()) {
                    is Inet6Address -> "[$address]:53"
                    is Inet4Address -> "$address:53"
                    else -> address
                })
                put("Timeout", timeout)
                put("EDNSClientSubnet", JSONObject().put("Policy", "disable"))
                if (proxy) {
                    put("Socks5Address", "127.0.0.1:${DataStore.portProxy}")
                }
                put("Protocol",
                        if (address.matches(dotpattern)) {
                            "tcp-tls"
                        } else if (proxy) {
                            "tcp"
                        } else {
                            "udp"
                        }
                )
            }

            fun buildOvertureConfig(file: String) = file.also {
                File(Core.deviceStorage.noBackupFilesDir, it).writeText(JSONObject().run {
                    put("BindAddress", "${DataStore.listenAddress}:${DataStore.portLocalDns}")
                    put("RedirectIPv6Record", true)
                    put("DomainBase64Decode", false)
                    put("HostsFile", "hosts")
                    put("MinimumTTL", 120)
                    put("CacheSize", 4096)
                    val remoteDns = JSONArray(profile.remoteDns.split(",")
                            .mapIndexed { i, dns -> makeDns("UserDef-Remote-$i", dns.trim(), 12) })
                    val directDns = JSONArray(profile.directDns.split(",")
                            .mapIndexed { i, dns -> makeDns("UserDef-Direct-$i", dns.trim(), 12, false) })
                    val localDns = JSONArray(arrayOf(
                            makeDns("Primary-1", "114.114.114.114:53", 9, false),
                            makeDns("Primary-2", "180.76.76.76:53", 9, false),
                            makeDns("Primary-3", "119.29.29.29:53", 9, false)))
                    when (profile.route) {
                        Acl.BYPASS_CHN, Acl.BYPASS_LAN_CHN, Acl.GFWLIST -> {
                            put("PrimaryDNS", directDns ?: localDns)
                            put("AlternativeDNS", remoteDns)
                            put("IPNetworkFile", JSONObject(mapOf("Primary" to "china_ip_list.txt")))
                            put("DomainFile", JSONObject(mapOf("Primary" to "bypassDomains", "Alternative" to "proxyDomains")))
                        }
                        Acl.CUSTOM_RULES -> {
                            if (remotedns!!) {
                                put("PrimaryDNS", remoteDns)
                                // no need to setup AlternativeDNS in Acl.ALL/BYPASS_LAN mode
                                put("OnlyPrimaryDNS", true)
                            } else {
                                put("PrimaryDNS", directDns ?: localDns)
                                put("AlternativeDNS", remoteDns)
                                put("IPNetworkFile", JSONObject(mapOf("Primary" to "china_ip_list.txt")))
                                put("DomainFile", JSONObject(mapOf("Primary" to "bypassDomains", "Alternative" to "proxyDomains")))
                            }
                        }
                        Acl.CHINALIST -> {
                            val primary = directDns ?: localDns
                            for (i in 0 until primary.length()) {
                                primary.getJSONObject(i).put("Socks5Address", "")
                            }
                            for (i in 0 until remoteDns.length()) {
                                remoteDns.getJSONObject(i).put("Socks5Address", "127.0.0.1:${DataStore.portProxy}")
                            }
                            put("PrimaryDNS", (directDns ?: localDns))
                            put("AlternativeDNS", remoteDns)
                        }
                        else -> {
                            put("PrimaryDNS", remoteDns)
                            // no need to setup AlternativeDNS in Acl.ALL/BYPASS_LAN mode
                            put("OnlyPrimaryDNS", true)
                        }
                    }
                    toString()
                })
            }

            data.processes!!.start(buildAdditionalArguments(arrayListOf(
                    File(app.applicationInfo.nativeLibraryDir, Executable.OVERTURE).absolutePath,
                    "-c", buildOvertureConfig("overture.conf"))))
        }
    }
}
