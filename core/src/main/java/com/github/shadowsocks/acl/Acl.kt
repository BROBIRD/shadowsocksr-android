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

package com.github.shadowsocks.acl

import android.content.Context
import androidx.recyclerview.widget.SortedList
import com.github.shadowsocks.Core
import com.github.shadowsocks.net.Subnet
import com.github.shadowsocks.preference.DataStore
import com.github.shadowsocks.utils.BaseSorter
import com.github.shadowsocks.utils.URLSorter
import com.github.shadowsocks.utils.asIterable
import kotlinx.coroutines.Job
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.runBlocking
import java.io.File
import java.io.IOException
import java.io.Reader
import java.net.URL
import java.net.URLConnection
import kotlin.coroutines.coroutineContext

class Acl {
    companion object {
        const val TAG = "Acl"
        const val ALL = "all"
        const val BYPASS_LAN = "bypass-lan"
        const val BYPASS_CHN = "bypass-china"
        const val BYPASS_LAN_CHN = "bypass-lan-china"
        const val GFWLIST = "gfwlist"
        const val CHINALIST = "china-list"
        const val CUSTOM_RULES = "custom-rules"

        fun getFile(id: String, context: Context = Core.deviceStorage) = File(context.noBackupFilesDir, "$id.acl")

        suspend fun <T> parse(reader: Reader, bypassHostnames: (String) -> T, proxyHostnames: (String) -> T,
                              urls: ((URL) -> T)? = null, defaultBypass: Boolean = false, defaultRemoteDns: Boolean = false): Triple<Boolean, Boolean, List<Subnet>> {
            var bypass = defaultBypass
            var remoteDns = defaultRemoteDns
            val bypassSubnets = mutableListOf<Subnet>()
            val proxySubnets = mutableListOf<Subnet>()
            var hostnames: ((String) -> T)? = if (defaultBypass) proxyHostnames else bypassHostnames
            var subnets: MutableList<Subnet>? = if (defaultBypass) proxySubnets else bypassSubnets
            reader.useLines {
                for (line in it) {
                    coroutineContext[Job]!!.ensureActive()
                    val input = if (line.startsWith("#")) continue else line.trim()
                    if (input.getOrNull(0) == '[') when (input) {
                        "[outbound_block_list]" -> {
                            hostnames = null
                            subnets = null
                        }
                        "[black_list]", "[bypass_list]" -> {
                            hostnames = bypassHostnames
                            subnets = bypassSubnets
                        }
                        "[white_list]", "[proxy_list]" -> {
                            hostnames = proxyHostnames
                            subnets = proxySubnets
                        }
                        "[reject_all]", "[bypass_all]" -> bypass = true
                        "[accept_all]", "[proxy_all]" -> bypass = false
                        "[remote_dns]" -> remoteDns = true
                        else -> error("Unrecognized block: $input")
                    } else if (subnets != null && input.isNotEmpty()) {
                        val subnet = Subnet.fromString(input)
                        if (subnet == null) hostnames!!(input) else subnets!!.add(subnet)
                    }
                }
            }
            return Triple(bypass, remoteDns, if (bypass) proxySubnets else bypassSubnets)
        }

        suspend fun createCustom(connect: suspend (URL) -> URLConnection) {
            val file = getFile(CUSTOM_RULES)
            if (file.exists()) return
            connect(URL(DataStore.aclUrl)).getInputStream().copyTo(file.outputStream())
        }
    }


    private open class DefaultSorter<T : Comparable<T>> : BaseSorter<T>() {
        override fun compareNonNull(o1: T, o2: T): Int = o1.compareTo(o2)
    }

    private object StringSorter : DefaultSorter<String>()
    private object SubnetSorter : DefaultSorter<Subnet>()

    val bypassHostnames = SortedList(String::class.java, StringSorter)
    val proxyHostnames = SortedList(String::class.java, StringSorter)
    val subnets = SortedList(Subnet::class.java, SubnetSorter)
    val urls = SortedList(URL::class.java, URLSorter)
    var bypass = false
    var remoteDns = false

    fun fromAcl(other: Acl): Acl {
        bypassHostnames.clear()
        for (item in other.bypassHostnames.asIterable()) bypassHostnames.add(item)
        proxyHostnames.clear()
        for (item in other.proxyHostnames.asIterable()) proxyHostnames.add(item)
        subnets.clear()
        for (item in other.subnets.asIterable()) subnets.add(item)
        urls.clear()
        for (item in other.urls.asIterable()) urls.add(item)
        bypass = other.bypass
        remoteDns = other.remoteDns
        return this
    }

    fun fromReader(reader: Reader, defaultBypass: Boolean = false, remoteDns: Boolean = false): Acl {
        bypassHostnames.clear()
        proxyHostnames.clear()
        subnets.clear()
        urls.clear()
        val (bypass, remotedns, subnets) = runBlocking {
            parse(reader, bypassHostnames::add, proxyHostnames::add, urls::add, defaultBypass, remoteDns)
        }
        this.bypass = bypass
        this.remoteDns = remotedns
        for (item in subnets) this.subnets.add(item)
        return this
    }

    fun fromId(id: String): Acl = try {
        fromReader(getFile(id).bufferedReader())
    } catch (_: IOException) {
        this
    }

}

