package com.github.shadowsocks.job

import java.io.IOException
import java.net.URL
import java.util.concurrent.TimeUnit

import com.evernote.android.job.Job.{Params, Result}
import com.evernote.android.job.{Job, JobRequest}
import com.github.shadowsocks.ShadowsocksApplication.app
import com.github.shadowsocks.utils.CloseUtils._
import com.github.shadowsocks.utils.IOUtils

/**
  * @author Mygod
  */
object Acl4SSRJob {
  final val TAG = "Acl4SSRJob"

  def schedule(route: String) = new JobRequest.Builder(Acl4SSRJob.TAG + ':' + route)
    .setPeriodic(TimeUnit.HOURS.toMillis(1))
    .setRequirementsEnforced(true)
    .setRequiredNetworkType(JobRequest.NetworkType.UNMETERED)
    .setRequiresCharging(true)
    .setUpdateCurrent(true)
    .build().schedule()
}

class Acl4SSRJob(route: String) extends Job {
  override def onRunJob(params: Params): Result = {
    val filename = route + ".acl"
    try {
      if(route == "gfwlist-banAD" || route == "banAD" || route == "fullgfwlist" || route == "nobanAD" || route == "backcn-banAD" || route == "onlybanAD")
      {
        IOUtils.writeString(app.getApplicationInfo.dataDir + '/' + filename, autoClose(
          new URL("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/" +
            filename).openConnection().getInputStream())(IOUtils.readString))
      }
      Result.SUCCESS
    } catch {
      case e: IOException =>
        e.printStackTrace()
        Result.RESCHEDULE
      case e: Exception =>  // unknown failures, probably shouldn't retry
        e.printStackTrace()
        Result.FAILURE
    }
  }
}

