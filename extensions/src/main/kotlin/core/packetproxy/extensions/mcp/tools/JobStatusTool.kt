package packetproxy.extensions.mcp.tools

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import packetproxy.model.Configs
import packetproxy.model.Packet
import packetproxy.model.Packets
import packetproxy.util.log

/** ジョブの状況を取得するツール */
class JobStatusTool(private val packets: Packets, configs: Configs) :
  AuthenticatedMCPTool(configs) {

  override fun getName(): String = "get_job_status"

  override fun getDescription(): String =
    "Get status information for jobs created by send tools (resend_packet/bulk_send/call_vulcheck_helper). " +
      "Returns job details including request/response packet counts and completion status."

  override fun getInputSchema(): JsonObject {
    var schema = JsonObject()

    var jobIdProp = JsonObject()
    jobIdProp.addProperty("type", "string")
    jobIdProp.addProperty(
      "description",
      "Job ID to get status for. If not provided, returns status for all jobs.",
    )
    schema.add("job_id", jobIdProp)

    return addAccessTokenToSchema(schema)
  }

  @Throws(Exception::class)
  override fun executeAuthenticated(arguments: JsonObject): JsonObject {
    log("JobStatusTool called with arguments: " + getSafeArgumentsString(arguments))

    var jobId = if (arguments.has("job_id")) arguments.get("job_id").getAsString() else null

    if (jobId != null && !jobId.trim().isEmpty()) {
      // 特定のジョブの詳細を取得
      return getJobDetail(jobId)
    }
    // 全ジョブの概要を取得
    return getAllJobsStatus()
  }

  /** 特定のジョブの詳細情報を取得 */
  @Throws(Exception::class)
  private fun getJobDetail(jobId: String): JsonObject {
    log("JobStatusTool: Getting detail for job $jobId")

    // job_idが一致するパケットを取得（メタデータのみで十分）
    var allPackets = packets.queryAllMetadata()
    var jobPackets = ArrayList<Packet>()

    log("JobStatusTool: Searching for job $jobId in " + allPackets.size + " total packets")

    for (packet in allPackets) {
      var packetJobId = packet.getJobId()
      if (packetJobId != null) {
        log("JobStatusTool: Packet " + packet.getId() + " has job_id: $packetJobId")
      }
      if (jobId == packetJobId) {
        jobPackets.add(packet)
        log("JobStatusTool: Found matching packet " + packet.getId() + " for job $jobId")
      }
    }

    log("JobStatusTool: Found " + jobPackets.size + " packets for job $jobId")

    if (jobPackets.isEmpty()) {
      throw IllegalArgumentException("Job not found: $jobId")
    }

    // temporary_id ごとにパケットを整理
    var jobRequests = HashMap<String, JobRequest>()

    for (packet in jobPackets) {
      var temporaryId = packet.getTemporaryId()
      if (temporaryId == null || temporaryId.trim().isEmpty()) {
        continue
      }

      var jobRequest = jobRequests.computeIfAbsent(temporaryId) { JobRequest() }
      jobRequest.setTemporaryId(temporaryId)

      if (packet.getDirection() == Packet.Direction.CLIENT) {
        // リクエストパケット
        jobRequest.requestPacketId = packet.getId()
        jobRequest.hasRequest = true
      } else if (packet.getDirection() == Packet.Direction.SERVER) {
        // レスポンスパケット
        jobRequest.responsePacketId = packet.getId()
        jobRequest.hasResponse = true
      }
    }

    // 結果を構築
    var result = JsonObject()
    result.addProperty("job_id", jobId)
    result.addProperty("total_requests", jobRequests.size)

    var requestsSent = 0
    var responsesReceived = 0

    for (jobRequest in jobRequests.values) {
      if (jobRequest.hasRequest) {
        requestsSent++
      }
      if (jobRequest.hasResponse) {
        responsesReceived++
      }
    }

    result.addProperty("requests_sent", requestsSent)
    result.addProperty("responses_received", responsesReceived)

    // ジョブの状態を判定
    var status =
      if (requestsSent == 0) {
        "created"
      } else if (requestsSent < jobRequests.size) {
        "sending_requests"
      } else if (responsesReceived == 0) {
        "requests_sent"
      } else if (responsesReceived < requestsSent) {
        "receiving_responses"
      } else {
        "completed"
      }
    result.addProperty("status", status)

    // 各リクエストの詳細
    var requestsArray = JsonArray()
    for (jobRequest in jobRequests.values) {
      var reqObj = JsonObject()
      reqObj.addProperty("temporary_id", jobRequest.getTemporaryId())
      reqObj.addProperty("has_request", jobRequest.hasRequest)
      reqObj.addProperty("has_response", jobRequest.hasResponse)

      if (jobRequest.hasRequest) {
        reqObj.addProperty("request_packet_id", jobRequest.requestPacketId)
      }
      if (jobRequest.hasResponse) {
        reqObj.addProperty("response_packet_id", jobRequest.responsePacketId)
      }

      requestsArray.add(reqObj)
    }
    result.add("requests", requestsArray)

    log(
      "JobStatusTool: Job $jobId has $requestsSent requests sent, $responsesReceived" +
        " responses received, status: $status"
    )

    return result
  }

  /** 全ジョブの概要を取得 */
  @Throws(Exception::class)
  private fun getAllJobsStatus(): JsonObject {
    log("JobStatusTool: Getting status for all jobs")

    // 全パケットからjob_idが設定されているものを取得（メタデータのみで十分）
    var allPackets = packets.queryAllMetadata()
    var jobs = HashMap<String, JobSummary>()

    log("JobStatusTool: Total packets in database: " + allPackets.size)

    var packetsWithJobId = 0
    for (packet in allPackets) {
      var jobId = packet.getJobId()
      if (jobId == null || jobId.trim().isEmpty()) {
        continue
      }

      packetsWithJobId++
      log(
        "JobStatusTool: Found packet " +
          packet.getId() +
          " with job_id: $jobId, temporary_id: " +
          packet.getTemporaryId()
      )

      var jobSummary = jobs.computeIfAbsent(jobId) { JobSummary() }
      jobSummary.setJobId(jobId)

      var temporaryId = packet.getTemporaryId()
      if (temporaryId != null && !temporaryId.trim().isEmpty()) {
        jobSummary.temporaryIds.add(temporaryId)

        if (packet.getDirection() == Packet.Direction.CLIENT) {
          jobSummary.requestsSent++
        } else if (packet.getDirection() == Packet.Direction.SERVER) {
          jobSummary.responsesReceived++
        }
      }
    }

    log("JobStatusTool: Found $packetsWithJobId packets with job_id")

    // 結果を構築
    var result = JsonObject()
    result.addProperty("total_jobs", jobs.size)

    var jobsArray = JsonArray()
    for (jobSummary in jobs.values) {
      var jobObj = JsonObject()
      jobObj.addProperty("job_id", jobSummary.getJobId())
      jobObj.addProperty("total_requests", jobSummary.temporaryIds.size)
      jobObj.addProperty("requests_sent", jobSummary.requestsSent)
      jobObj.addProperty("responses_received", jobSummary.responsesReceived)

      // ステータスを判定
      var status =
        if (jobSummary.requestsSent == 0) {
          "created"
        } else if (jobSummary.responsesReceived == 0) {
          "requests_sent"
        } else if (jobSummary.responsesReceived < jobSummary.requestsSent) {
          "receiving_responses"
        } else {
          "completed"
        }
      jobObj.addProperty("status", status)

      jobsArray.add(jobObj)
    }
    result.add("jobs", jobsArray)

    log("JobStatusTool: Found " + jobs.size + " jobs")
    return result
  }

  /** ジョブのリクエスト情報 */
  private class JobRequest {
    private var temporaryId: String? = null
    var hasRequest = false
    var hasResponse = false
    var requestPacketId = -1
    var responsePacketId = -1

    fun getTemporaryId(): String? = temporaryId

    fun setTemporaryId(temporaryId: String?) {
      this.temporaryId = temporaryId
    }
  }

  /** ジョブの概要情報 */
  private class JobSummary {
    private var jobId: String? = null
    var temporaryIds: MutableList<String> = ArrayList()
    var requestsSent = 0
    var responsesReceived = 0

    fun getJobId(): String? = jobId

    fun setJobId(jobId: String?) {
      this.jobId = jobId
    }
  }
}
