/*
 * Copyright (c) 2025 TESOBE
 *
 * This file is part of OBP-OIDC.
 *
 * OBP-OIDC is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * OBP-OIDC is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with OBP-OIDC. If not, see <http://www.gnu.org/licenses/>.
 */

package com.tesobe.oidc.endpoints

import cats.effect.IO
import com.tesobe.oidc.stats.{StatsService, StatsEvent}
import com.tesobe.oidc.config.OidcConfig
import org.http4s._
import org.http4s.dsl.io._
import org.http4s.headers.{`Content-Type`, Location}
import org.slf4j.LoggerFactory

class StatsEndpoint(statsService: StatsService[IO], config: OidcConfig) {

  private val logger = LoggerFactory.getLogger(getClass)

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case GET -> Root / "stats" =>
      logger.debug("Stats page requested")
      statsService.getStats.flatMap { stats =>
        val html = generateStatsHtml(stats)
        Ok(html).map(_.withContentType(`Content-Type`(MediaType.text.html)))
      }

    case POST -> Root / "stats" / "reset" =>
      logger.info("Stats reset requested")
      statsService.reset.flatMap { _ =>
        SeeOther(Location(Uri.unsafeFromString("/stats")))
      }
  }

  private def generateStatsHtml(
      stats: com.tesobe.oidc.stats.OidcStats
  ): String = {
    val uptime =
      com.tesobe.oidc.stats.StatsService.formatUptime(stats.serverStartTime)
    val startTime =
      com.tesobe.oidc.stats.StatsService.formatTimestamp(stats.serverStartTime)

    // Filter active (non-expired) tokens
    val now = java.time.Instant.now()
    val activeTokens = stats.activeTokens.filter(_.expiresAt.isAfter(now))

    val activeTokensHtml = if (activeTokens.nonEmpty) {
      activeTokens
        .sortBy(_.expiresAt.getEpochSecond)
        .map { token =>
          val issuedAt =
            com.tesobe.oidc.stats.StatsService.formatTimestamp(token.issuedAt)
          val expiresAt =
            com.tesobe.oidc.stats.StatsService.formatTimestamp(token.expiresAt)
          val timeLeft = {
            val duration = java.time.Duration.between(now, token.expiresAt)
            val hours = duration.toHours
            val minutes = duration.toMinutes % 60
            if (hours > 0) s"${hours}h ${minutes}m" else s"${minutes}m"
          }
          val tokenClass =
            if (token.tokenType == "access") "token-access" else "token-refresh"
          s"""
           |<tr class="$tokenClass">
           |  <td><code>${token.tokenId}</code></td>
           |  <td>${token.clientName}</td>
           |  <td>${token.username}</td>
           |  <td><span class="badge badge-${token.tokenType}">${token.tokenType}</span></td>
           |  <td>${token.scope}</td>
           |  <td>$issuedAt</td>
           |  <td>$expiresAt</td>
           |  <td><span class="time-left">$timeLeft</span></td>
           |</tr>""".stripMargin
        }
        .mkString("")
    } else {
      """<tr><td colspan="8"><em>No active tokens</em></td></tr>"""
    }

    val recentEventsHtml = if (stats.recentEvents.nonEmpty) {
      stats.recentEvents
        .map { event =>
          val timestamp =
            com.tesobe.oidc.stats.StatsService.formatTimestamp(event.timestamp)
          val eventClass = event.eventType.toLowerCase.replace(" ", "-")
          s"""
           |<tr class="event-$eventClass">
           |  <td>$timestamp</td>
           |  <td><span class="event-type">${event.eventType}</span></td>
           |  <td>${event.details}</td>
           |</tr>""".stripMargin
        }
        .mkString("")
    } else {
      """<tr><td colspan="3"><em>No recent events</em></td></tr>"""
    }

    val totalTokenGrants =
      stats.authorizationCodeGrantsSuccessful + stats.refreshTokenGrantsSuccessful
    val totalFailedGrants =
      stats.authorizationCodeGrantsFailed + stats.refreshTokenGrantsFailed

    val successRate = if (totalTokenGrants + totalFailedGrants > 0) {
      val rate =
        (totalTokenGrants.toDouble / (totalTokenGrants + totalFailedGrants)) * 100
      f"$rate%.1f%%"
    } else "N/A"

    s"""<!DOCTYPE html>
       |<html>
       |<head>
       |    <title>OIDC Statistics - Real-time</title>
       |    <meta name="viewport" content="width=device-width, initial-scale=1.0">
       |    <meta http-equiv="refresh" content="10">
       |    <link rel="stylesheet" href="/static/css/main.css">
       |    <style>
       |        .container {
       |            max-width: 1200px;
       |            overflow: hidden;
       |        }
       |        .header {
       |            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
       |            color: white;
       |            padding: 30px;
       |            text-align: center;
       |            border-radius: 8px 8px 0 0;
       |            margin: -40px -40px 30px -40px;
       |        }
       |        .header h1 {
       |            margin: 0;
       |            font-size: 2.5em;
       |            font-weight: 300;
       |            color: white;
       |        }
       |        .header p {
       |            margin: 10px 0 0 0;
       |            opacity: 0.9;
       |            font-size: 1.1em;
       |        }
       |        .auto-refresh {
       |            background: rgba(255,255,255,0.2);
       |            padding: 8px 16px;
       |            border-radius: 20px;
       |            display: inline-block;
       |            margin-top: 15px;
       |            font-size: 0.9em;
       |        }
       |        .events-section {
       |            margin: 40px 0 20px 0;
       |        }
       |        .section-title {
       |            font-size: 1.5em;
       |            color: #1f2937;
       |            margin: 0 0 20px 0;
       |            font-weight: 500;
       |        }
       |        .event-type {
       |            font-weight: 600;
       |        }
       |        .event-authorization-code-success,
       |        .event-refresh-token-success,
       |        .event-login-success {
       |            border-left: 3px solid #10b981;
       |        }
       |        .event-authorization-code-failed,
       |        .event-refresh-token-failed,
       |        .event-login-failed {
       |            border-left: 3px solid #ef4444;
       |        }
       |        .nav {
       |            padding: 20px 0;
       |            background: #f8fafc;
       |            border-top: 1px solid #e5e7eb;
       |            margin: 30px -40px -40px -40px;
       |            padding: 20px 40px;
       |        }
       |        .nav a {
       |            color: #26a69a;
       |        }
       |        .tokens-section {
       |            margin: 40px 0 20px 0;
       |        }
       |        .tokens-table {
       |            width: 100%;
       |            border-collapse: collapse;
       |            background: white;
       |            border-radius: 8px;
       |            overflow: hidden;
       |            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
       |        }
       |        .tokens-table th {
       |            background: #f3f4f6;
       |            padding: 12px;
       |            text-align: left;
       |            font-weight: 600;
       |            color: #374151;
       |            border-bottom: 2px solid #e5e7eb;
       |        }
       |        .tokens-table td {
       |            padding: 12px;
       |            border-bottom: 1px solid #f3f4f6;
       |        }
       |        .tokens-table tr:hover {
       |            background: #f9fafb;
       |        }
       |        .tokens-table code {
       |            background: #f3f4f6;
       |            padding: 2px 6px;
       |            border-radius: 4px;
       |            font-family: 'Courier New', monospace;
       |            font-size: 0.9em;
       |        }
       |        .badge {
       |            display: inline-block;
       |            padding: 4px 8px;
       |            border-radius: 12px;
       |            font-size: 0.85em;
       |            font-weight: 600;
       |            text-transform: uppercase;
       |        }
       |        .badge-access {
       |            background: #dbeafe;
       |            color: #1e40af;
       |        }
       |        .badge-refresh {
       |            background: #d1fae5;
       |            color: #065f46;
       |        }
       |        .time-left {
       |            font-weight: 600;
       |            color: #059669;
       |        }
       |        .token-access {
       |            border-left: 3px solid #3b82f6;
       |        }
       |        .token-refresh {
       |            border-left: 3px solid #10b981;
       |        }
       |    </style>
       |</head>
       |<body>
       |    <div class="container">
       |        <div class="header">
       |            <h1>OIDC Statistics</h1>
       |            <p>Real-time monitoring of OpenID Connect operations</p>
       |            <div class="auto-refresh">
       |                Auto-refreshing every 10 seconds
       |            </div>
       |        </div>
       |
       |        <div class="stats-grid" style="padding: 0;">
       |            <div class="stat-card success">
       |                <h2 class="stat-number">${stats.refreshTokenGrantsSuccessful}</h2>
       |                <p class="stat-label">Refresh Tokens Used</p>
       |                <p class="stat-description">Successfully refreshed access tokens</p>
       |            </div>
       |
       |            <div class="stat-card success">
       |                <h2 class="stat-number">${stats.authorizationCodeGrantsSuccessful}</h2>
       |                <p class="stat-label">Authorization Codes</p>
       |                <p class="stat-description">Successfully exchanged for tokens</p>
       |            </div>
       |
       |            <div class="stat-card success">
       |                <h2 class="stat-number">${stats.loginAttemptsSuccessful}</h2>
       |                <p class="stat-label">Successful Logins</p>
       |                <p class="stat-description">Users authenticated successfully</p>
       |            </div>
       |
       |            <div class="stat-card error">
       |                <h2 class="stat-number">$totalFailedGrants</h2>
       |                <p class="stat-label">Failed Token Grants</p>
       |                <p class="stat-description">Authorization code + refresh token failures</p>
       |            </div>
       |
       |            <div class="stat-card error">
       |                <h2 class="stat-number">${stats.loginAttemptsFailed}</h2>
       |                <p class="stat-label">Failed Logins</p>
       |                <p class="stat-description">Authentication failures</p>
       |            </div>
       |
       |            <div class="stat-card info">
       |                <h2 class="stat-number">$successRate</h2>
       |                <p class="stat-label">Success Rate</p>
       |                <p class="stat-description">Token grant success percentage</p>
       |            </div>
       |
       |            <div class="stat-card info">
       |                <h2 class="stat-number">${stats.totalRequests}</h2>
       |                <p class="stat-label">Total Requests</p>
       |                <p class="stat-description">All HTTP requests processed</p>
       |            </div>
       |
       |            <div class="stat-card info">
       |                <h2 class="stat-number">$uptime</h2>
       |                <p class="stat-label">Server Uptime</p>
       |                <p class="stat-description">Started: $startTime UTC</p>
       |            </div>
       |        </div>
       |
       |        <div class="tokens-section">
       |            <h2 class="section-title">Active Tokens (${activeTokens.size})</h2>
       |            <table class="tokens-table">
       |                <thead>
       |                    <tr>
       |                        <th>Token Hash Fragment</th>
       |                        <th>Client</th>
       |                        <th>User</th>
       |                        <th>Type</th>
       |                        <th>Scope</th>
       |                        <th>Issued At (UTC)</th>
       |                        <th>Expires At (UTC)</th>
       |                        <th>Time Left</th>
       |                    </tr>
       |                </thead>
       |                <tbody>
       |                    $activeTokensHtml
       |                </tbody>
       |            </table>
       |        </div>
       |
       |        <div class="events-section">
       |            <h2 class="section-title">Recent Events</h2>
       |            <table class="events-table">
       |                <thead>
       |                    <tr>
       |                        <th>Timestamp (UTC)</th>
       |                        <th>Event Type</th>
       |                        <th>Details</th>
       |                    </tr>
       |                </thead>
       |                <tbody>
       |                    $recentEventsHtml
       |                </tbody>
       |            </table>
       |        </div>
       |
       |        <div class="nav">
       |            <a href="/">Back to Home</a>
       |            <a href="/clients">View Clients</a>
       |            <a href="/health">Health Check</a>
       |            <form style="display: inline;" method="post" action="/stats/reset">
       |                <button type="submit" class="btn btn-danger" onclick="return confirm('Are you sure you want to reset all statistics?')">
       |                    Reset Stats
       |                </button>
       |            </form>
       |        </div>
       |    </div>
       |</body>
       |</html>""".stripMargin
  }
}

object StatsEndpoint {
  def apply(statsService: StatsService[IO], config: OidcConfig): StatsEndpoint =
    new StatsEndpoint(statsService, config)
}
