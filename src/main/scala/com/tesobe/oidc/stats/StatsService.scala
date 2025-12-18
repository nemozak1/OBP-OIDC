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

package com.tesobe.oidc.stats

import cats.effect.{IO, Ref}
import cats.syntax.all._
import java.time.{Instant, ZoneOffset, ZonedDateTime}
import java.time.format.DateTimeFormatter
import java.util.concurrent.atomic.AtomicLong
import scala.collection.mutable

/** Statistics for OIDC operations
  */
case class OidcStats(
    // Token statistics
    authorizationCodeGrantsSuccessful: Long = 0,
    authorizationCodeGrantsFailed: Long = 0,
    refreshTokenGrantsSuccessful: Long = 0,
    refreshTokenGrantsFailed: Long = 0,

    // User authentication statistics
    loginAttemptsSuccessful: Long = 0,
    loginAttemptsFailed: Long = 0,

    // General statistics
    totalRequests: Long = 0,
    serverStartTime: Instant = Instant.now(),

    // Recent activity (last 10 events)
    recentEvents: List[StatsEvent] = List.empty,

    // Active tokens tracking
    activeTokens: List[ActiveToken] = List.empty
)

/** Represents an active token issued to a client
  */
case class ActiveToken(
    tokenId: String, // First 8 chars of token for identification
    clientId: String,
    clientName: String,
    username: String,
    issuedAt: Instant,
    expiresAt: Instant,
    tokenType: String, // "access" or "refresh"
    scope: String
)

/** Single statistics event
  */
case class StatsEvent(
    timestamp: Instant,
    eventType: String,
    details: String
)

/** Thread-safe statistics service
  */
trait StatsService[F[_]] {
  def getStats: F[OidcStats]
  def incrementAuthorizationCodeSuccess(
      clientId: String,
      username: String
  ): F[Unit]
  def incrementAuthorizationCodeFailure(error: String): F[Unit]
  def incrementRefreshTokenSuccess(clientId: String, username: String): F[Unit]
  def incrementRefreshTokenFailure(error: String): F[Unit]
  def incrementLoginSuccess(username: String): F[Unit]
  def incrementLoginFailure(username: String, error: String): F[Unit]
  def incrementTotalRequests: F[Unit]
  def reset: F[Unit]
  def recordTokenIssued(
      tokenId: String,
      clientId: String,
      clientName: String,
      username: String,
      expiresAt: Instant,
      tokenType: String,
      scope: String
  ): F[Unit]
  def getActiveTokens: F[List[ActiveToken]]
}

class StatsServiceImpl(statsRef: Ref[IO, OidcStats]) extends StatsService[IO] {

  private val maxRecentEvents = 20

  def getStats: IO[OidcStats] = statsRef.get

  def incrementAuthorizationCodeSuccess(
      clientId: String,
      username: String
  ): IO[Unit] = {
    val event = StatsEvent(
      timestamp = Instant.now(),
      eventType = "Authorization Code Success",
      details = s"User: $username, Client: $clientId"
    )
    updateStats(stats =>
      stats.copy(
        authorizationCodeGrantsSuccessful =
          stats.authorizationCodeGrantsSuccessful + 1,
        recentEvents = (event :: stats.recentEvents).take(maxRecentEvents)
      )
    )
  }

  def incrementAuthorizationCodeFailure(error: String): IO[Unit] = {
    val event = StatsEvent(
      timestamp = Instant.now(),
      eventType = "Authorization Code Failed",
      details = s"Error: $error"
    )
    updateStats(stats =>
      stats.copy(
        authorizationCodeGrantsFailed = stats.authorizationCodeGrantsFailed + 1,
        recentEvents = (event :: stats.recentEvents).take(maxRecentEvents)
      )
    )
  }

  def incrementRefreshTokenSuccess(
      clientId: String,
      username: String
  ): IO[Unit] = {
    val event = StatsEvent(
      timestamp = Instant.now(),
      eventType = "Refresh Token Success",
      details = s"User: $username, Client: $clientId"
    )
    updateStats(stats =>
      stats.copy(
        refreshTokenGrantsSuccessful = stats.refreshTokenGrantsSuccessful + 1,
        recentEvents = (event :: stats.recentEvents).take(maxRecentEvents)
      )
    )
  }

  def incrementRefreshTokenFailure(error: String): IO[Unit] = {
    val event = StatsEvent(
      timestamp = Instant.now(),
      eventType = "Refresh Token Failed",
      details = s"Error: $error"
    )
    updateStats(stats =>
      stats.copy(
        refreshTokenGrantsFailed = stats.refreshTokenGrantsFailed + 1,
        recentEvents = (event :: stats.recentEvents).take(maxRecentEvents)
      )
    )
  }

  def incrementLoginSuccess(username: String): IO[Unit] = {
    val event = StatsEvent(
      timestamp = Instant.now(),
      eventType = "Login Success",
      details = s"User: $username"
    )
    updateStats(stats =>
      stats.copy(
        loginAttemptsSuccessful = stats.loginAttemptsSuccessful + 1,
        recentEvents = (event :: stats.recentEvents).take(maxRecentEvents)
      )
    )
  }

  def incrementLoginFailure(username: String, error: String): IO[Unit] = {
    val event = StatsEvent(
      timestamp = Instant.now(),
      eventType = "Login Failed",
      details = s"User: $username, Error: $error"
    )
    updateStats(stats =>
      stats.copy(
        loginAttemptsFailed = stats.loginAttemptsFailed + 1,
        recentEvents = (event :: stats.recentEvents).take(maxRecentEvents)
      )
    )
  }

  def incrementTotalRequests: IO[Unit] = {
    updateStats(stats => stats.copy(totalRequests = stats.totalRequests + 1))
  }

  def reset: IO[Unit] = {
    updateStats(_ => OidcStats())
  }

  def recordTokenIssued(
      tokenId: String,
      clientId: String,
      clientName: String,
      username: String,
      expiresAt: Instant,
      tokenType: String,
      scope: String
  ): IO[Unit] = {
    val token = ActiveToken(
      tokenId = tokenId,
      clientId = clientId,
      clientName = clientName,
      username = username,
      issuedAt = Instant.now(),
      expiresAt = expiresAt,
      tokenType = tokenType,
      scope = scope
    )
    updateStats(stats =>
      stats.copy(
        activeTokens =
          (token :: stats.activeTokens).take(100) // Keep last 100 tokens
      )
    )
  }

  def getActiveTokens: IO[List[ActiveToken]] = {
    val now = Instant.now()
    statsRef.get.map { stats =>
      // Filter out expired tokens
      stats.activeTokens.filter(_.expiresAt.isAfter(now))
    }
  }

  private def updateStats(f: OidcStats => OidcStats): IO[Unit] = {
    statsRef.update(f)
  }
}

object StatsService {
  def apply(): IO[StatsService[IO]] = {
    for {
      statsRef <- Ref.of[IO, OidcStats](OidcStats())
    } yield new StatsServiceImpl(statsRef)
  }

  /** Format timestamp for display
    */
  def formatTimestamp(instant: Instant): String = {
    val formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
    ZonedDateTime.ofInstant(instant, ZoneOffset.UTC).format(formatter)
  }

  /** Calculate uptime in human-readable format
    */
  def formatUptime(startTime: Instant): String = {
    val now = Instant.now()
    val duration = java.time.Duration.between(startTime, now)

    val days = duration.toDays
    val hours = duration.toHours % 24
    val minutes = duration.toMinutes % 60
    val seconds = duration.getSeconds % 60

    if (days > 0) {
      s"${days}d ${hours}h ${minutes}m ${seconds}s"
    } else if (hours > 0) {
      s"${hours}h ${minutes}m ${seconds}s"
    } else if (minutes > 0) {
      s"${minutes}m ${seconds}s"
    } else {
      s"${seconds}s"
    }
  }
}
