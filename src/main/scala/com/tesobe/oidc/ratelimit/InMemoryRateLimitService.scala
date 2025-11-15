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

package com.tesobe.oidc.ratelimit

import cats.effect.{IO, Ref}
import org.slf4j.LoggerFactory
import java.time.Instant

/** Represents a failed login attempt */
case class LoginAttempt(
    timestamp: Instant,
    username: String,
    ip: String
)

/** Represents a blocked entity (IP or username) */
case class BlockedEntity(
    blockedUntil: Instant,
    reason: String,
    attemptCount: Int
)

/** In-memory implementation of RateLimitService.
  *
  * Uses Ref for thread-safe mutable state. Suitable for single-instance
  * deployments. For distributed systems, use a Redis-backed implementation.
  */
class InMemoryRateLimitService(
    config: RateLimitConfig,
    ipAttemptsRef: Ref[IO, Map[String, List[LoginAttempt]]],
    usernameAttemptsRef: Ref[IO, Map[String, List[LoginAttempt]]],
    blockedIPsRef: Ref[IO, Map[String, BlockedEntity]],
    blockedUsernamesRef: Ref[IO, Map[String, BlockedEntity]]
) extends RateLimitService[IO] {

  private val logger = LoggerFactory.getLogger(getClass)

  def checkAndRecordFailedAttempt(
      ip: String,
      username: String
  ): IO[Either[String, Unit]] = {
    val now = Instant.now()
    val windowStart = now.minusSeconds(config.windowDurationSeconds)

    for {
      // Check if currently blocked
      ipBlocked <- isIPBlocked(ip, now)
      usernameBlocked <- isUsernameBlocked(username, now)

      result <-
        if (ipBlocked) {
          logger.warn(s"Rate limit: IP blocked: $ip")
          IO.pure(
            Left(
              s"Too many failed login attempts from this IP address. Please try again in ${config.blockDurationSeconds / 60} minutes."
            )
          )
        } else if (usernameBlocked) {
          logger.warn(s"Rate limit: Username blocked: $username")
          IO.pure(
            Left(
              s"Too many failed login attempts for this account. Please try again in ${config.blockDurationSeconds / 60} minutes."
            )
          )
        } else {
          // Record the failed attempt
          for {
            _ <- recordFailedAttempt(ip, username, now)

            // Get recent attempts within the window
            ipAttempts <- getRecentAttempts(ip, windowStart, ipAttemptsRef)
            usernameAttempts <- getRecentAttempts(
              username,
              windowStart,
              usernameAttemptsRef
            )

            // Check if we've exceeded limits and block if necessary
            _ <-
              if (ipAttempts.size >= config.maxAttemptsPerIP) {
                logger.warn(
                  s"Rate limit: Blocking IP $ip after ${ipAttempts.size} attempts"
                )
                blockIP(ip, now, ipAttempts.size)
              } else IO.unit

            _ <-
              if (usernameAttempts.size >= config.maxAttemptsPerUsername) {
                logger.warn(
                  s"Rate limit: Blocking username $username after ${usernameAttempts.size} attempts"
                )
                blockUsername(username, now, usernameAttempts.size)
              } else IO.unit

          } yield {
            if (ipAttempts.size >= config.maxAttemptsPerIP) {
              Left(
                s"Too many failed login attempts. Your IP address has been temporarily blocked for ${config.blockDurationSeconds / 60} minutes."
              )
            } else if (usernameAttempts.size >= config.maxAttemptsPerUsername) {
              Left(
                s"Too many failed login attempts for this account. It has been temporarily blocked for ${config.blockDurationSeconds / 60} minutes."
              )
            } else {
              logger.debug(
                s"Rate limit: Recorded failed attempt for IP $ip, username $username (IP: ${ipAttempts.size}/${config.maxAttemptsPerIP}, Username: ${usernameAttempts.size}/${config.maxAttemptsPerUsername})"
              )
              Right(())
            }
          }
        }
    } yield result
  }

  def recordSuccessfulLogin(ip: String, username: String): IO[Unit] = {
    logger.debug(
      s"Rate limit: Clearing failed attempts for IP $ip, username $username"
    )
    for {
      _ <- ipAttemptsRef.update(_.removed(ip))
      _ <- usernameAttemptsRef.update(_.removed(username))
      _ <- blockedIPsRef.update(_.removed(ip))
      _ <- blockedUsernamesRef.update(_.removed(username))
    } yield ()
  }

  def isBlocked(ip: String, username: String): IO[Boolean] = {
    val now = Instant.now()
    for {
      ipBlocked <- isIPBlocked(ip, now)
      usernameBlocked <- isUsernameBlocked(username, now)
    } yield ipBlocked || usernameBlocked
  }

  def cleanup(): IO[Unit] = {
    val now = Instant.now()
    val windowStart = now.minusSeconds(config.windowDurationSeconds)

    for {
      // Clean up old attempts
      _ <- ipAttemptsRef.update { map =>
        map
          .map { case (key, attempts) =>
            key -> attempts.filter(_.timestamp.isAfter(windowStart))
          }
          .filter(_._2.nonEmpty)
      }
      _ <- usernameAttemptsRef.update { map =>
        map
          .map { case (key, attempts) =>
            key -> attempts.filter(_.timestamp.isAfter(windowStart))
          }
          .filter(_._2.nonEmpty)
      }

      // Clean up expired blocks
      _ <- blockedIPsRef.update(_.filter(_._2.blockedUntil.isAfter(now)))
      _ <- blockedUsernamesRef.update(_.filter(_._2.blockedUntil.isAfter(now)))

      _ <- IO(logger.debug("Rate limit: Cleanup completed"))
    } yield ()
  }

  // Private helper methods

  private def recordFailedAttempt(
      ip: String,
      username: String,
      now: Instant
  ): IO[Unit] = {
    val attempt = LoginAttempt(now, username, ip)
    for {
      _ <- ipAttemptsRef.update { map =>
        val existing = map.getOrElse(ip, List.empty)
        map.updated(ip, attempt :: existing)
      }
      _ <- usernameAttemptsRef.update { map =>
        val existing = map.getOrElse(username, List.empty)
        map.updated(username, attempt :: existing)
      }
    } yield ()
  }

  private def getRecentAttempts(
      key: String,
      windowStart: Instant,
      ref: Ref[IO, Map[String, List[LoginAttempt]]]
  ): IO[List[LoginAttempt]] = {
    ref.get.map { map =>
      map
        .getOrElse(key, List.empty)
        .filter(_.timestamp.isAfter(windowStart))
    }
  }

  private def blockIP(ip: String, now: Instant, attemptCount: Int): IO[Unit] = {
    val blockedUntil = now.plusSeconds(config.blockDurationSeconds)
    blockedIPsRef.update(
      _.updated(
        ip,
        BlockedEntity(
          blockedUntil,
          s"Exceeded maximum login attempts (${attemptCount} attempts)",
          attemptCount
        )
      )
    )
  }

  private def blockUsername(
      username: String,
      now: Instant,
      attemptCount: Int
  ): IO[Unit] = {
    val blockedUntil = now.plusSeconds(config.blockDurationSeconds)
    blockedUsernamesRef.update(
      _.updated(
        username,
        BlockedEntity(
          blockedUntil,
          s"Exceeded maximum login attempts (${attemptCount} attempts)",
          attemptCount
        )
      )
    )
  }

  private def isIPBlocked(ip: String, now: Instant): IO[Boolean] = {
    blockedIPsRef.get.map { blocked =>
      blocked.get(ip).exists(_.blockedUntil.isAfter(now))
    }
  }

  private def isUsernameBlocked(username: String, now: Instant): IO[Boolean] = {
    blockedUsernamesRef.get.map { blocked =>
      blocked.get(username).exists(_.blockedUntil.isAfter(now))
    }
  }
}

object InMemoryRateLimitService {

  /** Create a new InMemoryRateLimitService with the given configuration */
  def apply(config: RateLimitConfig): IO[InMemoryRateLimitService] = {
    for {
      ipAttemptsRef <- Ref.of[IO, Map[String, List[LoginAttempt]]](Map.empty)
      usernameAttemptsRef <- Ref.of[IO, Map[String, List[LoginAttempt]]](
        Map.empty
      )
      blockedIPsRef <- Ref.of[IO, Map[String, BlockedEntity]](Map.empty)
      blockedUsernamesRef <- Ref.of[IO, Map[String, BlockedEntity]](Map.empty)
    } yield new InMemoryRateLimitService(
      config,
      ipAttemptsRef,
      usernameAttemptsRef,
      blockedIPsRef,
      blockedUsernamesRef
    )
  }
}
