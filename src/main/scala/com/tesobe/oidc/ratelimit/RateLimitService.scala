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

/** Rate limiting service for preventing brute force authentication attacks.
  *
  * Tracks failed login attempts by both IP address and username to provide
  * defense in depth against credential stuffing and brute force attacks.
  */
trait RateLimitService[F[_]] {

  /** Check if a login attempt is allowed and record it if it fails.
    *
    * This method should be called BEFORE attempting authentication. If the
    * authentication fails, the attempt will be recorded for rate limiting.
    *
    * @param ip
    *   The IP address of the client
    * @param username
    *   The username being authenticated
    * @return
    *   Right(()) if the attempt is allowed, Left(errorMessage) if rate limited
    */
  def checkAndRecordFailedAttempt(
      ip: String,
      username: String
  ): F[Either[String, Unit]]

  /** Record a successful login and clear any failed attempts.
    *
    * This should be called after a successful authentication to reset the
    * failed attempt counters for both the IP and username.
    *
    * @param ip
    *   The IP address of the client
    * @param username
    *   The username that was authenticated
    */
  def recordSuccessfulLogin(ip: String, username: String): F[Unit]

  /** Check if an IP address or username is currently blocked.
    *
    * @param ip
    *   The IP address to check
    * @param username
    *   The username to check
    * @return
    *   true if either the IP or username is blocked, false otherwise
    */
  def isBlocked(ip: String, username: String): F[Boolean]

  /** Clean up old entries to prevent memory leaks.
    *
    * This should be called periodically to remove expired attempts and blocks.
    */
  def cleanup(): F[Unit]
}

/** Configuration for rate limiting behavior. */
case class RateLimitConfig(
    maxAttemptsPerIP: Int = 10,
    maxAttemptsPerUsername: Int = 5,
    windowDurationSeconds: Int = 300, // 5 minutes
    blockDurationSeconds: Int = 900 // 15 minutes
)

object RateLimitConfig {
  def fromEnv: RateLimitConfig = {
    RateLimitConfig(
      maxAttemptsPerIP = sys.env
        .get("RATE_LIMIT_MAX_ATTEMPTS_PER_IP")
        .flatMap(_.toIntOption)
        .getOrElse(10),
      maxAttemptsPerUsername = sys.env
        .get("RATE_LIMIT_MAX_ATTEMPTS_PER_USERNAME")
        .flatMap(_.toIntOption)
        .getOrElse(5),
      windowDurationSeconds = sys.env
        .get("RATE_LIMIT_WINDOW_SECONDS")
        .flatMap(_.toIntOption)
        .getOrElse(300),
      blockDurationSeconds = sys.env
        .get("RATE_LIMIT_BLOCK_SECONDS")
        .flatMap(_.toIntOption)
        .getOrElse(900)
    )
  }
}
