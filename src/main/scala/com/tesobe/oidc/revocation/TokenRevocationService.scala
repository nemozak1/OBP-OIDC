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

package com.tesobe.oidc.revocation

import cats.effect.{IO, Ref}
import org.slf4j.LoggerFactory

import java.time.Instant

/** Service for managing revoked tokens according to RFC 7009
  *
  * This service maintains an in-memory blacklist of revoked tokens. In
  * production, this should be backed by a persistent store (Redis, database,
  * etc.) to survive server restarts.
  */
trait TokenRevocationService[F[_]] {

  /** Revoke a token (access token or refresh token)
    *
    * @param token
    *   The token string to revoke
    * @param tokenTypeHint
    *   Optional hint about token type ("access_token" or "refresh_token")
    * @return
    *   Unit (always succeeds per RFC 7009 - even if token is invalid)
    */
  def revokeToken(token: String, tokenTypeHint: Option[String]): F[Unit]

  /** Check if a token has been revoked
    *
    * @param token
    *   The token string to check
    * @return
    *   true if the token has been revoked, false otherwise
    */
  def isRevoked(token: String): F[Boolean]

  /** Remove expired tokens from the revocation list
    *
    * This should be called periodically to clean up the blacklist and prevent
    * memory leaks.
    *
    * @return
    *   The number of expired tokens removed
    */
  def cleanupExpiredTokens(): F[Int]

  /** Get statistics about revoked tokens
    *
    * @return
    *   RevokedTokenStats containing counts and information
    */
  def getStats(): F[RevokedTokenStats]
}

/** Statistics about revoked tokens */
case class RevokedTokenStats(
    totalRevoked: Int,
    accessTokensRevoked: Int,
    refreshTokensRevoked: Int,
    oldestRevocation: Option[Instant],
    newestRevocation: Option[Instant]
)

/** Entry in the revocation blacklist */
case class RevokedTokenEntry(
    tokenHash: String, // SHA-256 hash of the token (for security)
    tokenTypeHint: Option[String],
    revokedAt: Instant,
    expiresAt: Instant // When the token would naturally expire
)

/** In-memory implementation of TokenRevocationService
  *
  * Uses a concurrent Ref to store revoked tokens. In production, this should be
  * replaced with a Redis-backed implementation.
  */
class InMemoryTokenRevocationService(
    revokedTokensRef: Ref[IO, Map[String, RevokedTokenEntry]],
    maxTokenLifetimeSeconds: Long =
      2592000L // 30 days - should match longest token lifetime
) extends TokenRevocationService[IO] {

  private val logger = LoggerFactory.getLogger(getClass)

  /** Hash a token for storage (don't store plain tokens for security) */
  private def hashToken(token: String): String = {
    import java.security.MessageDigest
    val digest = MessageDigest.getInstance("SHA-256")
    val hash = digest.digest(token.getBytes("UTF-8"))
    hash.map("%02x".format(_)).mkString
  }

  /** Extract expiration time from token string (JWT)
    *
    * If we can't parse it, assume max lifetime from now
    */
  private def extractExpiration(token: String): Instant = {
    try {
      import com.auth0.jwt.JWT
      val decoded = JWT.decode(token)
      val expDate = decoded.getExpiresAt
      if (expDate != null) {
        expDate.toInstant
      } else {
        // No expiration in token, use max lifetime
        Instant.now().plusSeconds(maxTokenLifetimeSeconds)
      }
    } catch {
      case _: Exception =>
        // Can't decode token, assume max lifetime
        Instant.now().plusSeconds(maxTokenLifetimeSeconds)
    }
  }

  def revokeToken(token: String, tokenTypeHint: Option[String]): IO[Unit] = {
    val tokenHash = hashToken(token)
    val expiresAt = extractExpiration(token)
    val entry = RevokedTokenEntry(
      tokenHash = tokenHash,
      tokenTypeHint = tokenTypeHint,
      revokedAt = Instant.now(),
      expiresAt = expiresAt
    )

    revokedTokensRef.update { tokens =>
      tokens + (tokenHash -> entry)
    } *> IO(
      logger.info(
        s"Token revoked: ${tokenHash.take(8)}... (type: ${tokenTypeHint.getOrElse("unspecified")})"
      )
    )
  }

  def isRevoked(token: String): IO[Boolean] = {
    val tokenHash = hashToken(token)
    revokedTokensRef.get.map { tokens =>
      tokens.get(tokenHash) match {
        case Some(entry) =>
          // Check if revocation entry is still valid (token hasn't naturally expired yet)
          if (entry.expiresAt.isAfter(Instant.now())) {
            true // Token is revoked and hasn't expired yet
          } else {
            false // Token has naturally expired, no need to keep blocking it
          }
        case None =>
          false // Token not in revocation list
      }
    }
  }

  def cleanupExpiredTokens(): IO[Int] = {
    val now = Instant.now()
    revokedTokensRef
      .modify { tokens =>
        val (expired, valid) = tokens.partition { case (_, entry) =>
          entry.expiresAt.isBefore(now)
        }
        val expiredCount = expired.size
        (valid, expiredCount)
      }
      .flatTap { expiredCount =>
        if (expiredCount > 0) {
          IO(
            logger
              .info(s"Removed $expiredCount expired revocations from blacklist")
          )
        } else {
          IO.unit
        }
      }
  }

  def getStats(): IO[RevokedTokenStats] = {
    revokedTokensRef.get.map { tokens =>
      val now = Instant.now()
      // Only count non-expired entries
      val activeRevocations = tokens.values.filter(_.expiresAt.isAfter(now))

      val accessCount =
        activeRevocations.count(_.tokenTypeHint.contains("access_token"))
      val refreshCount =
        activeRevocations.count(_.tokenTypeHint.contains("refresh_token"))

      val revocationTimes = activeRevocations.map(_.revokedAt)
      val oldest =
        if (revocationTimes.nonEmpty) Some(revocationTimes.min) else None
      val newest =
        if (revocationTimes.nonEmpty) Some(revocationTimes.max) else None

      RevokedTokenStats(
        totalRevoked = activeRevocations.size,
        accessTokensRevoked = accessCount,
        refreshTokensRevoked = refreshCount,
        oldestRevocation = oldest,
        newestRevocation = newest
      )
    }
  }
}

object InMemoryTokenRevocationService {

  /** Create a new TokenRevocationService with background cleanup task
    *
    * @param maxTokenLifetimeSeconds
    *   Maximum lifetime of any token (default 30 days)
    * @param cleanupIntervalMinutes
    *   How often to run cleanup (default 60 minutes)
    * @return
    *   IO containing the service
    */
  def apply(
      maxTokenLifetimeSeconds: Long = 2592000L, // 30 days
      cleanupIntervalMinutes: Int = 60
  ): IO[TokenRevocationService[IO]] = {
    for {
      ref <- Ref.of[IO, Map[String, RevokedTokenEntry]](Map.empty)
      service = new InMemoryTokenRevocationService(ref, maxTokenLifetimeSeconds)
      // Note: Background cleanup task would need to be started separately in production
      // For now, cleanup can be triggered manually or via a scheduled task
    } yield service
  }
}
