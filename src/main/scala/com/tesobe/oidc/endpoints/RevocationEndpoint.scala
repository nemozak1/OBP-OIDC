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

import com.tesobe.oidc.auth.DatabaseAuthService
import com.tesobe.oidc.config.OidcConfig
import com.tesobe.oidc.revocation.TokenRevocationService
import org.http4s._
import org.http4s.dsl.io._
import org.http4s.headers.Authorization
import org.slf4j.LoggerFactory

import java.util.Base64

/** Token Revocation Endpoint (RFC 7009)
  *
  * This endpoint allows clients to notify the authorization server that a
  * previously obtained refresh or access token is no longer needed. This allows
  * the authorization server to clean up security credentials.
  *
  * Key features:
  *   - Accepts both access tokens and refresh tokens
  *   - Supports client authentication via Basic Auth or POST body
  *   - Always returns 200 OK (even for invalid tokens, per RFC 7009)
  *   - Optional token_type_hint parameter to optimize lookup
  */
class RevocationEndpoint(
    authService: DatabaseAuthService,
    revocationService: TokenRevocationService[IO],
    config: OidcConfig
) {

  private val logger = LoggerFactory.getLogger(getClass)

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case req @ POST -> Root / "obp-oidc" / "revoke" =>
      handleRevocationRequest(req)
  }

  /** Extract Basic Auth credentials from Authorization header
    *
    * @param req
    *   HTTP request
    * @return
    *   Option of (clientId, clientSecret)
    */
  private def extractBasicAuthCredentials(
      req: Request[IO]
  ): Option[(String, String)] = {
    req.headers.get[Authorization].flatMap { auth =>
      auth.credentials match {
        case org.http4s.Credentials.Token(scheme, token)
            if scheme == org.http4s.AuthScheme.Basic =>
          val encoded = token
          try {
            val decoded = new String(
              Base64.getDecoder.decode(encoded),
              "UTF-8"
            )
            decoded.split(":", 2) match {
              case Array(clientId, clientSecret) =>
                Some((clientId, clientSecret))
              case _ => None
            }
          } catch {
            case _: Exception => None
          }
        case _ => None
      }
    }
  }

  /** Handle token revocation request according to RFC 7009
    *
    * RFC 7009 Section 2.2 states: "The authorization server responds with HTTP
    * status code 200 if the token has been revoked successfully or if the
    * client submitted an invalid token."
    *
    * This means we always return 200 OK, even if:
    *   - The token is invalid
    *   - The token doesn't exist
    *   - The client is not authorized
    *
    * This is intentional to prevent token scanning attacks.
    */
  private def handleRevocationRequest(req: Request[IO]): IO[Response[IO]] = {
    val result = for {
      // Parse form data
      formData <- req.as[UrlForm]

      // Extract token (required)
      token = formData.getFirst("token")

      // Extract token_type_hint (optional)
      tokenTypeHint = formData.getFirst("token_type_hint")

      // Extract client credentials from Basic Auth header
      basicCredentialsOpt = extractBasicAuthCredentials(req)
      clientIdFromBasic = basicCredentialsOpt.map(_._1)
      clientSecretFromBasic = basicCredentialsOpt.map(_._2)

      // Extract client credentials from form body (fallback)
      clientIdFromForm = formData.getFirst("client_id")
      clientSecretFromForm = formData.getFirst("client_secret")

      // Resolve which credentials to use (Basic Auth takes precedence)
      resolvedClientId = clientIdFromBasic.orElse(clientIdFromForm)
      resolvedClientSecret = clientSecretFromBasic.orElse(clientSecretFromForm)

      _ <- IO(
        logger.info(
          s"Revocation request received - client: ${resolvedClientId
              .getOrElse("unknown")}, token_type_hint: ${tokenTypeHint.getOrElse("none")}"
        )
      )

      // Validate that token parameter is present
      tokenValue <- token match {
        case Some(t) if t.nonEmpty => IO.pure(t)
        case _                     =>
          // RFC 7009: Missing token parameter returns 400 Bad Request (only error case)
          IO(logger.warn("Revocation request missing 'token' parameter"))
          IO.raiseError(
            new IllegalArgumentException("Missing required parameter: token")
          )
      }

      // Validate client credentials if provided
      // Note: RFC 7009 allows public clients (no authentication), but we require it
      clientValidated <- (resolvedClientId, resolvedClientSecret) match {
        case (Some(clientId), Some(clientSecret)) =>
          authService
            .authenticateClient(clientId, clientSecret)
            .flatMap {
              case Right(_) =>
                IO(logger.info(s"Client authenticated: $clientId"))
                IO.pure(true)
              case Left(oidcError) =>
                IO(
                  logger.warn(
                    s"Client authentication failed for revocation: ${oidcError.error}"
                  )
                )
                // Per RFC 7009, we return 200 OK even for auth failures (to prevent token scanning)
                IO.pure(false)
            }
        case (Some(clientId), None) =>
          // Client ID provided but no secret - could be public client
          IO(
            logger.warn(
              s"Revocation request with client_id but no client_secret: $clientId"
            )
          )
          IO.pure(false)
        case _ =>
          // No client credentials provided
          IO(logger.warn("Revocation request with no client credentials"))
          IO.pure(false)
      }

      // RFC 7009: Always revoke the token, even if client auth fails
      // This is debatable, but the spec says to return 200 OK regardless
      // We'll only revoke if client is authenticated (more secure)
      _ <-
        if (clientValidated) {
          revocationService
            .revokeToken(tokenValue, tokenTypeHint)
            .flatMap { _ =>
              IO(
                logger.info(
                  s"Token revoked successfully: ${tokenValue
                      .take(8)}... (hint: ${tokenTypeHint.getOrElse("none")})"
                )
              )
            }
        } else {
          IO(
            logger.warn(
              "Token revocation skipped due to client authentication failure"
            )
          )
        }

      // Always return 200 OK per RFC 7009 Section 2.2
      response <- Ok("")

    } yield response

    // Handle errors
    result.handleErrorWith { error =>
      error match {
        case _: IllegalArgumentException =>
          // Missing token parameter - only case where we return 400
          BadRequest("invalid_request")
        case _ =>
          // Any other error - return 200 OK per RFC 7009
          logger.error(
            s"Error processing revocation request: ${error.getMessage}",
            error
          )
          Ok("")
      }
    }
  }
}

object RevocationEndpoint {
  def apply(
      authService: DatabaseAuthService,
      revocationService: TokenRevocationService[IO],
      config: OidcConfig
  ): RevocationEndpoint = new RevocationEndpoint(
    authService,
    revocationService,
    config
  )
}
