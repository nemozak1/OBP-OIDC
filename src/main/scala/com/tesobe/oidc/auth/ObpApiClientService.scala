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

package com.tesobe.oidc.auth

import cats.effect.{IO, Ref, Resource}
import com.tesobe.oidc.config.OidcConfig
import com.tesobe.oidc.models.{OidcClient, OidcError}
import io.circe.{Decoder, Encoder, Json}
import io.circe.generic.semiauto.{deriveDecoder, deriveEncoder}
import io.circe.syntax._
import org.http4s._
import org.http4s.circe._
import org.http4s.client.Client
import org.http4s.ember.client.EmberClientBuilder
import org.http4s.headers._
import org.http4s.MediaType
import org.typelevel.ci._
import org.slf4j.LoggerFactory

import java.time.Instant

/** Request body for POST /obp/v6.0.0/oidc/clients/verify
  */
case class VerifyClientRequest(
    client_id: String,
    client_secret: String
)

object VerifyClientRequest {
  implicit val encoder: Encoder[VerifyClientRequest] = deriveEncoder
}

/** Response from POST /obp/v6.0.0/oidc/clients/verify
  */
case class VerifyClientResponse(
    valid: Boolean,
    client_id: Option[String],
    consumer_id: Option[String],
    redirect_uris: Option[List[String]]
)

object VerifyClientResponse {
  implicit val decoder: Decoder[VerifyClientResponse] = deriveDecoder
}

/** Service for verifying OIDC clients via OBP API endpoint
  *
  * This service calls POST /obp/v6.0.0/oidc/clients/verify to verify
  * client credentials instead of accessing the consumer database directly.
  */
class ObpApiClientService(
    client: Client[IO],
    config: OidcConfig,
    tokenRef: Ref[IO, Option[CachedToken]]
) {

  private val logger = LoggerFactory.getLogger(getClass)

  /** Obtain a DirectLogin token using username/password
    * Reuses the same approach as ObpApiCredentialsService
    */
  private[auth] def obtainDirectLoginToken(): IO[Either[OidcError, String]] = {
    (config.obpApiUrl, config.obpApiUsername, config.obpApiPassword, config.obpApiConsumerKey) match {
      case (Some(baseUrl), Some(username), Some(password), Some(consumerKey)) =>
        val endpoint = s"${baseUrl.stripSuffix("/")}/my/logins/direct"
        logger.info(s"Obtaining DirectLogin token from: $endpoint")

        val request = Request[IO](
          method = Method.POST,
          uri = Uri.unsafeFromString(endpoint)
        ).putHeaders(
          Header.Raw(
            ci"DirectLogin",
            s"""username="$username",password="$password",consumer_key="$consumerKey""""
          ),
          `Content-Type`(MediaType.application.json)
        )

        client
          .run(request)
          .use { response =>
            response.status match {
              case Status.Ok | Status.Created =>
                response.as[Json].flatMap { json =>
                  json.hcursor.get[String]("token") match {
                    case Right(token) =>
                      logger.info("Successfully obtained DirectLogin token for client verification")
                      tokenRef.set(Some(CachedToken(token, Instant.now()))).map { _ =>
                        Right(token)
                      }
                    case Left(_) =>
                      logger.error(s"DirectLogin response missing token field: $json")
                      IO.pure(Left(OidcError(
                        "server_error",
                        Some("Invalid DirectLogin response: missing token")
                      )))
                  }
                }

              case Status.Unauthorized | Status.Forbidden =>
                response.as[String].flatMap { body =>
                  logger.error(s"DirectLogin authentication failed: $body")
                  IO.pure(Left(OidcError(
                    "server_error",
                    Some("OBP API authentication failed - check OBP_API_USERNAME, OBP_API_PASSWORD, and OBP_API_CONSUMER_KEY")
                  )))
                }

              case status =>
                response.as[String].flatMap { body =>
                  logger.error(s"DirectLogin request failed with status $status: $body")
                  IO.pure(Left(OidcError(
                    "server_error",
                    Some(s"Failed to obtain DirectLogin token: ${status.code}")
                  )))
                }
            }
          }
          .handleErrorWith { error =>
            logger.error(s"Error obtaining DirectLogin token: ${error.getMessage}", error)
            IO.pure(Left(OidcError(
              "server_error",
              Some(s"Failed to connect to OBP API for authentication: ${error.getMessage}")
            )))
          }

      case _ =>
        val missing = List(
          if (config.obpApiUrl.isEmpty) Some("OBP_API_URL") else None,
          if (config.obpApiUsername.isEmpty) Some("OBP_API_USERNAME") else None,
          if (config.obpApiPassword.isEmpty) Some("OBP_API_PASSWORD") else None,
          if (config.obpApiConsumerKey.isEmpty) Some("OBP_API_CONSUMER_KEY") else None
        ).flatten.mkString(", ")

        logger.error(s"Missing configuration for DirectLogin: $missing")
        IO.pure(Left(OidcError(
          "server_error",
          Some(s"Missing OBP API configuration: $missing")
        )))
    }
  }

  /** Get a valid token, refreshing if necessary
    */
  private def getValidToken(): IO[Either[OidcError, String]] = {
    tokenRef.get.flatMap {
      case Some(cached) if !cached.isExpired =>
        logger.debug("Using cached DirectLogin token for client verification")
        IO.pure(Right(cached.token))
      case _ =>
        logger.info("Token expired or not present, obtaining new token")
        obtainDirectLoginToken()
    }
  }

  /** Verify client credentials by calling POST /obp/v6.0.0/oidc/clients/verify
    *
    * Requires:
    * - OBP_API_URL to be configured
    * - OBP_API_USERNAME (a user with CanVerifyOidcClient role)
    * - OBP_API_PASSWORD
    * - OBP_API_CONSUMER_KEY
    */
  def verifyClient(
      clientId: String,
      clientSecret: String
  ): IO[Either[OidcError, OidcClient]] = {
    config.obpApiUrl match {
      case None =>
        logger.error("OBP_API_URL is not configured")
        IO.pure(
          Left(
            OidcError(
              "server_error",
              Some("OBP API URL not configured for client verification")
            )
          )
        )

      case Some(baseUrl) =>
        getValidToken().flatMap {
          case Left(error) => IO.pure(Left(error))
          case Right(token) =>
            val endpoint =
              s"${baseUrl.stripSuffix("/")}/obp/v6.0.0/oidc/clients/verify"
            logger.info(
              s"Verifying client via OBP API: $endpoint for client_id: $clientId"
            )

            val requestBody = VerifyClientRequest(
              client_id = clientId,
              client_secret = clientSecret
            )

            val request = Request[IO](
              method = Method.POST,
              uri = Uri.unsafeFromString(endpoint)
            ).withEntity(requestBody.asJson)
              .putHeaders(
                Header.Raw(
                  ci"DirectLogin",
                  s"token=$token"
                ),
                `Content-Type`(MediaType.application.json)
              )

            client
              .run(request)
              .use { response =>
                response.status match {
                  case Status.Ok =>
                    response
                      .as[Json]
                      .flatMap { json =>
                        json.as[VerifyClientResponse] match {
                          case Right(verifyResponse) if verifyResponse.valid =>
                            logger.info(
                              s"Client verified successfully via OBP API for client_id: $clientId"
                            )
                            val oidcClient = OidcClient(
                              client_id = verifyResponse.client_id.getOrElse(clientId),
                              client_secret = Some(clientSecret), // Don't expose, but keep for internal use
                              consumer_id = verifyResponse.consumer_id.getOrElse(""),
                              client_name = "", // Not returned by API
                              redirect_uris = verifyResponse.redirect_uris.getOrElse(List.empty),
                              grant_types = List("authorization_code", "refresh_token"),
                              response_types = List("code"),
                              scopes = List("openid", "profile", "email"),
                              token_endpoint_auth_method = "client_secret_basic",
                              created_at = None
                            )
                            IO.pure(Right(oidcClient))

                          case Right(verifyResponse) =>
                            // valid = false
                            logger.warn(
                              s"Client verification failed via OBP API for client_id: $clientId (valid=false)"
                            )
                            IO.pure(
                              Left(
                                OidcError(
                                  "invalid_client",
                                  Some("Invalid client credentials")
                                )
                              )
                            )

                          case Left(error) =>
                            logger.error(
                              s"Failed to parse OBP API response: ${error.getMessage}"
                            )
                            IO.pure(
                              Left(
                                OidcError(
                                  "server_error",
                                  Some("Invalid response from client verification endpoint")
                                )
                              )
                            )
                        }
                      }

                  case Status.Unauthorized =>
                    // Token might have expired, clear cache and report error
                    response.as[String].flatMap { body =>
                      if (body.contains("token") || body.contains("Token")) {
                        // Token expired, clear cache for next attempt
                        tokenRef.set(None).map { _ =>
                          Left(OidcError(
                            "server_error",
                            Some("OBP API token expired, please retry")
                          ))
                        }
                      } else {
                        IO.pure(Left(OidcError(
                          "invalid_client",
                          Some("Client verification unauthorized")
                        )))
                      }
                    }

                  case Status.Forbidden =>
                    logger.warn(
                      s"Client verification forbidden for client_id: $clientId"
                    )
                    IO.pure(
                      Left(
                        OidcError(
                          "access_denied",
                          Some("Not authorized to verify clients")
                        )
                      )
                    )

                  case Status.NotFound =>
                    logger.warn(
                      s"Client not found via OBP API: $clientId"
                    )
                    IO.pure(
                      Left(
                        OidcError(
                          "invalid_client",
                          Some("Client not found")
                        )
                      )
                    )

                  case Status.BadRequest =>
                    response.as[Json].flatMap { json =>
                      val errorMsg = json.hcursor
                        .get[String]("message")
                        .getOrElse("Bad request")
                      logger.warn(
                        s"Client verification returned bad request: $errorMsg"
                      )
                      IO.pure(
                        Left(
                          OidcError(
                            "invalid_request",
                            Some(errorMsg)
                          )
                        )
                      )
                    }

                  case status =>
                    response.as[String].flatMap { body =>
                      logger.error(
                        s"Unexpected response from OBP API: status=$status, body=$body"
                      )
                      IO.pure(
                        Left(
                          OidcError(
                            "server_error",
                            Some(s"Client verification failed with status: ${status.code}")
                          )
                        )
                      )
                    }
                }
              }
              .handleErrorWith { error =>
                logger.error(
                  s"Error calling OBP API verify-client endpoint: ${error.getMessage}",
                  error
                )
                IO.pure(
                  Left(
                    OidcError(
                      "server_error",
                      Some(s"Failed to connect to OBP API: ${error.getMessage}")
                    )
                  )
                )
              }
        }
    }
  }

  /** Find client by client_id (without verifying secret)
    * Used for authorization endpoint to check redirect_uri
    */
  def findClient(clientId: String): IO[Option[OidcClient]] = {
    // For finding a client without secret verification, we still need to call the API
    // but we can pass an empty secret - the API should return valid=false but still include
    // the redirect_uris if the client exists
    //
    // Note: This is a limitation - the current API design requires client_secret.
    // For a metadata-only lookup, the API would need to support that mode.
    // For now, we'll return None and fall back to database lookup if needed.
    logger.warn(s"findClient via API not fully supported - client_id: $clientId")
    IO.pure(None)
  }
}

object ObpApiClientService {

  private val logger = LoggerFactory.getLogger(getClass)
  private val RequiredRole = "CanVerifyOidcClient"

  /** Create an ObpApiClientService with http4s Ember client
    */
  def create(config: OidcConfig): Resource[IO, ObpApiClientService] = {
    for {
      client <- EmberClientBuilder.default[IO].build
      tokenRef <- Resource.eval(Ref.of[IO, Option[CachedToken]](None))
      _ <- Resource.eval(IO(logger.info("Created ObpApiClientService with Ember HTTP client")))
    } yield new ObpApiClientService(client, config, tokenRef)
  }

  /** Test the OBP API connection for client verification
    */
  def testConnection(config: OidcConfig): IO[Either[String, String]] = {
    val username = config.obpApiUsername.getOrElse("unknown")
    val baseUrl = config.obpApiUrl.getOrElse("unknown")

    EmberClientBuilder.default[IO].build.use { client =>
      for {
        tokenRefLocal <- Ref.of[IO, Option[CachedToken]](None)
        service = new ObpApiClientService(client, config, tokenRefLocal)
        tokenResult <- service.obtainDirectLoginToken()
        result <- tokenResult match {
          case Left(error) =>
            IO.pure(Left(s"OBP API connection failed for client verification: ${error.error_description.getOrElse(error.error)}"))
          case Right(token) =>
            // Check for CanVerifyOidcClient role
            checkUserRole(client, baseUrl, token).map {
              case Right(hasRole) =>
                val roleStatus = if (hasRole) {
                  s"User has $RequiredRole role"
                } else {
                  s"WARNING: User does NOT have $RequiredRole role"
                }
                Right(
                  s"OBP API client verification connection successful. " +
                    s"Connected to $baseUrl as $username. $roleStatus"
                )
              case Left(roleError) =>
                Right(
                  s"OBP API client verification connection successful. " +
                    s"Connected to $baseUrl as $username. " +
                    s"WARNING: Could not verify $RequiredRole role: $roleError"
                )
            }
        }
      } yield result
    }
  }

  /** Check if the current user has the CanVerifyOidcClient role
    */
  private def checkUserRole(
      client: Client[IO],
      baseUrl: String,
      token: String
  ): IO[Either[String, Boolean]] = {
    val endpoint = s"${baseUrl.stripSuffix("/")}/obp/v6.0.0/my/entitlements"
    logger.debug(s"Checking user entitlements at: $endpoint")

    val request = Request[IO](
      method = Method.GET,
      uri = Uri.unsafeFromString(endpoint)
    ).putHeaders(
      Header.Raw(ci"DirectLogin", s"token=$token")
    )

    client
      .run(request)
      .use { response =>
        response.status match {
          case Status.Ok =>
            response.as[Json].map { json =>
              val hasRole = json.hcursor.get[List[EntitlementInfo]]("list") match {
                case Right(entitlements) =>
                  entitlements.exists(_.role_name == RequiredRole)
                case Left(_) =>
                  // Try alternative structure - just look for the role name in the JSON
                  json.toString.contains(RequiredRole)
              }
              Right(hasRole)
            }
          case status =>
            response.as[String].map { body =>
              logger.warn(s"Failed to check entitlements: $status - $body")
              Left(s"HTTP $status")
            }
        }
      }
      .handleErrorWith { error =>
        logger.warn(s"Error checking entitlements: ${error.getMessage}")
        IO.pure(Left(error.getMessage))
      }
  }
}
