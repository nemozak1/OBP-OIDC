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

package com.tesobe.oidc.server

import cats.effect.{ExitCode, IO, IOApp}
import cats.syntax.all._
import com.comcast.ip4s.{Host, Port}
import com.tesobe.oidc.auth.{CodeService, DatabaseAuthService, MockAuthService}
import com.tesobe.oidc.config.Config
import com.tesobe.oidc.endpoints._
import com.tesobe.oidc.tokens.JwtService
import org.http4s._
import org.http4s.ember.server.EmberServerBuilder
import org.http4s.implicits._
import cats.implicits._
import org.slf4j.LoggerFactory

object OidcServer extends IOApp {
  
  private val logger = LoggerFactory.getLogger(getClass)

  def run(args: List[String]): IO[ExitCode] = {
    for {
      config <- Config.load
      _ <- IO(println(s"Starting OIDC Provider on ${config.server.host}:${config.server.port}"))
      _ <- IO(println(s"Issuer: ${config.issuer}"))
      
      // Test database connections
      _ <- DatabaseAuthService.testConnection(config).flatMap {
        case Right(msg) => IO(println(msg))
        case Left(error) => IO.raiseError(new RuntimeException(s"User database connection failed: $error"))
      }
      
      _ <- DatabaseAuthService.testClientConnection(config).flatMap {
        case Right(msg) => IO(println(msg))
        case Left(error) => IO(println(s"Client database warning: $error (using permissive mode)"))
      }
      
      exitCode <- DatabaseAuthService.create(config).use { authService =>
        for {
          // Initialize services
          codeService <- CodeService(config)
          jwtService <- JwtService(config)
    
      // Initialize endpoints
      discoveryEndpoint = DiscoveryEndpoint(config)
      jwksEndpoint = JwksEndpoint(jwtService)
      authEndpoint = AuthEndpoint(authService, codeService)
      tokenEndpoint = TokenEndpoint(authService, codeService, jwtService, config)
      userInfoEndpoint = UserInfoEndpoint(authService, jwtService)
          
          // Create all routes in a single HttpRoutes definition
          routes = {
            import org.http4s.dsl.io._
            
            HttpRoutes.of[IO] {
              // Health check
              case GET -> Root / "health" =>
                Ok("OIDC Provider is running")
                
              // Root page
              case GET -> Root =>
                Ok("""<!DOCTYPE html>
                     |<html>
                     |<head><title>OBP OIDC Provider</title></head>
                     |<body>
                     |<h1>OBP OIDC Provider</h1>
                     |<p>OpenID Connect provider is running</p>
                     |<h2>Endpoints:</h2>
                     |<ul>
                     |<li><a href="/.well-known/openid-configuration">Discovery</a></li>
                     |<li><a href="/jwks">JWKS</a></li>
                     |<li><a href="/health">Health Check</a></li>
                     |</ul>
                     |</body>
                     |</html>""".stripMargin)
                   .map(_.withContentType(org.http4s.headers.`Content-Type`(MediaType.text.html)))
                   
              // OIDC Discovery
              case GET -> Root / ".well-known" / "openid-configuration" =>
                discoveryEndpoint.routes.run(org.http4s.Request[IO](org.http4s.Method.GET, org.http4s.Uri.unsafeFromString("/.well-known/openid-configuration"))).value.flatMap {
                  case Some(resp) => IO.pure(resp)
                  case None => NotFound("Discovery endpoint not found")
                }
                
              // JWKS
              case GET -> Root / "jwks" =>
                jwksEndpoint.routes.run(org.http4s.Request[IO](org.http4s.Method.GET, org.http4s.Uri.unsafeFromString("/jwks"))).value.flatMap {
                  case Some(resp) => IO.pure(resp)
                  case None => NotFound("JWKS endpoint not found")
                }
                
              // Delegate other requests to endpoints
              case req =>
                authEndpoint.routes.run(req).value.flatMap {
                  case Some(resp) => IO.pure(resp)
                  case None =>
                    tokenEndpoint.routes.run(req).value.flatMap {
                      case Some(resp) => IO.pure(resp)
                      case None =>
                        userInfoEndpoint.routes.run(req).value.flatMap {
                          case Some(resp) => IO.pure(resp)
                          case None => NotFound("Endpoint not found")
                        }
                    }
                }
            }.orNotFound
          }
          
          // Start server
          host <- IO.fromOption(Host.fromString(config.server.host))(
            new RuntimeException(s"Invalid host: ${config.server.host}")
          )
          port <- IO.fromOption(Port.fromInt(config.server.port))(
            new RuntimeException(s"Invalid port: ${config.server.port}")
          )
          
          _ <- EmberServerBuilder.default[IO]
            .withHost(host)
            .withPort(port)
            .withHttpApp(routes)
            .build
            .use { server =>
              IO(println(s"OIDC Provider started at ${server.baseUri}")) *>
              IO(println("Available endpoints:")) *>
              IO(println(s"  Discovery: ${server.baseUri}/.well-known/openid-configuration")) *>
              IO(println(s"  Authorization: ${server.baseUri}/auth")) *>
              IO(println(s"  Token: ${server.baseUri}/token")) *>
              IO(println(s"  UserInfo: ${server.baseUri}/userinfo")) *>
              IO(println(s"  JWKS: ${server.baseUri}/jwks")) *>
              IO(println(s"  Health Check: ${server.baseUri}/health")) *>
              printOBPConfiguration(server.baseUri.toString, authService) *>
              IO.never
            }
        } yield ExitCode.Success
      }
    } yield exitCode
  }.handleErrorWith { error =>
    IO(println(s"Failed to start OIDC Provider: ${error.getMessage}")) >>
    IO(error.printStackTrace()) >>
    IO.pure(ExitCode.Error)
  }


  /**
   * Print OBP-API configuration for easy copy-paste
   */
  private def printOBPConfiguration(baseUri: String, authService: DatabaseAuthService): IO[Unit] = {
    val clientId = "obp-api-client"
    val sampleSecret = java.util.UUID.randomUUID().toString.replace("-", "").substring(0, 32)
    
    for {
      // Check if client already exists (with error handling)
      existingClient <- authService.findClientById(clientId).handleErrorWith { error =>
        IO(println(s"Warning: Could not check existing clients: ${error.getMessage}")) >>
        IO.pure(None)
      }
      clientExists = existingClient.isDefined
      _ <- IO(println())
      _ <- IO(println("=" * 80))
      _ <- IO(println("📋 OBP-API CONFIGURATION - Copy and paste into your props file:"))
      _ <- IO(println("=" * 80))
      _ <- IO(println())
      _ <- IO(println("# OIDC Configuration for OBP-OIDC Provider"))
      _ <- IO(println("openid_connect.scope=openid email profile"))
      _ <- IO(println())
      _ <- IO(println("# OBP-OIDC Provider Settings"))
      _ <- IO(println("openid_connect_1.button_text=OBP-OIDC"))
      _ <- IO(println(s"openid_connect_1.client_id=$clientId"))
      _ <- IO(println(s"openid_connect_1.client_secret=$sampleSecret"))
      _ <- IO(println("openid_connect_1.callback_url=http://127.0.0.1:8080/auth/openid-connect/callback"))
      _ <- IO(println())
      _ <- IO(println("# OIDC Endpoints"))
      _ <- IO(println(s"openid_connect_1.endpoint.discovery=$baseUri/.well-known/openid-configuration"))
      _ <- IO(println(s"openid_connect_1.endpoint.authorization=$baseUri/auth"))
      _ <- IO(println(s"openid_connect_1.endpoint.userinfo=$baseUri/userinfo"))
      _ <- IO(println(s"openid_connect_1.endpoint.token=$baseUri/token"))
      _ <- IO(println(s"openid_connect_1.endpoint.jwks_uri=$baseUri/jwks"))
      _ <- IO(println("openid_connect_1.access_type_offline=true"))
      _ <- IO(println())
      _ <- if (clientExists) {
        val actualSecret = existingClient.get.client_secret.getOrElse("NO_SECRET")
        for {
          _ <- IO(println("=" * 80))
          _ <- IO(println("✅ CLIENT ALREADY REGISTERED"))
          _ <- IO(println("=" * 80))
          _ <- IO(println())
          _ <- IO(println(s"Client '$clientId' is already registered in v_oidc_clients."))
          _ <- IO(println(s"Use this client_secret in your props: $actualSecret"))
          _ <- IO(println())
          _ <- IO(println("Updated configuration:"))
          _ <- IO(println(s"openid_connect_1.client_id=$clientId"))
          _ <- IO(println(s"openid_connect_1.client_secret=$actualSecret"))
          _ <- IO(println())
          _ <- IO(println("=" * 80))
          _ <- IO(println())
        } yield ()
      } else {
        for {
          _ <- IO(println("=" * 80))
          _ <- IO(println("🔐 REQUIRED: Register client in v_oidc_clients database:"))
          _ <- IO(println("=" * 80))
          _ <- IO(println())
          _ <- IO(println("INSERT INTO v_oidc_clients ("))
          _ <- IO(println("  client_id, client_secret, client_name, redirect_uris,"))
          _ <- IO(println("  grant_types, response_types, scopes, token_endpoint_auth_method"))
          _ <- IO(println(") VALUES ("))
          _ <- IO(println(s"  '$clientId',"))
          _ <- IO(println(s"  '$sampleSecret',"))
          _ <- IO(println("  'OBP-API',"))
          _ <- IO(println("  '[\"http://127.0.0.1:8080/auth/openid-connect/callback\"]',"))
          _ <- IO(println("  '[\"authorization_code\"]',"))
          _ <- IO(println("  '[\"code\"]',"))
          _ <- IO(println("  '[\"openid\", \"profile\", \"email\"]',"))
          _ <- IO(println("  'client_secret_post'"))
          _ <- IO(println(");"))
          _ <- IO(println())
          _ <- IO(println("=" * 80))
          _ <- IO(println())
        } yield ()
      }
    } yield ()
  }

}