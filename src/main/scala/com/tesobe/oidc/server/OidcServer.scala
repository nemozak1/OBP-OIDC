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
      _ <- IO(logger.info(s"Starting OIDC Provider on ${config.server.host}:${config.server.port}"))
      _ <- IO(logger.info(s"Issuer: ${config.issuer}"))
      
      // Use MockAuthService for testing (no database required)
      authService = MockAuthService()
      
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
              IO(logger.info(s"OIDC Provider started at ${server.baseUri}")) *>
              IO(logger.info("Available endpoints:")) *>
              IO(logger.info(s"  Discovery: ${server.baseUri}/.well-known/openid-configuration")) *>
              IO(logger.info(s"  Authorization: ${server.baseUri}/auth")) *>
              IO(logger.info(s"  Token: ${server.baseUri}/token")) *>
              IO(logger.info(s"  UserInfo: ${server.baseUri}/userinfo")) *>
              IO(logger.info(s"  JWKS: ${server.baseUri}/jwks")) *>
              IO(logger.info(s"  Health Check: ${server.baseUri}/health")) *>
              IO.never
            }
        } yield ExitCode.Success
  }.handleErrorWith { error =>
    IO(logger.error("Failed to start OIDC Provider", error)) >>
    IO.pure(ExitCode.Error)
  }


}