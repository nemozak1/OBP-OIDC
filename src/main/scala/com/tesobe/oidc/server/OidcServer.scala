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

import scala.language.higherKinds
import cats.effect.{ExitCode, IO, IOApp}
import cats.syntax.all._
import com.comcast.ip4s.{Host, Port}
import com.tesobe.oidc.auth.{CodeService, DatabaseAuthService, DatabaseClient}
import com.tesobe.oidc.models.OidcClient
import com.tesobe.oidc.bootstrap.ClientBootstrap
import com.tesobe.oidc.config.Config
import com.tesobe.oidc.endpoints._
import com.tesobe.oidc.tokens.JwtService
import org.http4s._
import org.http4s.ember.server.EmberServerBuilder
import org.http4s.implicits._
import org.http4s.server.Router

import scala.concurrent.duration._

object OidcServer extends IOApp {

  def run(args: List[String]): IO[ExitCode] = {
    // Check for developer helper commands
    args.headOption match {
      case Some("--generate-config") | Some("--config") =>
        generateDeveloperConfig()
      case Some("--generate-db-config") | Some("--db-config") =>
        generateDatabaseConfig()
      case Some("--help") | Some("-h") =>
        printHelp()
      case _ =>
        startServer(args)
    }
  }

  private def startServer(args: List[String]): IO[ExitCode] = {
    for {
      config <- Config.load
      _ <- IO(
        println(
          s"Starting OIDC Provider on ${config.server.host}:${config.server.port}"
        )
      )
      _ <- IO(println(s"Issuer: ${config.issuer}"))

      // Test database connections
      _ <- DatabaseAuthService.testConnection(config).flatMap {
        case Right(msg) => IO(println(msg))
        case Left(error) =>
          IO.raiseError(
            new RuntimeException(s"User database connection failed: $error")
          )
      }

      _ <- DatabaseAuthService.testClientConnection(config).flatMap {
        case Right(msg) => IO(println(msg))
        case Left(error) =>
          IO(
            println(s"Client database warning: $error (using permissive mode)")
          )
      }

      _ <- DatabaseAuthService.testAdminConnection(config).flatMap {
        case Right(msg) => IO(println(msg))
        case Left(error) =>
          IO(
            println(
              s"Admin database warning: $error (client management features disabled)"
            )
          )
      }

      exitCode <- DatabaseAuthService.create(config).use { authService =>
        for {
          // Initialize standard OBP ecosystem clients (create-only mode)
          _ <- IO(
            println(
              "🔧 DEBUG: Starting ClientBootstrap initialization (create-only mode)..."
            )
          )
          _ <- IO(println("🔧 Starting ClientBootstrap initialization..."))
          _ <- IO
            .race(
              IO.sleep(15.seconds),
              ClientBootstrap.initialize(authService, config)
            )
            .flatMap {
              case Left(_) =>
                IO(
                  println(
                    "⚠️ DEBUG: Client initialization TIMED OUT after 15 seconds"
                  )
                )
                IO(
                  println(
                    "⚠️ Client initialization timed out after 15 seconds - continuing server startup"
                  )
                )
              case Right(_) =>
                IO(
                  println(
                    "✅ DEBUG: Client initialization completed successfully"
                  )
                )
                IO(println("✅ Client initialization completed successfully"))
            }
            .handleErrorWith { error =>
              IO(
                println(
                  s"❌ DEBUG: Client initialization FAILED with error: ${error.getClass.getSimpleName}: ${error.getMessage}"
                )
              )
              IO(
                println(
                  s"⚠️ Client initialization failed: ${error.getMessage} - continuing server startup"
                )
              )
              IO(error.printStackTrace())
            }

          // Initialize services
          codeService <- CodeService(config)
          jwtService <- JwtService(config)

          // Initialize endpoints
          discoveryEndpoint = DiscoveryEndpoint(config)
          jwksEndpoint = JwksEndpoint(jwtService)
          authEndpoint = AuthEndpoint(authService, codeService)
          tokenEndpoint = TokenEndpoint(
            authService,
            codeService,
            jwtService,
            config
          )
          userInfoEndpoint = UserInfoEndpoint(authService, jwtService)

          // Create all routes in a single HttpRoutes definition
          routes = {
            import org.http4s.dsl.io._

            HttpRoutes
              .of[IO] {
                // Health check
                case GET -> Root / "health" =>
                  IO(println("🏥 Health check requested")) *>
                    Ok("OIDC Provider is running")

                // Root page
                case GET -> Root =>
                  Ok(s"""<!DOCTYPE html>
                     |<html>
                     |<head><title>OBP OIDC Provider</title></head>
                     |<body>
                     |<h1>OBP OIDC Provider</h1>
                     |<p>OpenID Connect provider is running</p>
                     |<p><strong>Version:</strong> v2.0.0-DEBUG-${java.time.Instant
                         .now()}</p>
                     |<p><em>🐛 Debug mode enabled - Enhanced logging for azp claim troubleshooting</em></p>
                     |<h2>Endpoints:</h2>
                     |<ul>
                     |<li><a href="/obp-oidc/.well-known/openid-configuration">Discovery</a></li>
                     |<li><a href="/obp-oidc/jwks">JWKS</a></li>
                     |<li><a href="/health">Health Check</a></li>
                     |</ul>
                     |</body>
                     |</html>""".stripMargin)
                    .map(
                      _.withContentType(
                        org.http4s.headers.`Content-Type`(MediaType.text.html)
                      )
                    )

                // OIDC Discovery
                case GET -> Root / "obp-oidc" / ".well-known" / "openid-configuration" =>
                  discoveryEndpoint.routes
                    .run(
                      org.http4s.Request[IO](
                        org.http4s.Method.GET,
                        org.http4s.Uri.unsafeFromString(
                          "/obp-oidc/.well-known/openid-configuration"
                        )
                      )
                    )
                    .value
                    .flatMap {
                      case Some(resp) => IO.pure(resp)
                      case None => NotFound("Discovery endpoint not found")
                    }

                // JWKS
                case GET -> Root / "obp-oidc" / "jwks" =>
                  jwksEndpoint.routes
                    .run(
                      org.http4s.Request[IO](
                        org.http4s.Method.GET,
                        org.http4s.Uri.unsafeFromString("/obp-oidc/jwks")
                      )
                    )
                    .value
                    .flatMap {
                      case Some(resp) => IO.pure(resp)
                      case None       => NotFound("JWKS endpoint not found")
                    }

                // Delegate other requests to endpoints
                case req =>
                  IO(
                    println(
                      s"🌐 Incoming request: ${req.method} ${req.uri} - Content-Type: ${req.headers.get[headers.`Content-Type`].map(_.mediaType).getOrElse("MISSING")}"
                    )
                  ) *>
                    authEndpoint.routes.run(req).value.flatMap {
                      case Some(resp) =>
                        IO(println(s"🔐 Request handled by AuthEndpoint")) *>
                          IO.pure(resp)
                      case None =>
                        IO(
                          println(
                            s"🔐 AuthEndpoint did not handle request, trying TokenEndpoint"
                          )
                        ) *>
                          tokenEndpoint.routes.run(req).value.flatMap {
                            case Some(resp) =>
                              IO(
                                println(s"🎫 Request handled by TokenEndpoint")
                              ) *>
                                IO.pure(resp)
                            case None =>
                              IO(
                                println(
                                  s"🎫 TokenEndpoint did not handle request, trying UserInfoEndpoint"
                                )
                              ) *>
                                userInfoEndpoint.routes.run(req).value.flatMap {
                                  case Some(resp) =>
                                    IO(
                                      println(
                                        s"👤 Request handled by UserInfoEndpoint"
                                      )
                                    ) *>
                                      IO.pure(resp)
                                  case None =>
                                    IO(
                                      println(
                                        s"❌ No endpoint handled the request: ${req.method} ${req.uri}"
                                      )
                                    ) *>
                                      NotFound("Endpoint not found")
                                }
                          }
                    }
              }
              .orNotFound
          }

          // Start server
          host <- IO.fromOption(Host.fromString(config.server.host))(
            new RuntimeException(s"Invalid host: ${config.server.host}")
          )
          port <- IO.fromOption(Port.fromInt(config.server.port))(
            new RuntimeException(s"Invalid port: ${config.server.port}")
          )

          _ <- EmberServerBuilder
            .default[IO]
            .withHost(host)
            .withPort(port)
            .withHttpApp(routes)
            .build
            .use { server =>
              val baseUriString = server.baseUri.toString.stripSuffix("/")
              IO(println(s"OIDC Provider started at ${server.baseUri}")) *>
                IO(println("Available endpoints:")) *>
                IO(
                  println(
                    s"  Discovery: $baseUriString/.well-known/openid-configuration"
                  )
                ) *>
                IO(println(s"  Authorization: $baseUriString/auth")) *>
                IO(println(s"  Token: $baseUriString/token")) *>
                IO(println(s"  UserInfo: $baseUriString/userinfo")) *>
                IO(println(s"  JWKS: $baseUriString/jwks")) *>
                IO(println(s"  Health Check: $baseUriString/health")) *>
                printOBPConfiguration(baseUriString, authService) *>
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

  /** Generate developer configuration (database + OIDC clients)
    */
  private def generateDeveloperConfig(): IO[ExitCode] = {
    for {
      config <- Config.load
      _ <- IO(println("🚀 OBP-OIDC Developer Configuration Generator"))
      _ <- IO(println())
      _ <- ClientBootstrap.generateDatabaseConfig(config)
      _ <- IO(
        println(
          "📋 Next, run the database setup commands above, then start OBP-OIDC to generate OIDC client configurations."
        )
      )
      _ <- IO(
        println(
          "💡 Or run: ./mvn exec:java to start the server and auto-generate everything."
        )
      )
    } yield ExitCode.Success
  }

  /** Generate only database configuration
    */
  private def generateDatabaseConfig(): IO[ExitCode] = {
    for {
      config <- Config.load
      _ <- ClientBootstrap.generateDatabaseConfig(config)
    } yield ExitCode.Success
  }

  /** Print help information
    */
  private def printHelp(): IO[ExitCode] = {
    IO {
      println()
      println("🚀 OBP-OIDC Developer Helper")
      println("=" * 50)
      println()
      println("Usage:")
      println("  java -jar target/obp-oidc-1.0.0-SNAPSHOT.jar [COMMAND]")
      println()
      println("Commands:")
      println(
        "  --generate-config    Generate database + OIDC client configuration"
      )
      println("  --db-config         Generate only database configuration")
      println("  --help, -h          Show this help")
      println()
      println("Default (no command): Start OIDC server")
      println()
      println("Examples:")
      println("  # Generate all developer configuration")
      println("  java -jar obp-oidc.jar --generate-config")
      println()
      println("  # Start server (auto-generates client configs)")
      println("  java -jar obp-oidc.jar")
      println()
    } *> IO.pure(ExitCode.Success)
  }

  /** Print configuration for all clients from database
    */
  private def printOBPConfiguration(
      baseUri: String,
      authService: DatabaseAuthService
  ): IO[Unit] = {
    for {
      _ <- IO(println("=" * 100))
      _ <- IO(println("🚀 OBP clients from the database"))
      _ <- IO(println("=" * 100))
      _ <- IO(println())

      clientsResult <- authService.listClients()
      _ <- clientsResult match {
        case Right(clients) if clients.nonEmpty =>
          clients.foldLeft(IO.unit) { (acc, client) =>
            acc.flatMap(_ => printClient(Some(client)))
          }
        case Right(_) =>
          IO(println("No Clients Found"))
        case Left(error) =>
          IO(println(s"Error retrieving clients: ${error.error}"))
      }

      _ <- IO(println("=" * 100))
    } yield ()
  }

  /** Print client configuration in standardized format
    */
  private def printClient(client: Option[OidcClient]): IO[Unit] = {
    client match {
      case Some(c) =>
        for {
          _ <- IO(println(s"consumer_id: ${c.consumer_id}"))
          _ <- IO(println(s"client_id: ${c.client_id}"))
          _ <- IO(
            println(s"client_secret: ${c.client_secret.getOrElse("NOT_SET")}")
          )
          _ <- IO(println(s"redirect_uris: ${c.redirect_uris.mkString(",")}"))
          _ <- IO(println("-" * 50))
        } yield ()
      case None =>
        IO(println("Client not found"))
    }
  }

}
