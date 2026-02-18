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

package com.tesobe.oidc.debug

import cats.effect.{IO, IOApp, ExitCode}
import com.tesobe.oidc.auth.HybridAuthService
import com.tesobe.oidc.config.Config
import com.tesobe.oidc.models.OidcClient

/** Debug Client Creation Test
  *
  * Simple standalone test to debug client creation issues Run with: mvn
  * exec:java -Dexec.mainClass="com.tesobe.oidc.debug.DebugClientCreation"
  */
object DebugClientCreation extends IOApp {

  def run(args: List[String]): IO[ExitCode] = {
    for {
      _ <- IO(println("Debug Client Creation Test"))
      _ <- IO(println("=" * 40))

      // Load configuration
      config <- Config.load
      _ <- IO(println(s"Configuration loaded"))
      _ <- IO(
        println(
          s"   Database: ${config.database.host}:${config.database.port}/${config.database.database}"
        )
      )
      _ <- IO(println(s"   User: ${config.database.username}"))
      _ <- IO(println(s"   Admin User: ${config.adminDatabase.username}"))
      _ <- IO(println())

      // Test database connections
      _ <- IO(println("Testing database connections..."))

      userDbResult <- HybridAuthService.testConnection(config)
      _ <- userDbResult match {
        case Right(msg)  => IO(println(s"User DB: $msg"))
        case Left(error) => IO(println(s"User DB: $error"))
      }

      adminDbResult <- HybridAuthService.testAdminConnection(config)
      _ <- adminDbResult match {
        case Right(msg)  => IO(println(s"Admin DB: $msg"))
        case Left(error) => IO(println(s"Admin DB: $error"))
      }
      _ <- IO(println())

      // Create HybridAuthService and test client operations
      exitCode <- HybridAuthService.create(config).use { authService =>
        for {
          _ <- IO(println("Testing client operations..."))

          // Test 1: List existing clients
          _ <- IO(println("Listing existing clients..."))
          listResult <- authService.listClients()
          _ <- listResult match {
            case Right(clients) =>
              IO(println(s"Found ${clients.length} existing clients:")) *>
                IO(
                  clients.foreach(client =>
                    println(s"   - ${client.client_name} (${client.client_id})")
                  )
                )
            case Left(error) =>
              IO(
                println(
                  s"Failed to list clients: ${error.error} - ${error.error_description.getOrElse("No description")}"
                )
              )
          }
          _ <- IO(println())

          // Test 2: Create a test client
          _ <- IO(println("Creating test client..."))
          testClient = OidcClient(
            client_id = "debug-test-client",
            client_secret = Some("debug-secret-123"),
            client_name = "Debug Test Client",
            consumer_id = "debug-test-client",
            redirect_uris = List("http://localhost:3000/debug/callback"),
            grant_types = List("authorization_code"),
            response_types = List("code"),
            scopes = List("openid", "profile", "email"),
            token_endpoint_auth_method = "client_secret_basic",
            created_at = None
          )

          createResult <- authService.createClient(testClient)
          _ <- createResult match {
            case Right(_) => IO(println("Test client created successfully"))
            case Left(error) =>
              IO(
                println(
                  s"Failed to create test client: ${error.error} - ${error.error_description
                      .getOrElse("No description")}"
                )
              )
          }
          _ <- IO(println())

          // Test 3: Find the created client
          _ <- IO(println("Finding created test client..."))
          findResult <- authService
            .findClientByClientIdThatIsKey("debug-test-client")
          _ <- findResult match {
            case Some(client) =>
              IO(println(s"Found client: ${client.client_name}"))
            case None => IO(println("Test client not found after creation"))
          }
          _ <- IO(println())

          // Test 4: Clean up - delete test client
          _ <- IO(println("Cleaning up test client..."))
          deleteResult <- authService.deleteClient("debug-test-client")
          _ <- deleteResult match {
            case Right(msg) => IO(println(s"$msg"))
            case Left(error) =>
              IO(
                println(
                  s"Failed to delete test client: ${error.error} - ${error.error_description
                      .getOrElse("No description")}"
                )
              )
          }

          _ <- IO(println())
          _ <- IO(println("Debug test completed!"))
          _ <- IO(println())
          _ <- IO(
            println(
              "If all tests passed, client creation should work during startup"
            )
          )
          _ <- IO(
            println(
              "If any tests failed, that's where the startup issue is occurring"
            )
          )

        } yield ExitCode.Success
      }

    } yield exitCode
  }
}
