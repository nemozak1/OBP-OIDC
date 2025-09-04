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
import com.tesobe.oidc.models.OidcClient
import org.http4s._
import org.http4s.dsl.io._

class ClientsEndpoint(authService: DatabaseAuthService) {

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case GET -> Root / "clients" =>
      handleClientsListRequest()
  }

  private def handleClientsListRequest(): IO[Response[IO]] = {
    for {
      _ <- IO(println("DEBUG: Clients list page requested"))
      clientsResult <- authService.listClients()
      response <- clientsResult match {
        case Right(clients) =>
          renderClientsPage(clients)
        case Left(error) =>
          renderErrorPage(
            error.error_description.getOrElse("Failed to retrieve clients")
          )
      }
    } yield response
  }

  private def renderClientsPage(clients: List[OidcClient]): IO[Response[IO]] = {
    val maskedClients = clients.map(maskClientSecret)
    val html = generateClientsHtml(maskedClients)
    Ok(html).map(
      _.withContentType(org.http4s.headers.`Content-Type`(MediaType.text.html))
    )
  }

  private def renderErrorPage(error: String): IO[Response[IO]] = {
    val html = s"""<!DOCTYPE html>
                  |<html>
                  |<head>
                  |    <title>Clients - Error</title>
                  |    <style>
                  |        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
                  |        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                  |        .error { color: #d32f2f; background-color: #ffebee; padding: 15px; border-radius: 4px; margin: 20px 0; }
                  |        .nav { margin-bottom: 30px; }
                  |        .nav a { text-decoration: none; color: #1976d2; margin-right: 20px; }
                  |        .nav a:hover { text-decoration: underline; }
                  |    </style>
                  |</head>
                  |<body>
                  |    <div class="container">
                  |        <nav class="nav">
                  |            <a href="/">Back to Home</a>
                  |        </nav>
                  |        <h1>OIDC Clients - Error</h1>
                  |        <div class="error">
                  |            <strong>Error:</strong> $error
                  |        </div>
                  |    </div>
                  |</body>
                  |</html>""".stripMargin
    Ok(html).map(
      _.withContentType(org.http4s.headers.`Content-Type`(MediaType.text.html))
    )
  }

  private def maskClientSecret(client: OidcClient): OidcClient = {
    client.copy(
      client_secret = client.client_secret.map(secret =>
        if (secret.length > 8) {
          secret.take(4) + "****" + secret.takeRight(4)
        } else {
          "****"
        }
      )
    )
  }

  private def generateClientsHtml(clients: List[OidcClient]): String = {
    val clientRows = clients.map(generateClientRow).mkString("")

    s"""<!DOCTYPE html>
       |<html>
       |<head>
       |    <title>OIDC Clients</title>
       |    <style>
       |        body {
       |            font-family: Arial, sans-serif;
       |            margin: 40px;
       |            background-color: #f5f5f5;
       |        }
       |        .container {
       |            max-width: 1400px;
       |            margin: 0 auto;
       |            background: white;
       |            padding: 20px;
       |            border-radius: 8px;
       |            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
       |        }
       |        .header {
       |            display: flex;
       |            justify-content: space-between;
       |            align-items: center;
       |            margin-bottom: 30px;
       |        }
       |        .nav a {
       |            text-decoration: none;
       |            color: #1976d2;
       |            margin-right: 20px;
       |        }
       |        .nav a:hover {
       |            text-decoration: underline;
       |        }
       |        .stats {
       |            background: #e3f2fd;
       |            padding: 15px;
       |            border-radius: 4px;
       |            margin-bottom: 20px;
       |        }
       |        table {
       |            width: 100%;
       |            border-collapse: collapse;
       |            margin-top: 20px;
       |        }
       |        th, td {
       |            padding: 12px;
       |            text-align: left;
       |            border-bottom: 1px solid #ddd;
       |        }
       |        th {
       |            background-color: #f8f9fa;
       |            font-weight: bold;
       |            color: #495057;
       |        }
       |        tr:hover {
       |            background-color: #f8f9fa;
       |        }
       |        .client-name {
       |            font-weight: bold;
       |            color: #1976d2;
       |        }
       |        .client-id {
       |            font-family: monospace;
       |            background: #f5f5f5;
       |            padding: 2px 6px;
       |            border-radius: 3px;
       |            font-size: 0.9em;
       |        }
       |        .client-secret {
       |            font-family: monospace;
       |            background: #fff3e0;
       |            padding: 2px 6px;
       |            border-radius: 3px;
       |            color: #e65100;
       |            font-size: 0.9em;
       |        }
       |        .redirect-uris {
       |            max-width: 300px;
       |            word-break: break-all;
       |        }
       |        .redirect-uris ul {
       |            margin: 0;
       |            padding-left: 20px;
       |        }
       |        .scopes {
       |            max-width: 200px;
       |        }
       |        .scopes .scope {
       |            display: inline-block;
       |            background: #e8f5e8;
       |            color: #2e7d32;
       |            padding: 2px 6px;
       |            border-radius: 3px;
       |            font-size: 0.8em;
       |            margin: 1px;
       |        }
       |        .created-at {
       |            font-size: 0.9em;
       |            color: #666;
       |        }
       |        .empty-state {
       |            text-align: center;
       |            padding: 60px;
       |            color: #666;
       |        }
       |        .masked-note {
       |            background: #fff3e0;
       |            padding: 10px;
       |            border-radius: 4px;
       |            margin-bottom: 20px;
       |            border-left: 4px solid #ff9800;
       |        }
       |    </style>
       |</head>
       |<body>
       |    <div class="container">
       |        <div class="header">
       |            <div class="nav">
       |                <a href="/">Back to Home</a>
       |            </div>
       |            <h1>OIDC Clients</h1>
       |        </div>
       |
       |        <div class="stats">
       |            <strong>Total Clients:</strong> ${clients.length}
       |        </div>
       |
       |        <div class="masked-note">
       <strong>Security Note:</strong> Client secrets are masked for security. Only the first and last 4 characters are shown.
       |        </div>
       |
       |        ${if (clients.isEmpty) {
        """<div class="empty-state">
               |    <h3>No clients found</h3>
               |    <p>There are no OIDC clients registered in the system.</p>
               |</div>""".stripMargin
      } else {
        s"""<table>
                |    <thead>
                |        <tr>
                |            <th>Client Name</th>
                |            <th>Client ID</th>
                |            <th>Consumer ID</th>
                |            <th>Client Secret</th>
                |            <th>Redirect URIs</th>
                |            <th>Scopes</th>
                |            <th>Auth Method</th>
                |            <th>Created At</th>
                |        </tr>
                |    </thead>
                |    <tbody>
                |        $clientRows
                |    </tbody>
                |</table>""".stripMargin
      }}
       |    </div>
       |</body>
       |</html>""".stripMargin
  }

  private def generateClientRow(client: OidcClient): String = {
    val redirectUrisList = if (client.redirect_uris.isEmpty) {
      "<em>None</em>"
    } else {
      "<ul>" + client.redirect_uris
        .map(uri => s"<li>$uri</li>")
        .mkString("") + "</ul>"
    }

    val scopesList = client.scopes
      .map(scope => s"""<span class="scope">$scope</span>""")
      .mkString(" ")

    val clientSecretDisplay = client.client_secret match {
      case Some(secret) => s"""<span class="client-secret">$secret</span>"""
      case None         => "<em>Not set</em>"
    }

    s"""<tr>
       |    <td><span class="client-name">${client.client_name}</span></td>
       |    <td><span class="client-id">${client.client_id}</span></td>
       |    <td><span class="client-id">${client.consumer_id}</span></td>
       |    <td>$clientSecretDisplay</td>
       |    <td class="redirect-uris">$redirectUrisList</td>
       |    <td class="scopes">$scopesList</td>
       |    <td>${client.token_endpoint_auth_method}</td>
       |    <td class="created-at">${client.created_at.getOrElse(
        "Unknown"
      )}</td>
       |</tr>""".stripMargin
  }
}

object ClientsEndpoint {
  def apply(authService: DatabaseAuthService): ClientsEndpoint =
    new ClientsEndpoint(authService)
}
