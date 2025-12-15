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
import org.http4s._
import org.http4s.dsl.io._
import org.http4s.headers.`Content-Type`
import scala.io.Source

class StaticFilesEndpoint {

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case GET -> Root / "static" / "css" / fileName if fileName.endsWith(".css") =>
      serveStaticFile(s"static/css/$fileName", MediaType.text.css)
  }

  private def serveStaticFile(
      resourcePath: String,
      mediaType: MediaType
  ): IO[Response[IO]] = {
    IO {
      Option(getClass.getClassLoader.getResourceAsStream(resourcePath))
    }.flatMap {
      case Some(inputStream) =>
        IO {
          val content = Source.fromInputStream(inputStream, "UTF-8").mkString
          inputStream.close()
          content
        }.flatMap { content =>
          Ok(content).map(_.withContentType(`Content-Type`(mediaType)))
        }
      case None =>
        NotFound(s"Static file not found: $resourcePath")
    }.handleErrorWith { error =>
      InternalServerError(s"Error serving static file: ${error.getMessage}")
    }
  }
}

object StaticFilesEndpoint {
  def apply(): StaticFilesEndpoint = new StaticFilesEndpoint()
}
