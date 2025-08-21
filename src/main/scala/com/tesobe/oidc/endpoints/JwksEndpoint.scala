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
import cats.syntax.all._
import com.tesobe.oidc.models.JsonWebKeySet
import com.tesobe.oidc.tokens.JwtService
import io.circe.syntax._
import org.http4s._
import org.http4s.circe._
import org.http4s.dsl.io._

class JwksEndpoint(jwtService: JwtService[IO]) {

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case GET -> Root / "jwks" =>
      getJwks
  }

  private def getJwks: IO[Response[IO]] = {
    for {
      jwk <- jwtService.getJsonWebKey
      jwks = JsonWebKeySet(List(jwk))
      response <- Ok(jwks.asJson)
    } yield response
  }
}

object JwksEndpoint {
  def apply(jwtService: JwtService[IO]): JwksEndpoint = new JwksEndpoint(jwtService)
}