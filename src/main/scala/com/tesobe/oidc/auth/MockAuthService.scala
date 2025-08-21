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

import cats.effect.IO
import cats.syntax.either._
import com.tesobe.oidc.models.{User, OidcError}

trait AuthService[F[_]] {
  def authenticate(username: String, password: String): F[Either[OidcError, User]]
  def getUserById(sub: String): F[Option[User]]
  def validateClient(clientId: String, redirectUri: String): F[Boolean]
}

class MockAuthService extends AuthService[IO] {
  
  // Hardcoded test users - NO DATABASE
  private val users = Map(
    "alice" -> User(
      sub = "alice",
      username = "alice",
      password = "secret123",
      name = Some("Alice Smith"),
      email = Some("alice@example.com"),
      email_verified = Some(true)
    ),
    "bob" -> User(
      sub = "bob", 
      username = "bob",
      password = "password456",
      name = Some("Bob Jones"),
      email = Some("bob@example.com"),
      email_verified = Some(true)
    ),
    "charlie" -> User(
      sub = "charlie",
      username = "charlie", 
      password = "test789",
      name = Some("Charlie Brown"),
      email = Some("charlie@example.com"),
      email_verified = Some(true)
    )
  )

  def authenticate(username: String, password: String): IO[Either[OidcError, User]] = IO {
    users.get(username) match {
      case Some(user) if user.password == password => 
        user.asRight[OidcError]
      case Some(_) => 
        OidcError("access_denied", Some("Invalid password")).asLeft[User]
      case None => 
        OidcError("access_denied", Some("User not found")).asLeft[User]
    }
  }

  def getUserById(sub: String): IO[Option[User]] = IO {
    users.values.find(_.sub == sub)
  }

  def validateClient(clientId: String, redirectUri: String): IO[Boolean] = IO {
    // Mock implementation - accepts any client_id and redirect_uri for testing
    // In production, this would check against the v_oidc_clients database view
    true
  }
}

object MockAuthService {
  def apply(): MockAuthService = new MockAuthService()
}