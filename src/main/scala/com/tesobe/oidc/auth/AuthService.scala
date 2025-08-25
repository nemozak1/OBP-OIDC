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

import com.tesobe.oidc.models.{User, OidcError, OidcClient}

/**
 * Authentication service trait defining the contract for user authentication
 * and client validation in the OIDC provider.
 */
trait AuthService[F[_]] {
  /**
   * Authenticate a user by username and password
   * Returns the user information if authentication succeeds
   */
  def authenticate(username: String, password: String, provider: String): F[Either[OidcError, User]]

  /**
   * Get user information by subject ID
   */
  def getUserById(sub: String): F[Option[User]]

  /**
   * Get available authentication providers
   */
  def getAvailableProviders(): F[List[String]]

  /**
   * Validate that a client_id and redirect_uri combination is valid
   */
  def validateClient(clientId: String, redirectUri: String): F[Boolean]

  /**
   * Find a client by client ID
   */
  def findClientById(clientId: String): F[Option[OidcClient]]

  /**
   * Find an admin client by client ID (with write access)
   */
  def findAdminClientById(clientId: String): F[Option[OidcClient]]

  /**
   * List all registered clients
   */
  def listClients(): F[Either[OidcError, List[OidcClient]]]
}
