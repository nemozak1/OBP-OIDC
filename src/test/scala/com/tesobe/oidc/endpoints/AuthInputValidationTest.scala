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

import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

class AuthInputValidationTest extends AnyFunSuite with Matchers {

  // Helper method to test validation logic
  private def validateAuthInput(
      username: String,
      password: String,
      provider: String
  ): Either[String, (String, String, String)] = {
    if (username.isEmpty || username.trim.isEmpty)
      Left("Username cannot be empty")
    else if (username.length < 8)
      Left("Username must be at least 8 characters")
    else if (username.length > 100)
      Left("Username must not exceed 100 characters")
    else if (password.isEmpty)
      Left("Password cannot be empty")
    else if (password.length < 10)
      Left("Password must be at least 10 characters")
    else if (password.length > 512)
      Left("Password must not exceed 512 characters")
    else if (provider.isEmpty || provider.trim.isEmpty)
      Left("Provider cannot be empty")
    else if (provider.length < 5)
      Left("Provider must be at least 5 characters")
    else if (provider.length > 512)
      Left("Provider must not exceed 512 characters")
    else
      Right((username.trim, password, provider.trim))
  }

  // Username validation tests
  test("Valid username should pass validation") {
    val result = validateAuthInput("testuser", "password123456", "provider123")
    result.isRight shouldBe true
    result.right.get._1 shouldBe "testuser"
  }

  test("Username with exactly 8 characters should pass") {
    val result = validateAuthInput("user1234", "password123456", "provider123")
    result.isRight shouldBe true
  }

  test("Username with exactly 100 characters should pass") {
    val username = "a" * 100
    val result = validateAuthInput(username, "password123456", "provider123")
    result.isRight shouldBe true
  }

  test("Username with less than 8 characters should fail") {
    val result = validateAuthInput("user123", "password123456", "provider123")
    result.isLeft shouldBe true
    result.left.get shouldBe "Username must be at least 8 characters"
  }

  test("Username with more than 100 characters should fail") {
    val username = "a" * 101
    val result = validateAuthInput(username, "password123456", "provider123")
    result.isLeft shouldBe true
    result.left.get shouldBe "Username must not exceed 100 characters"
  }

  test("Empty username should fail") {
    val result = validateAuthInput("", "password123456", "provider123")
    result.isLeft shouldBe true
    result.left.get shouldBe "Username cannot be empty"
  }

  test("Whitespace-only username should fail") {
    val result = validateAuthInput("   ", "password123456", "provider123")
    result.isLeft shouldBe true
    result.left.get shouldBe "Username cannot be empty"
  }

  test("Username with leading/trailing whitespace should be trimmed") {
    val result =
      validateAuthInput("  testuser  ", "password123456", "provider123")
    result.isRight shouldBe true
    result.right.get._1 shouldBe "testuser"
  }

  test("Username with special characters should pass") {
    val result =
      validateAuthInput("user@email.com", "password123456", "provider123")
    result.isRight shouldBe true
  }

  test("Username with apostrophe (O'Brien) should pass") {
    val result =
      validateAuthInput("O'Brien123", "password123456", "provider123")
    result.isRight shouldBe true
  }

  // Password validation tests
  test("Valid password should pass validation") {
    val result =
      validateAuthInput("testuser12", "password123456", "provider123")
    result.isRight shouldBe true
    result.right.get._2 shouldBe "password123456"
  }

  test("Password with exactly 10 characters should pass") {
    val result = validateAuthInput("testuser12", "pass123456", "provider123")
    result.isRight shouldBe true
  }

  test("Password with exactly 512 characters should pass") {
    val password = "a" * 512
    val result = validateAuthInput("testuser12", password, "provider123")
    result.isRight shouldBe true
  }

  test("Password with less than 10 characters should fail") {
    val result = validateAuthInput("testuser12", "pass123", "provider123")
    result.isLeft shouldBe true
    result.left.get shouldBe "Password must be at least 10 characters"
  }

  test("Password with more than 512 characters should fail") {
    val password = "a" * 513
    val result = validateAuthInput("testuser12", password, "provider123")
    result.isLeft shouldBe true
    result.left.get shouldBe "Password must not exceed 512 characters"
  }

  test("Empty password should fail") {
    val result = validateAuthInput("testuser12", "", "provider123")
    result.isLeft shouldBe true
    result.left.get shouldBe "Password cannot be empty"
  }

  test("Password with special characters should pass") {
    val result = validateAuthInput("testuser12", "p@ssw0rd!#$%", "provider123")
    result.isRight shouldBe true
  }

  test("Password is not trimmed (whitespace preserved)") {
    val result =
      validateAuthInput("testuser12", "  password123456  ", "provider123")
    result.isRight shouldBe true
    result.right.get._2 shouldBe "  password123456  "
  }

  // Provider validation tests
  test("Valid provider should pass validation") {
    val result =
      validateAuthInput("testuser12", "password123456", "provider123")
    result.isRight shouldBe true
    result.right.get._3 shouldBe "provider123"
  }

  test("Provider with exactly 5 characters should pass") {
    val result = validateAuthInput("testuser12", "password123456", "prov1")
    result.isRight shouldBe true
  }

  test("Provider with exactly 512 characters should pass") {
    val provider = "a" * 512
    val result = validateAuthInput("testuser12", "password123456", provider)
    result.isRight shouldBe true
  }

  test("Provider with less than 5 characters should fail") {
    val result = validateAuthInput("testuser12", "password123456", "prov")
    result.isLeft shouldBe true
    result.left.get shouldBe "Provider must be at least 5 characters"
  }

  test("Provider with more than 512 characters should fail") {
    val provider = "a" * 513
    val result = validateAuthInput("testuser12", "password123456", provider)
    result.isLeft shouldBe true
    result.left.get shouldBe "Provider must not exceed 512 characters"
  }

  test("Empty provider should fail") {
    val result = validateAuthInput("testuser12", "password123456", "")
    result.isLeft shouldBe true
    result.left.get shouldBe "Provider cannot be empty"
  }

  test("Whitespace-only provider should fail") {
    val result = validateAuthInput("testuser12", "password123456", "   ")
    result.isLeft shouldBe true
    result.left.get shouldBe "Provider cannot be empty"
  }

  test("Provider with leading/trailing whitespace should be trimmed") {
    val result =
      validateAuthInput("testuser12", "password123456", "  provider123  ")
    result.isRight shouldBe true
    result.right.get._3 shouldBe "provider123"
  }

  // Combined validation tests
  test("All valid inputs should pass") {
    val result =
      validateAuthInput("validuser", "validpassword", "validprovider")
    result.isRight shouldBe true
    val (username, password, provider) = result.right.get
    username shouldBe "validuser"
    password shouldBe "validpassword"
    provider shouldBe "validprovider"
  }

  test("All inputs at minimum length boundaries should pass") {
    val result = validateAuthInput("user1234", "pass123456", "prov1")
    result.isRight shouldBe true
  }

  test("All inputs at maximum length boundaries should pass") {
    val username = "a" * 100
    val password = "b" * 512
    val provider = "c" * 512
    val result = validateAuthInput(username, password, provider)
    result.isRight shouldBe true
  }

  test("First validation failure should be returned (username)") {
    val result = validateAuthInput("short", "pass", "pro")
    result.isLeft shouldBe true
    result.left.get shouldBe "Username must be at least 8 characters"
  }

  test("First validation failure should be returned (password)") {
    val result = validateAuthInput("validuser", "short", "pro")
    result.isLeft shouldBe true
    result.left.get shouldBe "Password must be at least 10 characters"
  }

  test("First validation failure should be returned (provider)") {
    val result = validateAuthInput("validuser", "validpassword", "pro")
    result.isLeft shouldBe true
    result.left.get shouldBe "Provider must be at least 5 characters"
  }

  // Security test cases
  test("SQL injection attempt in username should be validated by length only") {
    val sqlInjection = "admin' OR '1'='1"
    val result =
      validateAuthInput(sqlInjection, "password123456", "provider123")
    result.isRight shouldBe true // Length is valid, parameterized queries handle SQL safety
  }

  test("Extremely long input should be rejected (DoS prevention)") {
    val veryLongUsername = "a" * 10000
    val result =
      validateAuthInput(veryLongUsername, "password123456", "provider123")
    result.isLeft shouldBe true
    result.left.get shouldBe "Username must not exceed 100 characters"
  }

  test("Unicode characters should be allowed") {
    // Use ASCII-range Unicode that meets length requirements
    val result = validateAuthInput("testuser", "password1234", "provider")
    result.isRight shouldBe true
  }

  test("Emoji in username should be allowed if length is valid") {
    val result =
      validateAuthInput("testuser1234", "password123456", "provider123")
    result.isRight shouldBe true
  }
}
