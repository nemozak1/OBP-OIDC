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

class HtmlUtilsTest extends AnyFunSuite with Matchers {

  // Individual character escaping
  test("htmlEncode should escape ampersand to &amp;") {
    HtmlUtils.htmlEncode("&") shouldBe "&amp;"
  }

  test("htmlEncode should escape less-than to &lt;") {
    HtmlUtils.htmlEncode("<") shouldBe "&lt;"
  }

  test("htmlEncode should escape greater-than to &gt;") {
    HtmlUtils.htmlEncode(">") shouldBe "&gt;"
  }

  test("htmlEncode should escape double-quote to &quot;") {
    HtmlUtils.htmlEncode("\"") shouldBe "&quot;"
  }

  test("htmlEncode should escape single-quote to &#x27;") {
    HtmlUtils.htmlEncode("'") shouldBe "&#x27;"
  }

  // Edge cases
  test("htmlEncode should return empty string unchanged") {
    HtmlUtils.htmlEncode("") shouldBe ""
  }

  test("htmlEncode should return plain text unchanged") {
    HtmlUtils.htmlEncode("hello world") shouldBe "hello world"
  }

  // Mixed strings
  test("htmlEncode should escape all five special characters in one string") {
    HtmlUtils.htmlEncode("&<>\"'") shouldBe "&amp;&lt;&gt;&quot;&#x27;"
  }

  test("htmlEncode should escape special characters embedded in plain text") {
    HtmlUtils.htmlEncode("hello <world> & \"everyone\"") shouldBe
      "hello &lt;world&gt; &amp; &quot;everyone&quot;"
  }

  test("htmlEncode should escape an HTML tag to prevent injection") {
    HtmlUtils.htmlEncode("<script>alert('xss')</script>") shouldBe
      "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"
  }

  test("htmlEncode should escape HTML attribute injection attempt") {
    HtmlUtils.htmlEncode("\" onmouseover=\"alert(1)") shouldBe
      "&quot; onmouseover=&quot;alert(1)"
  }

  // Ampersand-first ordering: ensures existing text is not double-escaped
  test("htmlEncode should not double-escape an already-escaped entity") {
    HtmlUtils.htmlEncode("&amp;") shouldBe "&amp;amp;"
  }

  test("htmlEncode should escape multiple ampersands") {
    HtmlUtils.htmlEncode("a && b") shouldBe "a &amp;&amp; b"
  }
}
