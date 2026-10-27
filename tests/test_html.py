"""Tests for the HTML inspector."""

from __future__ import annotations

from web_guard.html import (
    has_blank_link_protection,
    iter_http_resources,
    parse_html,
)

PAGE = """
<!doctype html>
<html>
<head>
  <title> My Page </title>
  <base href="https://cdn.example/app/">
  <meta name="generator" content="WordPress 6.4">
</head>
<body>
  <form id="login" action="/login" method="POST">
    <input type="hidden" name="csrf_token" value="secret">
    <input type="password" name="password">
    <input name="username">
  </form>
  <form action="" method="get">
    <textarea name="comment"></textarea>
  </form>
  <form>
    <input type="password" name="p2">
  </form>
  <a href="/x" target="_blank" rel="noopener noreferrer">x</a>
  <a href="/y" target="_blank">y</a>
  <script src="http://cdn.example/a.js"></script>
  <link rel="stylesheet" href="/style.css">
  <img src="//img.example/p.png">
  <iframe src="https://frame.example"></iframe>
  <!-- a comment -->
</body>
</html>
"""


def test_page_metadata_is_extracted():
    page = parse_html(PAGE)
    assert page.title == "My Page"
    assert page.base_href == "https://cdn.example/app/"
    assert page.meta_generator == "WordPress 6.4"
    assert page.comments == [" a comment "]


def test_forms_and_inputs_are_extracted():
    page = parse_html(PAGE)
    assert len(page.forms) == 3
    login = page.forms[0]
    assert login.identifier == "login"
    assert login.method == "post"
    assert login.has_password is True
    assert login.has_csrf_token is True
    assert login.display_name == "login"
    assert len(page.password_forms) == 2
    second = page.forms[1]
    assert second.method == "get"
    assert second.has_password is False
    third = page.forms[2]
    assert third.method == "get"
    assert third.has_password is True
    assert third.has_csrf_token is False
    assert third.display_name == "(inline form)"


def test_resources_and_blank_links_are_extracted():
    page = parse_html(PAGE)
    kinds = {resource.kind for resource in page.resources}
    assert kinds == {"script", "stylesheet", "image", "iframe"}
    assert len(page.blank_links) == 2
    assert has_blank_link_protection(page.blank_links[0]) is True
    assert has_blank_link_protection(page.blank_links[1]) is False
    http_resources = list(iter_http_resources(page.resources))
    assert len(http_resources) == 1
    assert http_resources[0].url == "http://cdn.example/a.js"


def test_malformed_html_is_tolerated_and_open_form_is_closed():
    page = parse_html("<html><title>x</title><form action='/a'><input type='password' name='p'")
    assert page.title == "x"
    assert len(page.forms) == 1
    assert page.forms[0].has_password is True


def test_attribute_names_are_case_insensitive():
    page = parse_html("<FORM METHOD='POST'><INPUT TYPE='PASSWORD' NAME='p'></FORM>")
    assert page.forms[0].method == "post"
    assert page.forms[0].has_password is True


def test_blank_link_protection_accepts_comma_separated_tokens():
    from web_guard.html import BlankLink

    assert has_blank_link_protection(BlankLink(href="/a", rel="nofollow, NOOPENER")) is True
    assert has_blank_link_protection(BlankLink(href="/a", rel="noreferrer")) is True
    assert has_blank_link_protection(BlankLink(href="/a", rel="nofollow")) is False
