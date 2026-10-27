"""A tolerant HTML inspector for forms, resources and security relevant markup.

Web Guard does not render a page. It parses the delivered markup with the
standard library HTML parser and extracts only the facts needed by the checks.
The parser is deliberately forgiving because real pages often contain invalid
nesting. Every collection is capped so that a hostile or unusually large page
cannot exhaust memory.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from html.parser import HTMLParser

logger = logging.getLogger(__name__)

MAX_FORMS = 100
MAX_INPUTS_PER_FORM = 200
MAX_RESOURCES = 2_000
MAX_BLANK_LINKS = 500
MAX_COMMENTS = 200
MAX_TITLE_LENGTH = 500


@dataclass(frozen=True)
class FormInput:
    """Security relevant attributes of an input element."""

    name: str
    input_type: str
    autocomplete: str


@dataclass(frozen=True)
class Form:
    """A form together with the inputs that influence credential handling."""

    action: str
    method: str
    inputs: tuple[FormInput, ...]
    identifier: str = ""

    @property
    def password_inputs(self) -> tuple[FormInput, ...]:
        """Return inputs whose type is password."""

        return tuple(item for item in self.inputs if item.input_type == "password")

    @property
    def has_password(self) -> bool:
        """Return true when the form accepts a password."""

        return bool(self.password_inputs)

    @property
    def has_csrf_token(self) -> bool:
        """Use a conservative name based heuristic to detect anti-CSRF fields."""

        markers = ("csrf", "xsrf", "authenticity", "requestverification", "_token", "antiforgery")
        for item in self.inputs:
            name = item.name.lower()
            if item.input_type == "hidden" and any(marker in name for marker in markers):
                return True
        return False

    @property
    def display_name(self) -> str:
        """Return a stable label for reports without exposing field values."""

        return self.identifier or self.action or "(inline form)"


@dataclass(frozen=True)
class Resource:
    """An embedded resource reference that may cause mixed content."""

    tag: str
    attribute: str
    url: str
    kind: str


@dataclass(frozen=True)
class BlankLink:
    """An anchor that opens a new tab, checked for reverse tabnabbing."""

    href: str
    rel: str


@dataclass
class PageInfo:
    """Everything the checks need to know about the main HTML document."""

    title: str = ""
    base_href: str = ""
    meta_generator: str = ""
    forms: list[Form] = field(default_factory=list)
    resources: list[Resource] = field(default_factory=list)
    blank_links: list[BlankLink] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)

    @property
    def password_forms(self) -> list[Form]:
        """Return forms that contain at least one password input."""

        return [form for form in self.forms if form.has_password]


class _PageParser(HTMLParser):
    """Collect a small, security focused subset of the HTML document."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.page = PageInfo()
        self._in_title = False
        self._title_parts: list[str] = []
        self._current_form: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name.lower(): (value or "") for name, value in attrs}
        lowered = tag.lower()

        if lowered == "title":
            self._in_title = True
            return
        if lowered == "base" and not self.page.base_href and attributes.get("href"):
            self.page.base_href = attributes["href"]
            return
        if lowered == "meta":
            name = attributes.get("name", "").lower()
            if name == "generator" and not self.page.meta_generator:
                self.page.meta_generator = attributes.get("content", "").strip()
            return
        if lowered == "form":
            if self._current_form is None and len(self.page.forms) < MAX_FORMS:
                self._current_form = {
                    "action": attributes.get("action", ""),
                    "method": (attributes.get("method") or "get").lower(),
                    "identifier": attributes.get("id") or attributes.get("name") or "",
                    "inputs": [],
                }
            return
        if lowered in {"input", "textarea", "select"} and self._current_form is not None:
            inputs = self._current_form["inputs"]
            if isinstance(inputs, list) and len(inputs) < MAX_INPUTS_PER_FORM:
                input_type = (attributes.get("type") or "text").lower()
                if lowered != "input":
                    input_type = lowered
                inputs.append(
                    FormInput(
                        name=attributes.get("name", ""),
                        input_type=input_type,
                        autocomplete=attributes.get("autocomplete", ""),
                    )
                )
            return
        if lowered == "a":
            if attributes.get("target", "").lower() == "_blank" and len(self.page.blank_links) < MAX_BLANK_LINKS:
                self.page.blank_links.append(
                    BlankLink(href=attributes.get("href", ""), rel=attributes.get("rel", ""))
                )
            return

        resource = _resource_from_tag(lowered, attributes)
        if resource is not None and len(self.page.resources) < MAX_RESOURCES:
            self.page.resources.append(resource)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.lower()
        if lowered == "title":
            self._in_title = False
            self.page.title = "".join(self._title_parts).strip()[:MAX_TITLE_LENGTH]
            return
        if lowered == "form" and self._current_form is not None:
            inputs = self._current_form["inputs"]
            self.page.forms.append(
                Form(
                    action=str(self._current_form["action"]),
                    method=str(self._current_form["method"]),
                    identifier=str(self._current_form["identifier"]),
                    inputs=tuple(inputs) if isinstance(inputs, list) else (),
                )
            )
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self._in_title and sum(len(part) for part in self._title_parts) < MAX_TITLE_LENGTH:
            self._title_parts.append(data)

    def handle_comment(self, data: str) -> None:
        if len(self.page.comments) < MAX_COMMENTS:
            self.page.comments.append(data[:500])

    def finish(self) -> PageInfo:
        """Close any open form and return the collected information."""

        if self._current_form is not None:
            inputs = self._current_form["inputs"]
            self.page.forms.append(
                Form(
                    action=str(self._current_form["action"]),
                    method=str(self._current_form["method"]),
                    identifier=str(self._current_form["identifier"]),
                    inputs=tuple(inputs) if isinstance(inputs, list) else (),
                )
            )
            self._current_form = None
        if self._in_title and not self.page.title:
            self.page.title = "".join(self._title_parts).strip()[:MAX_TITLE_LENGTH]
        return self.page


def _resource_from_tag(tag: str, attributes: dict[str, str]) -> Resource | None:
    """Map an element and its attributes to an embedded resource description."""

    if tag == "script" and attributes.get("src"):
        return Resource(tag=tag, attribute="src", url=attributes["src"], kind="script")
    if tag == "link" and attributes.get("href"):
        rel = attributes.get("rel", "").lower()
        if "stylesheet" in rel:
            return Resource(tag=tag, attribute="href", url=attributes["href"], kind="stylesheet")
        if "icon" in rel:
            return Resource(tag=tag, attribute="href", url=attributes["href"], kind="icon")
        return None
    if tag == "iframe" and attributes.get("src"):
        return Resource(tag=tag, attribute="src", url=attributes["src"], kind="iframe")
    if tag == "img" and attributes.get("src"):
        return Resource(tag=tag, attribute="src", url=attributes["src"], kind="image")
    if tag == "source" and attributes.get("src"):
        return Resource(tag=tag, attribute="src", url=attributes["src"], kind="media")
    if tag == "video":
        reference = attributes.get("src") or attributes.get("poster")
        if reference:
            return Resource(tag=tag, attribute="src" if attributes.get("src") else "poster", url=reference, kind="media")
    if tag == "audio" and attributes.get("src"):
        return Resource(tag=tag, attribute="src", url=attributes["src"], kind="media")
    if tag == "object" and attributes.get("data"):
        return Resource(tag=tag, attribute="data", url=attributes["data"], kind="object")
    if tag == "embed" and attributes.get("src"):
        return Resource(tag=tag, attribute="src", url=attributes["src"], kind="object")
    return None


def parse_html(document: str) -> PageInfo:
    """Parse HTML and always return a page description, even for malformed input."""

    parser = _PageParser()
    # A document that ends inside a tag is common on error pages. Complete the
    # trailing tag so that the HTML parser still emits the element it describes.
    if document.rfind("<") > document.rfind(">"):
        document = f"{document}>"
    try:
        parser.feed(document)
        parser.close()
    except Exception as exc:  # noqa: BLE001 - third party parser failures must not abort an audit
        # A malformed document must not abort an audit. The collected prefix is
        # still useful and the report records that the page was inspected.
        logger.debug("HTML parser stopped early: %s", exc)
    return parser.finish()


def has_blank_link_protection(link: BlankLink) -> bool:
    """Return true when a target=_blank link prevents reverse tabnabbing."""

    values = {token.strip().lower() for token in link.rel.replace(",", " ").split()}
    return "noopener" in values or "noreferrer" in values


def iter_http_resources(resources: Iterable[Resource]) -> Iterable[Resource]:
    """Yield resources whose absolute URL uses plain HTTP."""

    for resource in resources:
        if resource.url.strip().lower().startswith("http://"):
            yield resource
