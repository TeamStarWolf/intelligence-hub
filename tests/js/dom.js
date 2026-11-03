// A small DOM for the node tests: enough of Element, Document, selectors and events to load
// site/index.html and run the page code. It parses only well-formed markup like the Hub's own.
const VOID = new Set(["meta", "link", "img", "input", "br", "hr", "source"]);

class Node {
  constructor() { this.parentNode = null; this.childNodes = []; }
  get children() { return this.childNodes.filter(child => child instanceof Element); }
  get firstChild() { return this.childNodes[0] || null; }
  get lastChild() { return this.childNodes[this.childNodes.length - 1] || null; }
  get textContent() { return this.childNodes.map(child => child.textContent).join(""); }
  set textContent(value) { this.replaceChildren(); if (value !== "" && value !== null && value !== undefined) this.append(new Text(String(value))); }
  append(...nodes) { for (const item of nodes) { const child = typeof item === "string" ? new Text(item) : item; if (child.parentNode) child.parentNode.childNodes.splice(child.parentNode.childNodes.indexOf(child), 1); child.parentNode = this; this.childNodes.push(child); } }
  prepend(...nodes) { const rest = this.childNodes; this.childNodes = []; this.append(...nodes); for (const child of rest) this.childNodes.push(child); }
  replaceChildren(...nodes) { for (const child of this.childNodes) child.parentNode = null; this.childNodes = []; this.append(...nodes); }
}

class Text extends Node {
  constructor(text) { super(); this.data = text; }
  get textContent() { return this.data; }
  set textContent(value) { this.data = String(value); }
}

class ClassList {
  constructor(element) { this.element = element; }
  get values() { return (this.element.getAttribute("class") || "").split(/\s+/).filter(Boolean); }
  contains(name) { return this.values.includes(name); }
  add(...names) { this.element.setAttribute("class", [...new Set([...this.values, ...names])].join(" ")); }
  remove(...names) { this.element.setAttribute("class", this.values.filter(value => !names.includes(value)).join(" ")); }
  toggle(name, force) { const on = force === undefined ? !this.contains(name) : Boolean(force); if (on) this.add(name); else this.remove(name); return on; }
}

const REFLECTED = { id: "id", className: "class", href: "href", target: "target", rel: "rel", type: "type", placeholder: "placeholder", scope: "scope", referrerPolicy: "referrerpolicy" };

export class Element extends Node {
  constructor(tagName, ownerDocument) {
    super();
    this.tagName = tagName.toUpperCase(); this.localName = tagName.toLowerCase(); this.attributes = new Map(); this.listeners = {}; this.ownerDocument = ownerDocument;
    this.value = ""; this.checked = false; this.disabled = false; this.open = false; this.maxLength = -1; this.tabIndex = -1;
    this.classList = new ClassList(this);
    const element = this;
    this.dataset = new Proxy({}, {
      get: (_, key) => typeof key === "string" ? element.getAttribute("data-" + key.replace(/[A-Z]/g, letter => "-" + letter.toLowerCase())) ?? undefined : undefined,
      set: (_, key, value) => { element.setAttribute("data-" + String(key).replace(/[A-Z]/g, letter => "-" + letter.toLowerCase()), String(value)); return true; }
    });
    for (const [property, attribute] of Object.entries(REFLECTED)) Object.defineProperty(this, property, { get: () => this.getAttribute(attribute) ?? "", set: value => this.setAttribute(attribute, value), configurable: true });
  }
  get hidden() { return this.attributes.has("hidden"); }
  set hidden(value) { if (value) this.setAttribute("hidden", ""); else this.removeAttribute("hidden"); }
  setAttribute(name, value) { this.attributes.set(name.toLowerCase(), String(value)); if (name === "value") this.value = String(value); if (name === "open") this.open = true; }
  getAttribute(name) { return this.attributes.has(name.toLowerCase()) ? this.attributes.get(name.toLowerCase()) : null; }
  hasAttribute(name) { return this.attributes.has(name.toLowerCase()); }
  removeAttribute(name) { this.attributes.delete(name.toLowerCase()); }
  addEventListener(type, handler) { (this.listeners[type] ||= []).push(handler); }
  dispatchEvent(event) { event.target ||= this; for (const handler of this.listeners[event.type] || []) handler(event); return true; }
  focus() { this.ownerDocument.activeElement = this; }
  showModal() { this.open = true; this.setAttribute("open", ""); }
  close() { if (!this.open) return; this.open = false; this.removeAttribute("open"); this.dispatchEvent({ type: "close" }); }
  closest(selector) { let item = this; while (item instanceof Element) { if (matches(item, selector)) return item; item = item.parentNode; } return null; }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  querySelectorAll(selector) { return descendants(this).filter(item => matches(item, selector)); }
  get options() { return this.children.filter(child => child.localName === "option"); }
}

function descendants(root) {
  const found = [];
  const walk = node => { for (const child of node.childNodes) if (child instanceof Element) { found.push(child); walk(child); } };
  walk(root);
  return found;
}

// Compound selectors (tag, #id, .class, [attr], [attr=v], [attr^=v]) joined by descendant spaces.
function compound(element, part) {
  const pattern = /([a-z0-9-]+)|#([A-Za-z0-9_-]+)|\.([A-Za-z0-9_-]+)|\[([a-z0-9-]+)(?:(\^?=)['"]?([^'"\]]*)['"]?)?\]/gy;
  let match; let index = 0;
  while (index < part.length && (match = pattern.exec(part))) {
    index = pattern.lastIndex;
    if (match[1] && element.localName !== match[1]) return false;
    if (match[2] && element.getAttribute("id") !== match[2]) return false;
    if (match[3] && !element.classList.contains(match[3])) return false;
    if (match[4]) {
      const value = element.getAttribute(match[4]);
      if (value === null) return false;
      if (match[5] === "=" && value !== match[6]) return false;
      if (match[5] === "^=" && !value.startsWith(match[6])) return false;
    }
  }
  return index === part.length;
}

export function matches(element, selector) {
  return selector.split(",").some(group => {
    const parts = group.trim().split(/\s+/);
    if (!compound(element, parts[parts.length - 1])) return false;
    let item = element.parentNode;
    for (let position = parts.length - 2; position >= 0; position--) {
      while (item instanceof Element && !compound(item, parts[position])) item = item.parentNode;
      if (!(item instanceof Element)) return false;
      item = item.parentNode;
    }
    return true;
  });
}

const ENTITIES = { amp: "&", lt: "<", gt: ">", quot: "\"", apos: "'", nbsp: " " };
const decode = text => text.replace(/&(#\d+|[a-z]+);/g, (whole, name) => name[0] === "#" ? String.fromCodePoint(Number(name.slice(1))) : ENTITIES[name] ?? whole);

export class Document extends Node {
  constructor() { super(); this.listeners = {}; this.activeElement = null; this.hidden = false; this.title = ""; }
  createElement(tag) { return new Element(tag, this); }
  get documentElement() { return this.children[0]; }
  get body() { return this.documentElement.querySelector("body"); }
  querySelector(selector) { return this.documentElement.querySelector(selector) || (matches(this.documentElement, selector) ? this.documentElement : null); }
  querySelectorAll(selector) { return [this.documentElement, ...descendants(this.documentElement)].filter(item => matches(item, selector)); }
  addEventListener(type, handler) { (this.listeners[type] ||= []).push(handler); }
  dispatchEvent(event) { for (const handler of this.listeners[event.type] || []) handler(event); return true; }
}

// Parses markup into a Document. Script elements are kept empty; the tests import modules themselves.
export function parseHtml(html) {
  const doc = new Document();
  let current = doc;
  const tag = /<!--[\s\S]*?-->|<!doctype[^>]*>|<\/([a-z0-9]+)\s*>|<([a-z0-9]+)((?:\s+[a-z0-9-]+(?:="[^"]*"|='[^']*')?)*)\s*\/?>|([^<]+)/gi;
  let match;
  while ((match = tag.exec(html))) {
    if (match[1]) { let item = current; while (item !== doc && item.localName !== match[1].toLowerCase()) item = item.parentNode; if (item !== doc) current = item.parentNode; continue; }
    if (match[2]) {
      const element = doc.createElement(match[2]);
      for (const attribute of (match[3] || "").matchAll(/([a-z0-9-]+)(?:="([^"]*)"|='([^']*)')?/gi)) element.setAttribute(attribute[1], decode(attribute[2] ?? attribute[3] ?? ""));
      if (element.localName === "input" && element.hasAttribute("maxlength")) element.maxLength = Number(element.getAttribute("maxlength"));
      if (element.localName === "option") element.value = element.getAttribute("value") ?? "";
      current.append(element);
      if (!VOID.has(element.localName)) current = element;
      continue;
    }
    if (match[4] && current !== doc && current.localName !== "script" && match[4].trim()) current.append(new Text(decode(match[4])));
  }
  // An option's value defaults to its text, and a select's value to its first option.
  for (const option of doc.querySelectorAll("option")) if (!option.hasAttribute("value")) option.value = option.textContent;
  for (const select of doc.querySelectorAll("select")) if (select.options.length) select.value = select.options[0].value;
  return doc;
}

// Every element in document order.
export function inOrder(doc) { return [doc.documentElement, ...descendants(doc.documentElement)]; }
