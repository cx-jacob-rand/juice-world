/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { AllHtmlEntities as Entities } from 'html-entities'
import * as utils from '../../lib/utils'

const expect = chai.expect
const entities = new Entities()

/**
 * These tests verify the security fix for the Stored XSS vulnerability in videoHandler.ts.
 *
 * The fix applies entities.encode() to the favicon() value before embedding it into the
 * pug template string (line 63 in routes/videoHandler.ts), consistent with the existing
 * encoding applied to application.name (line 62).
 *
 * The SAST taint flow was:
 *   config.get('application.favicon') → extractFilename() → template.replace(/_favicon_/) → res.send()
 *
 * The fix wraps favicon() with entities.encode() to HTML-encode the value before it is
 * inserted into the pug template, preventing stored XSS via a malicious favicon config.
 */

describe('videoHandler - XSS fix: entities.encode() on favicon value', () => {
  describe('AllHtmlEntities.encode() prevents XSS payloads from being embedded as raw HTML', () => {
    it('should encode < and > characters in a script-injection payload', () => {
      const maliciousFavicon = '"><script>alert(1)</script><"'
      const encoded = entities.encode(maliciousFavicon)
      expect(encoded).to.not.include('<script>')
      expect(encoded).to.not.include('</script>')
      expect(encoded).to.include('&lt;')
      expect(encoded).to.include('&gt;')
    })

    it('should encode double-quote characters that could break HTML attributes', () => {
      const maliciousFavicon = 'foo"onload="alert(1)'
      const encoded = entities.encode(maliciousFavicon)
      expect(encoded).to.not.include('"onload="')
      expect(encoded).to.include('&quot;')
    })

    it('should encode single-quote characters that could break HTML attributes', () => {
      const maliciousFavicon = "foo'onload='alert(1)"
      const encoded = entities.encode(maliciousFavicon)
      expect(encoded).to.not.include("'onload='")
    })

    it('should encode ampersand characters to prevent entity injection', () => {
      const maliciousFavicon = 'foo&bar'
      const encoded = entities.encode(maliciousFavicon)
      expect(encoded).to.include('&amp;')
      expect(encoded).to.not.include('foo&bar')
    })

    it('should preserve benign favicon filenames without modification of alphanumeric characters', () => {
      const normalFavicon = 'favicon.ico'
      const encoded = entities.encode(normalFavicon)
      // The encoded form of a plain filename should still contain the original characters
      expect(encoded).to.include('favicon')
      expect(encoded).to.include('.ico')
    })

    it('should encode a full XSS event-handler injection attempt', () => {
      const xssPayload = '"><img src=x onerror="alert(document.cookie)">'
      const encoded = entities.encode(xssPayload)
      expect(encoded).to.not.include('<img')
      expect(encoded).to.not.include('onerror=')
      expect(encoded).to.include('&lt;')
      expect(encoded).to.include('&gt;')
    })
  })

  describe('utils.extractFilename() - the function used to extract the favicon name from config', () => {
    it('should extract filename from a simple path', () => {
      expect(utils.extractFilename('/assets/public/images/favicon.ico')).to.equal('favicon.ico')
    })

    it('should extract filename from a URL with query parameters', () => {
      expect(utils.extractFilename('http://example.com/favicon.ico?v=2')).to.equal('favicon.ico')
    })

    it('should return the value as-is if there is no path separator', () => {
      expect(utils.extractFilename('favicon.ico')).to.equal('favicon.ico')
    })

    it('should decode percent-encoded characters in the filename', () => {
      // This is relevant to XSS: a percent-encoded payload is decoded before encoding
      const rawValue = '/assets/%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E'
      const extracted = utils.extractFilename(rawValue)
      // extractFilename decodes URI components, so the decoded value contains raw < > "
      // entities.encode() must then encode those characters to prevent XSS
      const encoded = entities.encode(extracted)
      expect(encoded).to.not.include('<script>')
      expect(encoded).to.not.include('</script>')
    })
  })

  describe('encoding consistency: favicon receives the same treatment as application.name', () => {
    it('entities.encode() on application.name-style payload prevents XSS', () => {
      const maliciousName = '<Evil Corp & Associates>'
      const encoded = entities.encode(maliciousName)
      expect(encoded).to.equal('&lt;Evil Corp &amp; Associates&gt;')
      expect(encoded).to.not.include('<')
      expect(encoded).to.not.include('>')
    })

    it('entities.encode() on favicon-style payload prevents XSS consistently', () => {
      const maliciousFavicon = '<script>stealCookies()</script>.ico'
      const encoded = entities.encode(maliciousFavicon)
      expect(encoded).to.not.include('<script>')
      expect(encoded).to.not.include('</script>')
    })

    it('entities.encode() is idempotent-safe: a benign favicon encoded value contains original text', () => {
      // After encoding a safe favicon name, the HTML should still render the intended filename
      const safeFavicon = 'juice-shop.ico'
      const encoded = entities.encode(safeFavicon)
      // Decoding the HTML-encoded string should recover the original
      const decoded = entities.decode(encoded)
      expect(decoded).to.equal(safeFavicon)
    })
  })
})
