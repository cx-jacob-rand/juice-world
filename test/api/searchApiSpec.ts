/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as frisby from 'frisby'
import { expect } from '@jest/globals'
import type { Product as ProductConfig } from '../../lib/config.types'
import config from 'config'

const christmasProduct = config.get<ProductConfig[]>('products').filter(({ useForChristmasSpecialChallenge }) => useForChristmasSpecialChallenge)[0]
const pastebinLeakProduct = config.get<ProductConfig[]>('products').filter(({ keywordsForPastebinDataLeakChallenge }) => keywordsForPastebinDataLeakChallenge)[0]

const API_URL = 'http://localhost:3000/api'
const REST_URL = 'http://localhost:3000/rest'

describe('/rest/products/search', () => {
  it('GET product search with no matches returns no products', () => {
    return frisby.get(`${REST_URL}/products/search?q=nomatcheswhatsoever`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        expect(json.data.length).toBe(0)
      })
  })

  it('GET product search with one match returns found product', () => {
    return frisby.get(`${REST_URL}/products/search?q=o-saft`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        expect(json.data.length).toBe(1)
      })
  })

  it('GET product search with empty search parameter returns all products', () => {
    return frisby.get(`${API_URL}/Products`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        const products = json.data
        return frisby.get(`${REST_URL}/products/search?q=`)
          .expect('status', 200)
          .expect('header', 'content-type', /application\/json/)
          .then(({ json }) => {
            expect(json.data.length).toBe(products.length)
          })
      })
  })

  it('GET product search without search parameter returns all products', () => {
    return frisby.get(`${API_URL}/Products`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        const products = json.data
        return frisby.get(`${REST_URL}/products/search`)
          .expect('status', 200)
          .expect('header', 'content-type', /application\/json/)
          .then(({ json }) => {
            expect(json.data.length).toBe(products.length)
          })
      })
  })

  it('GET product search cannot select logically deleted christmas special by default', () => {
    return frisby.get(`${REST_URL}/products/search?q=seasonal%20special%20offer`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        expect(json.data.length).toBe(0)
      })
  })

  it('GET product search with single quote SQL injection payload returns 200 with no SQL error (parameterized query)', () => {
    // With parameterized queries, a single quote is treated as a literal character,
    // not as SQL syntax — the request must succeed without a 500 error
    return frisby.get(`${REST_URL}/products/search?q='`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        // No product names contain a lone single-quote so result set should be empty
        expect(json.data.length).toBe(0)
      })
  })

  it('GET product search with SQL comment injection payload returns 200 (no SQL injection)', () => {
    // Parameterized queries prevent SQL comment sequences from altering the query
    return frisby.get(`${REST_URL}/products/search?q='))--`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        // The payload is treated as a literal string; no products match it
        expect(json.data.length).toBe(0)
      })
  })

  it('GET product search UNION SELECT payload cannot extract user data (SQL injection blocked)', () => {
    // With parameterized queries, UNION SELECT payloads are treated as literal search
    // strings and cannot exfiltrate data from other tables
    return frisby.get(`${REST_URL}/products/search?q=')) union select id,email,password,4,5,6,7,8,9 from users--`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        // Payload is a literal LIKE search term — no users data in the response
        expect(json.data.length).toBe(0)
        // Verify no user email addresses were returned in the payload
        if (json.data.length > 0) {
          json.data.forEach((item: any) => {
            expect(item.name).not.toMatch(/@/)
          })
        }
      })
  })

  it('GET product search UNION SELECT with sqlite_master cannot extract schema (SQL injection blocked)', () => {
    // Parameterized queries prevent schema extraction via UNION SELECT on sqlite_master
    return frisby.get(`${REST_URL}/products/search?q=')) union select sql,2,3,4,5,6,7,8,9 from sqlite_master--`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        // No table definitions should appear in results
        json.data.forEach((item: any) => {
          expect(typeof item.id).not.toBe('string')
          if (item.id) {
            expect(String(item.id)).not.toContain('CREATE TABLE')
          }
        })
      })
  })

  it('GET product search WITH SQL terminator cannot bypass deletedAt filter (SQL injection blocked)', () => {
    // The christmas special product is logically deleted (deletedAt IS NOT NULL).
    // SQL injection used to bypass the WHERE clause filter; parameterized queries prevent this.
    return frisby.get(`${REST_URL}/products/search?q=${encodeURIComponent(christmasProduct.name + "'))--")}`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        // The logically deleted product should NOT appear — the filter is intact
        const names: string[] = json.data.map((p: any) => p.name)
        expect(names).not.toContain(christmasProduct.name)
      })
  })

  it('GET product search with SQL boolean payload does not return all rows (SQL injection blocked)', () => {
    // `' OR '1'='1` is a classic always-true injection; parameterized queries treat it literally
    return frisby.get(`${REST_URL}/products/search?q=' OR '1'='1`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        // Should not match all products — the criteria is just a literal LIKE string
        return frisby.get(`${API_URL}/Products`)
          .expect('status', 200)
          .then(({ json: allJson }) => {
            // The payload doesn't contain a product name, so 0 results expected
            // (certainly not ALL products, which would indicate SQL injection)
            expect(json.data.length).toBe(0)
            expect(json.data.length).not.toBe(allJson.data.length)
          })
      })
  })

  it('GET product search with very long input is safely truncated and returns valid response', () => {
    // The route truncates input to 200 chars; verify the parameterized query handles this safely
    const longInput = 'a'.repeat(300)
    return frisby.get(`${REST_URL}/products/search?q=${longInput}`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        expect(json.data.length).toBe(0)
      })
  })

  it('GET product search with pastebinLeakProduct name returns that product', () => {
    return frisby.get(`${REST_URL}/products/search?q=${encodeURIComponent(pastebinLeakProduct.name)}`)
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .then(({ json }) => {
        // Legitimate search still works after parameterization fix
        expect(json.data.length).toBeGreaterThanOrEqual(1)
      })
  })
})
