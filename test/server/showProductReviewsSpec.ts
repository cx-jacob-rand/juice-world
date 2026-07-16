/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { showProductReviews } from '../../routes/showProductReviews'
import * as db from '../../data/mongodb'

const expect = chai.expect
chai.use(sinonChai)

describe('showProductReviews', () => {
  let req: any
  let res: any
  let next: any
  let findStub: sinon.SinonStub

  beforeEach(() => {
    req = { params: {}, headers: {} }
    res = {
      json: sinon.spy(),
      status: sinon.stub().returnsThis()
    }
    next = sinon.spy()
    // Stub the reviewsCollection.find to avoid real DB calls
    findStub = sinon.stub(db.reviewsCollection, 'find')
  })

  afterEach(() => {
    sinon.restore()
  })

  describe('NoSQL injection prevention via $where operator', () => {
    it('should use a plain field equality query instead of $where string interpolation', () => {
      const resolvedReviews: any[] = []
      findStub.returns(Promise.resolve(resolvedReviews))
      req.params.id = '1'

      showProductReviews()(req, res, next)

      // The query must NOT use $where — verify the stub was called with
      // a structured query object (not a JavaScript expression string)
      expect(findStub).to.have.been.calledOnce
      const queryArg = findStub.firstCall.args[0]
      expect(queryArg).to.not.have.property('$where')
      expect(queryArg).to.have.property('product')
    })

    it('should cast the id parameter to a Number before querying', () => {
      const resolvedReviews: any[] = []
      findStub.returns(Promise.resolve(resolvedReviews))
      req.params.id = '42'

      showProductReviews()(req, res, next)

      const queryArg = findStub.firstCall.args[0]
      expect(queryArg.product).to.equal(42)
      expect(typeof queryArg.product).to.equal('number')
    })

    it('should not pass raw user-supplied string directly to MongoDB query', () => {
      // Injection payload: a $where JavaScript expression
      // Without the fix, this would have been: { $where: 'this.product == 1; sleep(2000)' }
      // With the fix, Number('1; sleep(2000)') => NaN, which will not match anything
      const resolvedReviews: any[] = []
      findStub.returns(Promise.resolve(resolvedReviews))
      req.params.id = '1; sleep(2000)'

      showProductReviews()(req, res, next)

      const queryArg = findStub.firstCall.args[0]
      // The query must NOT contain $where
      expect(queryArg).to.not.have.property('$where')
      // Non-numeric id results in NaN, preventing any match
      expect(queryArg.product).to.be.NaN
    })

    it('should not allow NoSQL injection via JavaScript object operators in id', () => {
      // Attempt to inject a MongoDB operator via the id parameter
      const resolvedReviews: any[] = []
      findStub.returns(Promise.resolve(resolvedReviews))
      req.params.id = '{ "$gt": "" }'

      showProductReviews()(req, res, next)

      const queryArg = findStub.firstCall.args[0]
      expect(queryArg).to.not.have.property('$where')
      // Stringified object becomes NaN when cast to Number
      expect(queryArg.product).to.be.NaN
    })

    it('should not allow injection payload that attempts to access all documents', () => {
      // Classic $where injection: '0; return true' would match all documents
      const resolvedReviews: any[] = []
      findStub.returns(Promise.resolve(resolvedReviews))
      req.params.id = "0; return true"

      showProductReviews()(req, res, next)

      const queryArg = findStub.firstCall.args[0]
      expect(queryArg).to.not.have.property('$where')
    })
  })

  describe('normal operation', () => {
    it('should return reviews for a valid numeric product id', async () => {
      const mockReviews = [
        { product: 1, message: 'Great product!', author: 'user@test.com', likesCount: 0, likedBy: [] },
        { product: 1, message: 'Love it!', author: 'other@test.com', likesCount: 2, likedBy: [] }
      ]
      findStub.returns(Promise.resolve(mockReviews))
      req.params.id = '1'

      showProductReviews()(req, res, next)

      // Wait for the promise to resolve
      await new Promise(resolve => setTimeout(resolve, 10))

      expect(findStub).to.have.been.calledOnceWith({ product: 1 })
      expect(res.json).to.have.been.calledOnce
    })

    it('should return 400 on database error', async () => {
      findStub.returns(Promise.reject(new Error('DB error')))
      req.params.id = '1'

      showProductReviews()(req, res, next)

      await new Promise(resolve => setTimeout(resolve, 10))

      expect(res.status).to.have.been.calledWith(400)
      expect(res.json).to.have.been.calledWith({ error: 'Wrong Params' })
    })

    it('should query with numeric product id converted from string param', async () => {
      const mockReviews: any[] = []
      findStub.returns(Promise.resolve(mockReviews))
      req.params.id = '99'

      showProductReviews()(req, res, next)

      await new Promise(resolve => setTimeout(resolve, 10))

      expect(findStub).to.have.been.calledOnceWith({ product: 99 })
    })
  })
})
