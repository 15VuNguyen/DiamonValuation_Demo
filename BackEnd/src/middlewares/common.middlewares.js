import pkg from 'lodash'
const { pick } = pkg

export const filterMiddleware = (filterKey) => (req, res, next) => {
  req.body = pick(req.body, filterKey)
  next()
}
