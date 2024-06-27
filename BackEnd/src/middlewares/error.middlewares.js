import { ErrorWithStatus } from '../models/Errors.js'
import HTTP_STATUS from '../constants/httpStatus.js'
import omit from 'lodash'

export const defaultErrorHandler = (err, req, res, next) => {
  //lỗi từ các nơi sẽ dồn về đây
  if (err instanceof ErrorWithStatus) {
    return res.status(err.status).json(omit(err, ['status']))
  }
  // nếu mà lỗi xuống đc đây nghĩa là lỗi đó kh thuộc về ErrorWithStatus
  //set name, stack, message về enumerable true
  Object.getOwnPropertyNames(err).forEach((key) => {
    Object.defineProperty(err, key, { enumerable: true })
  })
  res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
    message: err.message,
    errorInfor: omit(err, ['stack'])
  })
}
